#!/usr/bin/env python3
"""Integrity checks every run must pass before its data may be used.

  python3 validate.py ../data/raw/campaign_v1        # prints a report, exit 1 on failure
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

import monitor_replay
import sare

EXEC_TOL_CYC = 0           # exec and [start, end] come from the same CYCCNT samples


def check_run(tr: pd.DataFrame, st: pd.DataFrame, meta: dict) -> list[tuple[str, bool, str]]:
    res = []
    add = lambda name, ok, detail="": res.append((name, bool(ok), detail))
    cpu_hz = meta["cpu_hz"]
    cfg = meta.get("config") or {}

    add("end_frame", meta.get("end") is not None, "DUT sent END")
    drops = (meta.get("end") or {}).get("trace_drops", -1)
    add("no_trace_drops", drops == 0, f"trace_drops={drops}")
    add("host_link_clean", meta.get("host_bad_frames", -1) == 0, f"bad DUT->host frames={meta.get('host_bad_frames')}")
    add("calibration", meta.get("calibration") is not None, "probe-cost frame received")
    add("build_id", "build=" in (meta.get("fw_info") or ""), meta.get("fw_info", "missing"))

    for task, d in tr[tr["task"] != "idle"].groupby("task", observed=True):
        d = d.sort_values("seq")
        seq = d["seq"].to_numpy()
        add(f"{task}:seq_contiguous", np.array_equal(seq, np.arange(len(seq))), f"n={len(seq)}")
        T = sare.PERIOD_MS.get(task)
        if task == "attack":
            T = cfg.get("attack_period_ms")
        # Amendment A2 (2026-09-30, during the campaign): the attacker's own job
        # completion and timing are measured outcomes (it may be starved when it
        # runs below the workload), not data-integrity properties. They are
        # recorded as information; integrity checks stay strict for the six
        # workload tasks, and the attacker's sequence must still be contiguous.
        attacker = task == "attack"
        if T and cfg.get("duration_ms"):
            expect = -(-cfg["duration_ms"] // T)
            if attacker:
                add("attack:jobs_completed", True, f"info (A2): {len(seq)} of {expect} released jobs completed")
            else:
                add(f"{task}:job_count", len(seq) == expect, f"{len(seq)} vs expected {expect}")
        if T and len(d) > 1:
            gaps = np.diff(d["release"].to_numpy().astype(np.int64)) % 2**32
            add(f"{task}:release_spacing", np.all(gaps == T * cpu_hz // 1000), "exact nominal period in cycles")
        sl, r, e = (d[c].to_numpy().astype(np.int64) for c in ("start_lat", "response", "exec"))
        if attacker:
            add("attack:max_response", True, f"info (A2): max response {r.max() / cpu_hz:.3f} s")
            continue
        add(f"{task}:causality", np.all((sl <= r) & (r < 2**31)), "start <= finish, no wrap")
        add(f"{task}:exec_bounded", np.all(e <= r - sl + EXEC_TOL_CYC), "exec <= finish - start")

    stim = meta.get("stimulus")
    if stim is not None:
        ok = abs(stim.get("rate_hz", 0) - 200) < 1.0 and stim.get("interval_ms_p99", 99) < 10
        add("stimulus_rate", ok, f"{stim.get('rate_hz', 0):.2f} Hz, p99 interval {stim.get('interval_ms_p99', 0):.1f} ms, "
                                 f"max {stim.get('interval_ms_max', 0):.1f} ms")

    # Two independent load measurements must agree: sum of per-task exec
    # (switch hooks) vs 1 - idle share (kernel + ISR overhead makes up the gap).
    if cfg.get("duration_ms") and len(st):
        busy = tr.loc[tr["task"] != "idle", "exec"].sum() / cpu_hz / (cfg["duration_ms"] / 1000)
        gap = st["cpu_load"].mean() - busy
        add("load_crosscheck", -0.005 < gap < 0.03, f"idle-based {st['cpu_load'].mean():.3%} vs task-sum {busy:.3%}")

    # The on-target monitor must match its bit-exact host replay: this is what
    # allows its parameters to be calibrated offline (docs/analysis_plan.md §6).
    if cfg.get("monitor_mode", 0) >= 1 and "sigma_floor" in cfg:
        p = monitor_replay.MonitorParams(cfg["ewma_alpha"], cfg["k_sigma"], cfg["guard_ratio"], cfg["sigma_floor"],
                                         cfg["warmup_jobs"], bool(cfg["monitor_frozen"]), cfg["alarm_consec"])
        for tid, task in enumerate(sare.TASKS[:3]):
            if not cfg["monitor_task_mask"] & (1 << tid):
                continue
            d = tr[tr["task"] == task].sort_values("seq")
            if d.empty:
                continue
            alarm, _ = monitor_replay.replay_frozen_fast(d["response"].to_numpy(), sare.PERIOD_MS[task] * cpu_hz // 1000, p)
            n_diff = int((alarm != d["alarm"].to_numpy()).sum())
            add(f"{task}:monitor_replay_exact", n_diff == 0, f"{n_diff} jobs differ from the host replay")

    if "rx_frames_bad" in st and len(st):
        flooded = "flood" in (meta.get("scenario_spec") or {})
        # Amendment A1 (2026-09-30, before any evaluation run; docs/analysis_plan.md):
        # rare host->DUT sensor-frame losses (whole frames, no UART error) are
        # tolerated up to 1e-4 of the frames received; DUT->host stays strict.
        bad = int(st["rx_frames_bad"].iloc[-1])
        ok_frames = int(st["rx_frames_ok"].iloc[-1])
        limit = max(1, int(1e-4 * ok_frames))
        add("rx_clean", flooded or bad <= limit,
            f"rx_frames_bad={bad} (limit {limit} = 1e-4 of {ok_frames}){' (flood scenario)' if flooded else ''}")
        # A1: UART noise flags (value recovered by 3-sample majority vote) are
        # tolerated up to 1e-5 of the bytes; framing/overrun errors are not.
        if "rx_ne" in st:
            last = st.iloc[-1]
            ne, fe_ore = int(last["rx_ne"]), int(last["rx_fe"]) + int(last["rx_ore"])
            lim_ne = max(1, int(1e-5 * int(last["rx_bytes"])))
            add("rx_hw_clean", flooded or (fe_ore == 0 and ne <= lim_ne),
                f"FE+ORE={fe_ore}, NE={ne} (limit {lim_ne}){' (flood scenario)' if flooded else ''}")
    return res


def validate_campaign(root: Path) -> pd.DataFrame:
    rows = []
    for m in sorted(root.glob("*.meta.json")):
        tr, st, meta = sare.load_run(m.with_name(m.name.removesuffix(".meta.json")))
        for name, ok, detail in check_run(tr, st, meta):
            rows.append({"scenario": meta["scenario"], "run": meta["run_id"], "check": name, "ok": ok,
                         "detail": detail, "build": (meta.get("fw_info") or "").split(" ")[0]})
    df = pd.DataFrame(rows)
    builds = set(df["build"])
    df.loc[len(df)] = {"scenario": "*", "run": -1, "check": "single_build", "ok": len(builds) == 1,
                       "detail": ", ".join(sorted(builds)), "build": ""}
    return df


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign", type=Path)
    args = ap.parse_args()
    df = validate_campaign(args.campaign)
    bad = df[~df["ok"]]
    runs = df[df["run"] >= 0].groupby(["scenario", "run"])["ok"].all()
    print(f"{runs.sum()}/{len(runs)} runs valid, {len(bad)} failed checks")
    if len(bad):
        print(bad[["scenario", "run", "check", "detail"]].to_string(index=False))
    return 0 if bad.empty else 1


if __name__ == "__main__":
    sys.exit(main())
