#!/usr/bin/env python3
"""Offline calibration of the EWMA timing monitor on the C0 runs.

Rule (fixed in docs/analysis_plan.md §6 before any C0 data exist):
  constraint  false-alarm rate <= 1e-4 per job on Sensor, Control and Nav,
              and no mitigation trigger (alarm_consec consecutive alarms);
  objective   lowest effective threshold min(mu + k*sigma, guard*D) / D,
              worst case over the three tasks (i.e. highest sensitivity);
  one parameter set for all tasks; frozen baseline; guard ratio fixed at 0.8.
Generalisation is estimated by leave-one-run-out: select on n-1 runs,
measure the false-alarm rate on the held-out run.

  python3 calibrate_monitor.py ../data/raw/campaign_v1 [--out ../data/processed]
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd

import monitor_replay as mr
import sare
import validate

TASKS = ("sensor", "control", "nav")
FP_MAX = 1e-4
GRID = dict(
    ewma_alpha=(0.02, 0.05, 0.1),
    warmup_jobs=(100, 200, 500),
    k_sigma=(2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0),
    sigma_floor=(0.0, 0.005, 0.01, 0.02, 0.05, 0.1),
)


def load_c0(root: Path, scenario: str = "C0_monitor_calibration"):
    """Valid C0 runs only: {run_id: {task: (R cycles in job order, D cycles)}}."""
    runs = {}
    for m in sorted(root.glob(f"{scenario}_r*.meta.json")):
        prefix = m.with_name(m.name.removesuffix(".meta.json"))
        tr, st, meta = sare.load_run(prefix)
        if not all(ok for _, ok, _ in validate.check_run(tr, st, meta)):
            print(f"skip invalid run {prefix.name}")
            continue
        runs[meta["run_id"]] = {
            t: (tr[tr["task"] == t].sort_values("seq")["response"].to_numpy(),
                sare.PERIOD_MS[t] * meta["cpu_hz"] // 1000)
            for t in TASKS}
    if len(runs) < 2:
        raise SystemExit(f"need >= 2 valid {scenario} runs, found {len(runs)}")
    return runs


def evaluate(runs: dict, p: mr.MonitorParams, run_ids) -> dict:
    """Pooled false alarms, triggers and worst-case threshold over the given runs."""
    alarms = jobs = trig = 0
    thr = []
    for rid in run_ids:
        for t, (R, D) in runs[rid].items():
            a, g = mr.replay_frozen_fast(R, D, p)
            alarms += int(a[p.warmup_jobs:].sum())
            jobs += max(len(R) - p.warmup_jobs, 0)
            trig += int(g.sum())
            thr.append(mr.threshold_over_d(R, D, p))
    return {"fp_rate": alarms / max(jobs, 1), "alarms": alarms, "jobs": jobs,
            "triggers": trig, "thr_over_d": float(np.max(thr))}


def grid():
    for vals in itertools.product(*GRID.values()):
        yield mr.MonitorParams(guard_ratio=0.8, frozen=True, **dict(zip(GRID, vals)))


def select(runs: dict, run_ids) -> tuple[mr.MonitorParams | None, pd.DataFrame]:
    rows = []
    for p in grid():
        e = evaluate(runs, p, run_ids)
        rows.append({**p.__dict__, **e, "feasible": e["fp_rate"] <= FP_MAX and e["triggers"] == 0})
    df = pd.DataFrame(rows)
    feas = df[df["feasible"]].sort_values(["thr_over_d", "k_sigma", "sigma_floor"])
    if feas.empty:
        return None, df
    best = feas.iloc[0]
    native = lambda v: v.item() if hasattr(v, "item") else v      # numpy scalar -> Python (JSON, TOML)
    return mr.MonitorParams(**{f: native(best[f]) for f in mr.MonitorParams.__dataclass_fields__}), df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign", type=Path)
    ap.add_argument("--out", type=Path, default=Path("../data/processed"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    runs = load_c0(args.campaign)
    ids = sorted(runs)
    best, table = select(runs, ids)
    table.to_csv(args.out / "monitor_calibration_grid.csv", index=False)
    if best is None:
        raise SystemExit("no parameter set meets the false-alarm constraint: widen the grid (and report it)")

    loro = []
    for held in ids:
        p, _ = select(runs, [r for r in ids if r != held])
        e = evaluate(runs, p, [held]) if p else {"fp_rate": np.nan, "triggers": np.nan}
        loro.append({"held_out_run": held, "fp_rate": e["fp_rate"], "triggers": e["triggers"],
                     "params": p.__dict__ if p else None})

    result = {"selected": best.__dict__, "in_sample": evaluate(runs, best, ids),
              "leave_one_run_out": loro, "rule": {"fp_max": FP_MAX, "tasks": TASKS, "grid": GRID}}
    (args.out / "monitor_calibration.json").write_text(json.dumps(result, indent=2, default=float))
    print(json.dumps(result["selected"], indent=2))
    print("in-sample:", result["in_sample"])
    print("leave-one-run-out FP rates:", [round(r["fp_rate"], 6) for r in loro])
    print("\n# paste into hil/campaign.toml [defaults] before the evaluation runs:")
    b = best
    print(f"ewma_alpha = {b.ewma_alpha}\nwarmup_jobs = {b.warmup_jobs}\nk_sigma = {b.k_sigma}\n"
          f"sigma_floor = {b.sigma_floor}\nguard_ratio = {b.guard_ratio}")


if __name__ == "__main__":
    main()
