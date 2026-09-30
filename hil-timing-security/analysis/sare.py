"""Load raw HIL runs and compute the timing metrics used in the paper.

Terminology (use it consistently in the manuscript):
  MOET  maximum observed execution time (a measurement, NOT a safe WCET bound)
  mOET  minimum observed execution time (observed BCET)
  R     response time = finish - nominal release
  RJ    response-time jitter = max(R) - min(R)
  SLJ   start-latency jitter = max(S) - min(S), S = start - release
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

TASKS = ["sensor", "control", "nav", "health", "security", "logging", "attack", "idle"]
PERIOD_MS = {"sensor": 5, "control": 10, "nav": 20, "health": 50, "security": 100, "logging": 500, "attack": np.nan}
TF_DEADLINE_MISS, TF_ALARM, TF_MITIGATING, TF_DATA_REJECT, TF_SLOW_PATH = 1, 2, 4, 8, 16


def load_run(prefix: Path) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """prefix = path without suffix, e.g. data/raw/campaign_v1/E1_baseline_r00"""
    meta = json.loads(prefix.with_suffix(".meta.json").read_text())
    tr = pd.read_csv(prefix.with_suffix(".trace.csv"))
    st = pd.read_csv(prefix.with_suffix(".stats.csv"))
    us = 1e6 / meta["cpu_hz"]
    tr["task"] = pd.Categorical.from_codes(tr["task"], TASKS)
    for c in ("start_lat", "response", "exec"):
        tr[c + "_us"] = tr[c] * us
    tr["mon_cost_us"] = tr["mon_cost"] * us
    tr["miss"] = (tr["flags"] & TF_DEADLINE_MISS) > 0
    tr["alarm"] = (tr["flags"] & TF_ALARM) > 0
    tr["slow"] = (tr["flags"] & TF_SLOW_PATH) > 0
    # Absolute release time in seconds since the epoch, unwrapped per task.
    period_cyc = tr["task"].map(PERIOD_MS).astype(float) * meta["cpu_hz"] / 1e3
    tr["t_s"] = tr["seq"] * period_cyc / meta["cpu_hz"]
    st["cpu_load"] = 1.0 - st["idle_cyc"] / st["window_cyc"]
    st = st.iloc[1:]   # first window includes the boot phase
    for df in (tr, st):
        df["scenario"] = meta["scenario"]
        df["run"] = meta["run_id"]
    return tr, st, meta


def load_campaign(root: Path) -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
    trs, sts, metas = [], [], []
    for m in sorted(root.glob("*.meta.json")):
        tr, st, meta = load_run(m.with_name(m.name.removesuffix(".meta.json")))
        trs.append(tr), sts.append(st), metas.append(meta)
    if not metas:
        raise FileNotFoundError(f"no runs in {root}")
    return pd.concat(trs, ignore_index=True), pd.concat(sts, ignore_index=True), metas


def task_metrics(tr: pd.DataFrame) -> pd.DataFrame:
    """Per scenario x task timing table (all runs pooled)."""
    g = tr[tr["task"] != "idle"].groupby(["scenario", "task"], observed=True)
    out = g.agg(
        jobs=("exec_us", "size"),
        mOET_us=("exec_us", "min"),
        mean_exec_us=("exec_us", "mean"),
        p99_exec_us=("exec_us", lambda x: np.percentile(x, 99)),
        MOET_us=("exec_us", "max"),
        R_min_us=("response_us", "min"),
        R_mean_us=("response_us", "mean"),
        R_p999_us=("response_us", lambda x: np.percentile(x, 99.9)),
        R_max_us=("response_us", "max"),
        R_std_us=("response_us", "std"),
        S_min_us=("start_lat_us", "min"),
        S_max_us=("start_lat_us", "max"),
        misses=("miss", "sum"),
        alarms=("alarm", "sum"),
        slow_path=("slow", "mean"),
    )
    out["RJ_us"] = out["R_max_us"] - out["R_min_us"]
    out["SLJ_us"] = out["S_max_us"] - out["S_min_us"]
    out["miss_ratio"] = out["misses"] / out["jobs"]
    out["D_us"] = [PERIOD_MS[t] * 1e3 for _, t in out.index]
    out["R_max_over_D"] = out["R_max_us"] / out["D_us"]
    return out.reset_index()


def load_metrics(st: pd.DataFrame) -> pd.DataFrame:
    return st.groupby("scenario")["cpu_load"].agg(["mean", "max", "std"]).add_prefix("cpu_").reset_index()


def detection_metrics(tr: pd.DataFrame, monitored=("sensor", "control", "nav")) -> pd.DataFrame:
    """Per run: false-alarm rate, first alarm vs first miss, detection lead time."""
    rows = []
    for (sc, run), d in tr.groupby(["scenario", "run"]):
        m = d[d["task"].isin(monitored)]
        alarms, misses = m[m["alarm"]], d[d["miss"]]
        t_alarm = alarms["t_s"].min() if len(alarms) else np.nan
        t_miss = misses["t_s"].min() if len(misses) else np.nan
        rows.append({
            "scenario": sc, "run": run, "jobs": len(m),
            "alarm_rate": len(alarms) / max(len(m), 1),
            "first_alarm_s": t_alarm, "first_miss_s": t_miss,
            "lead_ms": (t_miss - t_alarm) * 1e3 if np.isfinite(t_alarm) and np.isfinite(t_miss) else np.nan,
            "detected_before_miss": bool(np.isfinite(t_alarm) and (not np.isfinite(t_miss) or t_alarm <= t_miss)),
            "mon_cost_mean_cyc": m["mon_cost"].mean(),
            "mon_cost_max_cyc": m["mon_cost"].max(),
        })
    return pd.DataFrame(rows)
