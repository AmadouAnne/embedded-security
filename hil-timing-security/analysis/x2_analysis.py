#!/usr/bin/env python3
"""X2 (exploratory): per-task job counts, misses and worst R/D from the traces of
the overload runs, which are partial by construction (the trace transport is
starved). Writes x2_overload.csv.

  python3 x2_analysis.py ../data/raw/overload_x2 ../data/processed
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

import sare

ATTACK_PERIOD_MS = 10


def x2_table(root: Path) -> pd.DataFrame:
    rows = []
    for meta in sorted(root.glob("rep*/overload_x2/X2_*_r00.meta.json")):
        prefix = meta.with_name(meta.name.removesuffix(".meta.json"))
        rep, sc = meta.parts[-3], prefix.name.removesuffix("_r00")
        trace = prefix.with_name(prefix.name + ".trace.csv")
        if not trace.exists() or trace.stat().st_size < 100:
            rows.append({"scenario": sc, "rep": rep, "task": "*", "jobs": 0})
            continue
        tr, _, _ = sare.load_run(prefix)
        tr = tr[tr["task"] != "idle"]
        for task, g in tr.groupby("task", observed=True):
            d_us = (ATTACK_PERIOD_MS if task == "attack" else sare.PERIOD_MS[task]) * 1e3
            rows.append({"scenario": sc, "rep": rep, "task": str(task), "jobs": len(g),
                         "misses": int(g["miss"].sum()), "R_max_over_D": g["response_us"].max() / d_us})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    out = Path(sys.argv[2]) / "x2_overload.csv"
    x2_table(Path(sys.argv[1])).to_csv(out, index=False)
    print(out)
