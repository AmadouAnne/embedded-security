#!/usr/bin/env python3
"""Decode the post-run monitor state read over the ST-LINK in the X2 runs.

mon_state_t is { float mu; float var; uint32_t n; uint8_t consec; } (16 bytes,
little-endian), indexed by task id. With monitor_mode = 1 and every task in the
mask, n is the number of completed jobs of each task. Released jobs are
duration / T (all tasks start at the common epoch).

  python3 overload_readout.py ../data/raw/overload_x2
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

TASKS = ["sensor", "control", "nav", "health", "security", "logging", "attack", "idle"]
PERIOD_MS = {"sensor": 5, "control": 10, "nav": 20, "health": 50, "security": 100, "logging": 500, "attack": 10}


def decode(path: Path) -> dict[str, int]:
    raw = path.read_bytes()
    return {t: struct.unpack_from("<ffIB", raw, 16 * i)[2] for i, t in enumerate(TASKS) if t != "idle"}


def table(root: Path, duration_ms: int = 60_000):
    rows = []
    for f in sorted(root.glob("rep*/overload_x2/*_st.bin")):
        sc, rep = f.name.removesuffix("_st.bin"), f.parts[-3]
        n = decode(f)
        for t, done in n.items():
            rel = duration_ms // PERIOD_MS[t]
            rows.append({"scenario": sc, "rep": rep, "task": t, "released": rel, "completed": done,
                         "completed_ratio": done / rel})
    return rows


if __name__ == "__main__":
    import pandas as pd
    df = pd.DataFrame(table(Path(sys.argv[1])))
    pd.set_option("display.width", 200)
    print(df.pivot_table(index=["scenario", "rep"], columns="task", values="completed_ratio").round(3))
