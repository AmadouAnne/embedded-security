"""SYNTHETIC data generator used ONLY to exercise the analysis pipeline.

Its numbers are invented and must never appear in the paper; real data come
from hil/orchestrator.py. Output files carry "synthetic": true in their meta.
"""
import json
from pathlib import Path

import numpy as np

CPU_HZ = 180_000_000
PERIODS = [5, 10, 20, 50, 100, 500]
EXEC_US = [180, 900, 1500, 2600, 9000, 1200]


def make_run(out: Path, scenario: str, run: int, seconds=10, extra_load=0.0, alarm_after=None, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for tid, (T, C) in enumerate(zip(PERIODS, EXEC_US)):
        n = int(seconds * 1000 / T)
        k = np.arange(n)
        exec_c = (C * (1 + 0.02 * rng.standard_normal(n)) * CPU_HZ / 1e6).astype(np.int64)
        interf = (tid * 150 + extra_load * T * 1000 * rng.random(n) * (tid > 0)) * CPU_HZ / 1e6
        start = (2000 + rng.integers(0, 300, n) + interf * 0.3).astype(np.int64)
        resp = start + exec_c + interf.astype(np.int64)
        flags = (resp > T * CPU_HZ / 1000).astype(int)
        if alarm_after is not None and tid < 3:
            flags |= ((k * T / 1000 > alarm_after) & (rng.random(n) < 0.3)).astype(int) * 2
        mon = rng.integers(90, 140, n) if alarm_after is not None and tid < 3 else np.zeros(n, int)
        rows.append(np.column_stack([np.full(n, tid), flags, mon, k, (k * T * CPU_HZ // 1000) % 2**32,
                                     start, resp, exec_c]))
    tr = np.vstack(rows)
    prefix = out / f"{scenario}_r{run:02d}"
    np.savetxt(prefix.with_suffix(".trace.csv"), tr, fmt="%d", delimiter=",",
               header="task,flags,mon_cost,seq,release,start_lat,response,exec", comments="")
    # CPU load consistent with the generated exec times (+0.5 % kernel overhead),
    # as validate.py's load cross-check requires.
    win = CPU_HZ // 2
    busy = tr[:, 7].sum() / (seconds * CPU_HZ) + 0.005
    idle = (win * np.clip(1 - busy + 0.001 * rng.standard_normal(seconds * 2), 0, 1)).astype(int)
    with open(prefix.with_suffix(".stats.csv"), "w") as f:
        f.write("host_time,cyc,window_cyc,idle_cyc\n")
        for i, v in enumerate(idle):
            f.write(f"{i * 0.5},{i * win},{win},{v}\n")
    prefix.with_suffix(".meta.json").write_text(json.dumps(
        {"scenario": scenario, "run_id": run, "cpu_hz": CPU_HZ, "synthetic": True,
         "config": {"duration_ms": seconds * 1000}, "end": {"trace_drops": 0}, "host_bad_frames": 0,
         "calibration": {}, "fw_info": "build=synthetic"}))


def make_campaign(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    make_run(out, "E1_baseline", 0)
    for p, scale in ((13, 1.0), (9, 0.5), (3, 0.0)):
        for load in (100, 200, 400, 800):
            make_run(out, f"E2_p{p}_l{load}", 0, extra_load=scale * load / 1000 * 0.6, seed=p * load)
    make_run(out, "E3_random_85k", 0, extra_load=0.05, seed=3)
    make_run(out, "E4_spike_50pct", 0, extra_load=0.1, seed=4)
    make_run(out, "E5_E2_p13_l400_detect", 0, extra_load=0.3, alarm_after=2.0, seed=5)
    for r in range(3):
        make_run(out, "E1_ref", r, seconds=4, seed=200 + r)
    for r in (1, 2):
        make_run(out, "E2_p13_l400", r, extra_load=0.6 * 0.4, seed=300 + r)
    for r in range(40):
        make_run(out, "E6_evt_nominal", r, seconds=1, seed=400 + r)
