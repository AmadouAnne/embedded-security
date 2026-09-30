#!/usr/bin/env python3
"""Hardware bring-up: one short nominal run, then integrity checks and a summary.

  python3 bringup.py --port /dev/ttyACM0 [--seconds 10] [--work 32,40,20,64,1,0]

Use it after every flash and to calibrate work_units before a campaign.
Output goes to data/bringup/ (never mixed with campaign data).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import protocol as P
from orchestrator import Link, default_port, run_once
from provenance import firmware_build_id

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis"))
import sare  # noqa: E402
import validate  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None, help="link port (default: ESP32 bridge by stable name)")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--seconds", type=int, default=10)
    ap.add_argument("--work", default="512,362,1334,1500,1,0", help="work_units for the 6 tasks")
    ap.add_argument("--sec-chunk", type=int, default=65536)
    ap.add_argument("--reset-cmd", default="st-flash --connect-under-reset reset")
    args = ap.parse_args()

    out = ROOT / "data" / "bringup" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True)
    cfg = P.RunConfig(duration_ms=args.seconds * 1000, work_units=[int(x) for x in args.work.split(",")],
                      sec_chunk_bytes=args.sec_chunk, monitor_mode=P.MON_DETECT)
    port = args.port or default_port()
    print(f"link port: {port}")
    link = Link(port, args.baud)
    meta = run_once(link, cfg, {"name": "bringup"}, seed=1, out=out / "bringup_r00",
                    reset_cmd=args.reset_cmd, expect_build=firmware_build_id())

    tr, st, meta = sare.load_run(out / "bringup_r00")
    print(f"\nfirmware : {meta['fw_info']}")
    c = meta["calibration"] or {}
    print(f"probe cost (cycles, min/max): DWT read {c.get('dwt_read_min')}/{c.get('dwt_read_max')}, "
          f"trace_push {c.get('trace_push_min')}/{c.get('trace_push_max')}, "
          f"switch hooks {c.get('acct_hooks_min')}/{c.get('acct_hooks_max')}")

    tm = sare.task_metrics(tr)
    tm["U_%"] = tm["mean_exec_us"] / tm["D_us"] * 100
    cols = ["task", "jobs", "mOET_us", "mean_exec_us", "MOET_us", "R_max_us", "RJ_us", "SLJ_us", "misses", "alarms", "U_%"]
    print("\n" + tm[cols].round(1).to_string(index=False))
    print(f"\nsum of task utilisation : {tm['U_%'].sum():.1f} %")
    print(f"CPU load (idle-based)   : mean {st['cpu_load'].mean() * 100:.1f} %, max {st['cpu_load'].max() * 100:.1f} %")
    last = st.iloc[-1]
    print(f"link RX                 : {int(last.rx_frames_ok)} frames ok, {int(last.rx_frames_bad)} bad, "
          f"{int(last.rx_overflow)} overflow; sensor frames sent {meta['sensor_frames_sent']}")

    checks = validate.check_run(tr, st, meta)
    failed = [(n, d) for n, ok, d in checks if not ok]
    print(f"\nvalidation: {len(checks) - len(failed)}/{len(checks)} checks passed")
    for n, d in failed:
        print(f"  FAIL {n}: {d}")
    print(f"data: {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
