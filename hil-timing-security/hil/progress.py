#!/usr/bin/env python3
"""Live, read-only view of a running campaign (never touches the hardware).

  python3 hil/progress.py            # refreshes every 5 s, Ctrl-C to quit
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAMP = ROOT / "hil" / "campaign.toml"
OUT = ROOT / "data" / "raw" / "campaign_v1"
LOG = OUT / "campaign.log"
JOBS_PER_S = 200 + 100 + 50 + 20 + 10 + 2          # workload jobs per second (all six tasks)


def plan():
    c = tomllib.loads(CAMP.read_text())
    d, reps = c.get("defaults", {}), c.get("repetitions", 1)
    for sc in c["scenario"]:
        dur = sc.get("config", {}).get("duration_ms", d.get("duration_ms", 120_000)) / 1000
        for r in range(sc.get("repetitions", reps)):
            yield sc["name"], r, dur


def status():
    runs = list(plan())
    total_s = sum(d + 8 for _, _, d in runs)                 # ~8 s reset + handshake per run
    done, done_s, current = 0, 0.0, None
    for name, r, dur in runs:
        prefix = OUT / f"{name}_r{r:02d}"
        if prefix.with_suffix(".meta.json").exists():
            done += 1
            done_s += dur + 8
        elif prefix.with_suffix(".trace.csv").exists() and current is None:
            tr = prefix.with_suffix(".trace.csv")
            current = (name, r, dur, tr.stat().st_mtime, tr)
    log = LOG.read_text().splitlines() if LOG.exists() else []
    invalid = sum("INVALID" in line for line in log)
    active = subprocess.run(["systemctl", "--user", "is-active", "sare-campaign"],
                            capture_output=True, text=True).stdout.strip()

    os.system("clear")
    print(f"SARE campaign  {time.strftime('%H:%M:%S')}   service: {active}")
    print(f"runs complete  : {done}/{len(runs)}   ({100 * done_s / total_s:.1f} % of measurement time)")
    print(f"invalid retries: {invalid}")
    if current:
        name, r, dur, _, tr = current
        start = min(tr.stat().st_ctime, time.time())
        el = time.time() - start
        rows = max(sum(1 for _ in tr.open()) - 1, 0)
        pct = min(100.0, 100 * rows / (dur * JOBS_PER_S))
        bar = "#" * int(pct / 4) + "-" * (25 - int(pct / 4))
        print(f"current run    : {name} r{r}   [{bar}] {pct:5.1f} %   {rows} jobs recorded")
    left = max(total_s - done_s, 0)
    print(f"remaining      : ~{left / 3600:.1f} h  -> ends around {time.strftime('%H:%M', time.localtime(time.time() + left))}")
    print("\nlast results:")
    for line in [l for l in log if " run " in l][-8:]:
        print("  " + line.strip())
    print("\n(read-only view; Ctrl-C to quit. The campaign keeps running.)")


if __name__ == "__main__":
    try:
        while True:
            status()
            if "--once" in sys.argv:
                break
            time.sleep(5)
    except KeyboardInterrupt:
        pass
