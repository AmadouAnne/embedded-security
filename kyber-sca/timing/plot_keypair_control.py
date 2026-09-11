#!/usr/bin/env python3
"""Histogram of the keypair-generation measurement control (see
kyber-sca/firmware/pqm4/common/keypair_control.c and docs/methodology.md
Section 5): demonstrates the DWT-based harness detects real cycle-count
variance when it is actually present, ruling out "the harness is broken"
as an explanation for crypto_kem_dec's zero-variance result.

Usage:
    python3 plot_keypair_control.py ../traces/timing/keypair_control_5k.csv ../results/timing/keypair_control_hist.png
"""
import csv
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load(path):
    vals = []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            vals.append(int(row["cycles"]))
    return vals


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <control.csv> <out.png>", file=sys.stderr)
        return 1

    vals = load(sys.argv[1])
    n = len(vals)
    uniq = len(set(vals))

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(vals, bins=60, color="#2c3e50")
    ax.set_xlabel("cycles (DWT->CYCCNT delta)")
    ax.set_ylabel("count")
    ax.set_title(
        f"crypto_kem_keypair timing, N={n}, {uniq} unique values\n"
        "(measurement-harness control, not a decapsulation result)",
        fontsize=10,
    )
    fig.tight_layout()
    fig.savefig(sys.argv[2], dpi=150)
    print(f"wrote {sys.argv[2]}")
    print(f"N={n} unique={uniq} min={min(vals)} max={max(vals)} "
          f"mean={sum(vals)/n:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
