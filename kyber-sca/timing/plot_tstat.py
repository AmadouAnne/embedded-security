#!/usr/bin/env python3
"""Plot the running Welch's t-statistic vs. number of traces.

Standard dudect-style plot: as trials accumulate, a real leak's |t| grows
roughly with sqrt(N) and crosses the 4.5 threshold; a non-leaking
implementation's |t| stays bounded and noisy around 0. Handles the
degenerate zero-variance case (see welch_ttest.py) by plotting t=0 for any
step where pooled variance is exactly zero, rather than NaN/undefined --
annotated on the plot, never silently smoothed over.

Usage:
    python3 plot_tstat.py ../traces/timing/run1_100k.csv ../results/timing/tstat_run1.png
"""
import csv
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

STEP = 500


def load(path):
    c0, c1 = [], []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            cls = int(row["class"])
            cyc = int(row["cycles"])
            (c0 if cls == 0 else c1).append(cyc)
    return np.array(c0, dtype=np.float64), np.array(c1, dtype=np.float64)


def running_welch_t(c0, c1, step=STEP):
    ns, ts, degenerate = [], [], []
    n = min(len(c0), len(c1))
    for k in range(step, n + 1, step):
        a, b = c0[:k], c1[:k]
        m0, m1 = a.mean(), b.mean()
        v0, v1 = a.var(ddof=1), b.var(ddof=1)
        se2 = v0 / k + v1 / k
        ns.append(k)
        if se2 == 0.0:
            ts.append(0.0)
            degenerate.append(True)
        else:
            ts.append((m0 - m1) / np.sqrt(se2))
            degenerate.append(False)
    return np.array(ns), np.array(ts), np.array(degenerate)


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <traces.csv> <out.png>", file=sys.stderr)
        return 1

    csv_path, out_path = sys.argv[1], sys.argv[2]
    c0, c1 = load(csv_path)
    if len(c0) < STEP or len(c1) < STEP:
        print("ERROR: need at least STEP trials per class", file=sys.stderr)
        return 1

    ns, ts, degenerate = running_welch_t(c0, c1)
    all_degenerate = bool(degenerate.all())

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.axhline(4.5, color="#c0392b", linestyle="--", linewidth=1,
               label="|t| = 4.5 (leak threshold)")
    ax.axhline(-4.5, color="#c0392b", linestyle="--", linewidth=1)
    ax.axhline(0, color="#888888", linewidth=0.8)
    ax.plot(ns, ts, color="#2c3e50", linewidth=1.2, label="Welch's t")
    ax.set_xlabel("number of traces per class")
    ax.set_ylabel("Welch's t-statistic")
    title = "ML-KEM-512 m4fspeed crypto_kem_dec -- fixed vs. random ciphertext"
    if all_degenerate:
        title += "\n(t=0 plotted: zero within-class variance at every step -- see note below)"
    ax.set_title(title, fontsize=10)
    ax.legend(loc="upper right", fontsize=8)
    ax.set_ylim(-10, 10)

    fig.tight_layout()

    if all_degenerate:
        fig.subplots_adjust(bottom=0.34)
        fig.text(0.5, 0.02,
                  "Every step had zero measured cycle-count variance in both "
                  "classes (mean0=mean1 exactly); t is reported as 0 by\n"
                  "convention rather than left undefined (0/0). See "
                  "welch_ttest.py output and docs/methodology.md Section 5\n"
                  "for the keypair-generation control confirming the "
                  "harness itself detects real variance when present.",
                  ha="center", va="bottom", fontsize=7.5)

    fig.savefig(out_path, dpi=150)
    print(f"wrote {out_path}")
    print(f"final |t| at N={ns[-1]}: {abs(ts[-1]):.4f}"
          + (" (degenerate/zero-variance)" if degenerate[-1] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
