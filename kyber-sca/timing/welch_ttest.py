#!/usr/bin/env python3
"""Welch's t-test on dudect fixed-vs-random timing traces.

Standard dudect leakage-detection statistic: Welch's t-test between the two
classes' cycle-count distributions, |t| > 4.5 is the conventional threshold
in the dudect/TVLA literature for "leak detected with high confidence"
(does not by itself say how to exploit it, only that the two distributions
are distinguishable). See kyber-sca/docs/methodology.md Section 5.

Honesty discipline (carried over from the rest of this project, see
docs/methodology.md Section 3 point 4): if a class has zero variance, a
textbook Welch's t-test is undefined (division by zero) -- this is reported
explicitly as a degenerate/zero-variance result, never silently converted
into a fabricated t-value or suppressed.

Usage:
    python3 welch_ttest.py ../traces/timing/run1_100k.csv
"""
import csv
import math
import sys


def load(path):
    c0, c1 = [], []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            cls = int(row["class"])
            cyc = int(row["cycles"])
            (c0 if cls == 0 else c1).append(cyc)
    return c0, c1


def mean(xs):
    return sum(xs) / len(xs)


def variance(xs, m=None):
    if m is None:
        m = mean(xs)
    if len(xs) < 2:
        return 0.0
    return sum((x - m) ** 2 for x in xs) / (len(xs) - 1)


def welch_t(c0, c1):
    n0, n1 = len(c0), len(c1)
    m0, m1 = mean(c0), mean(c1)
    v0, v1 = variance(c0, m0), variance(c1, m1)

    se2 = v0 / n0 + v1 / n1
    if se2 == 0.0:
        return {
            "n0": n0, "n1": n1, "mean0": m0, "mean1": m1,
            "var0": v0, "var1": v1, "t": None, "degenerate": True,
        }

    t = (m0 - m1) / math.sqrt(se2)
    return {
        "n0": n0, "n1": n1, "mean0": m0, "mean1": m1,
        "var0": v0, "var1": v1, "t": t, "degenerate": False,
    }


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <traces.csv>", file=sys.stderr)
        return 1

    c0, c1 = load(sys.argv[1])
    if not c0 or not c1:
        print("ERROR: need at least one trial in each class", file=sys.stderr)
        return 1

    res = welch_t(c0, c1)

    print(f"class 0 (fixed):  n={res['n0']:>7}  mean={res['mean0']:.3f}  var={res['var0']:.6g}")
    print(f"class 1 (random): n={res['n1']:>7}  mean={res['mean1']:.3f}  var={res['var1']:.6g}")

    if res["degenerate"]:
        print("Welch's t-test: DEGENERATE (zero pooled variance -- both "
              "classes' cycle counts have zero within-class variance). "
              "Reported as such, not converted into a t-value: this is a "
              "measurement fact (see the keypair-generation control "
              "measurement in docs/methodology.md, which does show "
              "variance with the same harness), not test inconclusiveness.")
        if res["mean0"] == res["mean1"]:
            print("mean0 == mean1 exactly: no distinguishable timing "
                  "difference was observed between the two classes at this "
                  "sample size.")
        else:
            print(f"mean0 != mean1 (delta={res['mean0'] - res['mean1']:.3f} "
                  "cycles) despite zero within-class variance in each -- "
                  "this WOULD be a perfect (deterministic) distinguisher; "
                  "re-check the harness before reporting this as a leak.")
        return 0

    t = res["t"]
    print(f"Welch's t-statistic: {t:.4f}")
    if abs(t) > 4.5:
        print("|t| > 4.5: leak detected at conventional dudect/TVLA "
              "confidence threshold.")
    else:
        print("|t| <= 4.5: no leak detected at conventional dudect/TVLA "
              "confidence threshold (this does not prove absence of "
              "leakage, only that none was detected at this sample size).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
