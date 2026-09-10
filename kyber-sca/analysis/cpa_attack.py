#!/usr/bin/env python3
"""Coefficient-wise CPA attack against ML-KEM's NTT-domain pointwise multiplication.

Works on any .npz with `traces` (n_traces x n_samples) and
`ciphertext_coeffs` (n_traces x n_coeffs) -- real captures or
simulate_traces.py's output alike, same load_dataset() contract
side-channel/cpa_attack.py uses for AES. If `secret_coeffs` is present
(simulated ground truth), recovered coefficients are scored against it.

For each targeted coefficient index i and each of the Q=3329 candidate
values, this correlates the Hamming-weight hypothesis of
`ciphertext_coeffs[:, i] * candidate mod Q` against every sample of
every trace (Pearson's r), and picks the candidate with the strongest
correlation -- the direct coefficient-wise analogue of
side-channel/cpa_attack.py's byte-wise AES SubBytes attack.
"""
import argparse

import numpy as np

from kyber_math import Q, hamming_weight, pointwise_mul_mod_q


def load_dataset(path):
    data = np.load(path)
    traces = data["traces"]
    ciphertext_coeffs = data["ciphertext_coeffs"]
    secret_coeffs = data["secret_coeffs"] if "secret_coeffs" in data else None
    return traces, ciphertext_coeffs, secret_coeffs


def pearson_corr(hyp, traces):
    """hyp: (n_traces, n_candidates), traces: (n_traces, n_samples).

    Returns (n_candidates, n_samples) correlation matrix via a single
    matrix multiply -- the standard CPA-via-BLAS trick, needed here
    because Q=3329 candidates per coefficient (vs AES's 256) would be too
    slow with an explicit per-candidate loop.
    """
    hc = hyp - hyp.mean(axis=0, keepdims=True)
    tc = traces - traces.mean(axis=0, keepdims=True)
    num = hc.T @ tc
    h_norm = np.sqrt((hc ** 2).sum(axis=0))
    t_norm = np.sqrt((tc ** 2).sum(axis=0))
    den = h_norm[:, None] * t_norm[None, :]
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where(den > 0, num / den, 0.0)


def attack_coefficient(ciphertext_col, traces):
    """Returns (best_candidate, best_abs_corr, corr_at_best_per_sample)."""
    candidates = np.arange(Q)
    hyp = hamming_weight(pointwise_mul_mod_q(ciphertext_col[:, None], candidates[None, :]))
    corr = pearson_corr(hyp, traces)  # (Q, n_samples)
    abs_corr = np.abs(corr)
    peak_per_candidate = abs_corr.max(axis=1)
    best_candidate = int(np.argmax(peak_per_candidate))
    return best_candidate, float(peak_per_candidate[best_candidate])


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dataset")
    p.add_argument("--plot", action="store_true")
    args = p.parse_args()

    traces, ciphertext_coeffs, secret_coeffs = load_dataset(args.dataset)
    n_traces, n_coeffs = ciphertext_coeffs.shape
    print(f"{n_traces} traces, {traces.shape[1]} samples, {n_coeffs} targeted coefficients")

    recovered = np.zeros(n_coeffs, dtype=np.int64)
    peaks = np.zeros(n_coeffs)
    for i in range(n_coeffs):
        recovered[i], peaks[i] = attack_coefficient(ciphertext_coeffs[:, i], traces)

    print("Recovered coefficients:", recovered.tolist())
    print(f"Mean peak |r| = {peaks.mean():.3f}")

    if secret_coeffs is not None:
        secret_coeffs = secret_coeffs[:n_coeffs]
        correct = int((recovered == secret_coeffs).sum())
        print(f"True coefficients:     {secret_coeffs.tolist()}")
        print(f"Coefficients correct: {correct}/{n_coeffs}"
              + ("  -- FULL KEY SLICE RECOVERED" if correct == n_coeffs else ""))

    if args.plot:
        import matplotlib
        matplotlib.use("Agg")  # headless-safe; avoid a GUI backend crashing on exit
        import matplotlib.pyplot as plt
        plt.bar(range(n_coeffs), peaks)
        plt.xlabel("targeted NTT coefficient index")
        plt.ylabel("peak |Pearson r|")
        plt.title("CPA peak correlation per targeted coefficient")
        out = args.dataset.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        plt.savefig(f"results/cpa_{out}.png", dpi=150, bbox_inches="tight")
        print(f"Saved plot to results/cpa_{out}.png")


if __name__ == "__main__":
    main()
