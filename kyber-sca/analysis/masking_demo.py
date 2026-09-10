#!/usr/bin/env python3
"""Contrast the CPA attack against unmasked vs. arithmetically-masked
simulated traces -- same purpose as side-channel/masking_demo.py, adapted
to ML-KEM's coefficient-wise leakage model. See simulate_traces.py for
what "masked" means here (toy additive mod-Q splitting, not a claim
about any real masked ML-KEM implementation).
"""
import numpy as np

from cpa_attack import attack_coefficient
from simulate_traces import simulate


def run(masked, n_traces=3000, n_coeffs=16, n_samples=500, scale=1.0, noise_sigma=1.0, seed=0):
    traces, ciphertext_coeffs, secret_coeffs = simulate(
        n_traces, n_coeffs, n_samples, scale, noise_sigma, masked, seed,
    )
    recovered = np.zeros(n_coeffs, dtype=np.int64)
    peaks = np.zeros(n_coeffs)
    for i in range(n_coeffs):
        recovered[i], peaks[i] = attack_coefficient(ciphertext_coeffs[:, i], traces)
    correct = int((recovered == secret_coeffs).sum())
    return correct, n_coeffs, peaks.mean()


def main():
    n_traces, n_coeffs = 3000, 16

    print(f"=== UNMASKED implementation ({n_traces} traces) ===")
    correct, total, mean_peak = run(masked=False, n_traces=n_traces, n_coeffs=n_coeffs)
    print(f"Coefficients correct: {correct}/{total}   mean peak |r| = {mean_peak:.3f}")

    print(f"\n=== MASKED implementation ({n_traces} traces) ===")
    correct, total, mean_peak = run(masked=True, n_traces=n_traces, n_coeffs=n_coeffs)
    print(f"Coefficients correct: {correct}/{total}   mean peak |r| = {mean_peak:.3f}")


if __name__ == "__main__":
    main()
