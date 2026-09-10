#!/usr/bin/env python3
"""Simulated power traces for a coefficient-wise CPA attack on ML-KEM decryption.

Simulation only -- validates the CPA pipeline (simulate_traces.py +
cpa_attack.py + masking_demo.py) before any real trace exists, exactly
the same role side-channel/simulate_traces.py plays for P6's AES-128
attack. It does NOT model the real PQM4 m4fspeed assembly's actual
leakage (different intermediate values, register widths, instruction
scheduling) -- that requires real captures. See ../docs/methodology.md
and the disclaimer in ../README.md before reading anything here as a
result about the real firmware.

Target operation being simulated: ML-KEM decryption's NTT-domain
pointwise multiplication, u_hat[i] * s_hat[i] mod Q, computed
independently for each of the n_coeffs targeted NTT coefficients. u_hat
is attacker-known (derived from a chosen ciphertext), s_hat is the fixed
unknown secret-key coefficient being recovered -- the direct structural
analogue of AES CPA's known-plaintext/unknown-key-byte setup, which is
why the same distinguisher (Pearson correlation, see cpa_attack.py)
applies coefficient-by-coefficient the same way it applies byte-by-byte.

Leakage model, deliberately as simple and explicit as P6's:
    scale * HW(u_hat[i] * s_hat[i] mod Q [^ mask]) + Gaussian noise
injected at one fixed (but a priori unknown to the attack script)
sample per coefficient; every other sample is pure noise.
"""
import argparse

import numpy as np

from kyber_math import Q, hamming_weight, pointwise_mul_mod_q


def simulate(n_traces, n_coeffs, n_samples, scale, noise_sigma, masked, seed):
    rng = np.random.default_rng(seed)

    s_hat = rng.integers(0, Q, size=n_coeffs)  # fixed unknown secret coefficients
    if masked:
        # Toy first-order arithmetic masking: each coefficient is split into
        # two additive shares mod Q, s_hat = (share1 + share2) mod Q. The
        # masked pointwise multiplication leaks each share's product with
        # u_hat separately (two different samples), never the unmasked
        # product -- same purpose as P6's boolean masking of AES, adapted to
        # ML-KEM's arithmetic (mod Q, not XOR) domain.
        #
        # Critical: the mask must be freshly random on EVERY trace/execution,
        # not fixed for the whole dataset -- a fixed mask is just another
        # fixed unknown value and CPA recovers it exactly as easily as it
        # recovers s_hat itself (caught by actually running this: a first
        # version drew share1 once outside the trace loop and still got a
        # ~0.85 peak correlation, same as unmasked, just against the wrong
        # candidate -- it was recovering share1, not failing to find anything).
        share1 = rng.integers(0, Q, size=(n_traces, n_coeffs))
        share2 = (s_hat[None, :] - share1) % Q

    # One leaking sample index per coefficient (two if masked, one per
    # share), distinct, placed anywhere in the trace -- the attack script
    # does not get told where.
    n_leak_samples = 2 * n_coeffs if masked else n_coeffs
    if n_samples < n_leak_samples:
        raise ValueError(f"--n-samples must be >= {n_leak_samples} for n_coeffs={n_coeffs}, masked={masked}")
    leak_positions = rng.choice(n_samples, size=n_leak_samples, replace=False)

    u_hat = rng.integers(0, Q, size=(n_traces, n_coeffs))  # attacker-chosen ciphertexts
    traces = rng.normal(0, noise_sigma, size=(n_traces, n_samples))

    if masked:
        prod1 = pointwise_mul_mod_q(u_hat, share1)
        prod2 = pointwise_mul_mod_q(u_hat, share2)
        hw1 = hamming_weight(prod1)
        hw2 = hamming_weight(prod2)
        for i in range(n_coeffs):
            traces[:, leak_positions[2 * i]] += scale * hw1[:, i]
            traces[:, leak_positions[2 * i + 1]] += scale * hw2[:, i]
    else:
        prod = pointwise_mul_mod_q(u_hat, s_hat[None, :])
        hw = hamming_weight(prod)
        for i in range(n_coeffs):
            traces[:, leak_positions[i]] += scale * hw[:, i]

    return traces, u_hat, s_hat


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--n-traces", type=int, default=3000)
    p.add_argument("--n-coeffs", type=int, default=16, help="number of NTT coefficients to target (<=256*k)")
    p.add_argument("--n-samples", type=int, default=500)
    p.add_argument("--scale", type=float, default=1.0)
    p.add_argument("--noise-sigma", type=float, default=1.0)
    p.add_argument("--masked", action="store_true", help="simulate the toy arithmetic-masking countermeasure")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("-o", "--output", default=None)
    args = p.parse_args()

    traces, u_hat, s_hat = simulate(
        args.n_traces, args.n_coeffs, args.n_samples, args.scale,
        args.noise_sigma, args.masked, args.seed,
    )

    out = args.output or f"traces/simulated{'_masked' if args.masked else ''}.npz"
    np.savez(out, traces=traces, ciphertext_coeffs=u_hat, secret_coeffs=s_hat)
    print(f"Wrote {args.n_traces} traces x {args.n_samples} samples "
          f"({args.n_coeffs} targeted coefficients{', masked' if args.masked else ''}) to {out}")


if __name__ == "__main__":
    main()
