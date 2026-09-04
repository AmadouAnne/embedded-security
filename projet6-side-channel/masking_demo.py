"""Demonstrates that first-order boolean masking defeats the naive CPA in
cpa_attack.py -- generates matched unmasked/masked simulated datasets (same
key, same plaintexts, same noise) and runs the identical attack on both, so
the only difference in outcome is attributable to the masking.
"""
import numpy as np

from simulate_traces import generate, KEY_BYTES
from cpa_attack import cpa_attack

KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"


def run(masked: bool, seed: int):
    key = np.frombuffer(bytes.fromhex(KEY_HEX), dtype=np.uint8)
    traces, plaintexts, _leak_idx, _masks = generate(
        n_traces=3000, n_samples=200, key=key, noise_std=1.0,
        masked=masked, scale=1.0, seed=seed)
    print(f"\n=== {'MASKED' if masked else 'UNMASKED'} implementation ({traces.shape[0]} traces) ===")
    recovered_key, confidence, _ = cpa_attack(traces, plaintexts, verbose=False)
    matches = int(np.sum(recovered_key == key))
    print(f"Recovered: {recovered_key.tobytes().hex()}  (true: {key.tobytes().hex()})")
    print(f"Bytes correct: {matches}/{KEY_BYTES}   mean peak |r| = {confidence.mean():.3f}")
    return matches, confidence.mean()


def main():
    unmasked_matches, unmasked_conf = run(masked=False, seed=1)
    masked_matches, masked_conf = run(masked=True, seed=1)

    print("\n=== Summary ===")
    print(f"Unmasked: {unmasked_matches}/16 bytes recovered, mean peak correlation {unmasked_conf:.3f}")
    print(f"Masked:   {masked_matches}/16 bytes recovered, mean peak correlation {masked_conf:.3f}")

    if unmasked_matches == 16 and masked_matches < 16 and masked_conf < 0.5 * unmasked_conf:
        print("\nResult: naive first-order CPA fully recovers the unmasked key and "
              "fails against the masked implementation, as expected -- the random "
              "per-trace mask decorrelates the Hamming-weight hypothesis from any "
              "single observed share.")
    else:
        print("\nResult did not match the expected masking/no-masking contrast -- "
              "inspect confidence values above before trusting either run.")


if __name__ == "__main__":
    main()
