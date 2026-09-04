"""Correlation Power Analysis (CPA) against AES-128's first-round SubBytes.

Works identically on simulated traces (simulate_traces.py) and on real
captured traces, as long as the dataset is a .npz with:
    traces      : float array, shape (n_traces, n_samples)
    plaintexts  : uint8 array, shape (n_traces, 16)
    key         : uint8 array, shape (16,)   [optional -- ground truth, for
                  scoring simulated runs only; never used by the attack]

The attack does NOT use the key. It only uses (traces, plaintexts) to test,
for each of the 16 key bytes independently, which of the 256 candidate byte
values makes the Hamming-weight-of-SBox-output hypothesis correlate best
with some sample in the real trace -- the standard CPA distinguisher.
"""
import argparse
import numpy as np

from aes_sbox import sbox_out, hamming_weight


def load_dataset(path: str):
    data = np.load(path)
    traces = data["traces"].astype(np.float64)
    plaintexts = data["plaintexts"]
    key = data["key"] if "key" in data.files else None
    return traces, plaintexts, key


def correlate_byte(traces: np.ndarray, plaintext_byte: np.ndarray) -> np.ndarray:
    """Returns a (256, n_samples) Pearson-correlation matrix: for each of the
    256 key-byte hypotheses, the correlation of HW(SBox(pt^hyp)) against
    every time sample in the trace set."""
    n_traces, n_samples = traces.shape

    hyp = np.empty((256, n_traces), dtype=np.float64)
    for candidate in range(256):
        hyp[candidate] = hamming_weight(sbox_out(plaintext_byte, candidate))

    hyp_c = hyp - hyp.mean(axis=1, keepdims=True)
    traces_c = traces - traces.mean(axis=0, keepdims=True)

    numerator = hyp_c @ traces_c  # (256, n_samples)
    hyp_norm = np.sqrt((hyp_c ** 2).sum(axis=1))  # (256,)
    traces_norm = np.sqrt((traces_c ** 2).sum(axis=0))  # (n_samples,)
    denom = np.outer(hyp_norm, traces_norm)
    denom[denom == 0] = np.nan  # avoid div-by-zero on constant (all-noise-free) columns

    return numerator / denom


def cpa_attack(traces: np.ndarray, plaintexts: np.ndarray, verbose: bool = True):
    """Runs CPA independently for each of the 16 AES-128 key bytes.

    Returns (recovered_key: uint8[16], confidence: float[16], corr_matrices: list[16] of (256, n_samples)).
    """
    n_bytes = plaintexts.shape[1]
    recovered_key = np.zeros(n_bytes, dtype=np.uint8)
    confidence = np.zeros(n_bytes)
    corr_matrices = []

    for i in range(n_bytes):
        corr = correlate_byte(traces, plaintexts[:, i])
        corr_matrices.append(corr)
        abs_corr = np.nan_to_num(np.abs(corr))
        candidate, sample = np.unravel_index(np.argmax(abs_corr), abs_corr.shape)
        recovered_key[i] = candidate
        confidence[i] = abs_corr[candidate, sample]
        if verbose:
            print(f"  byte {i:2d}: recovered=0x{candidate:02x}  peak|r|={confidence[i]:.3f}  at sample {sample}")

    return recovered_key, confidence, corr_matrices


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dataset", help="Path to a .npz dataset (traces + plaintexts [+ key])")
    ap.add_argument("--plot", action="store_true", help="Save per-byte correlation plots under results/")
    args = ap.parse_args()

    traces, plaintexts, true_key = load_dataset(args.dataset)
    print(f"Loaded {args.dataset}: {traces.shape[0]} traces x {traces.shape[1]} samples")

    recovered_key, confidence, corr_matrices = cpa_attack(traces, plaintexts)

    print(f"\nRecovered key: {recovered_key.tobytes().hex()}")
    if true_key is not None:
        matches = int(np.sum(recovered_key == true_key))
        print(f"True key:      {true_key.tobytes().hex()}")
        print(f"Bytes correct: {matches}/16" + ("  -- FULL KEY RECOVERED" if matches == 16 else ""))
    else:
        print("(no ground-truth key in dataset -- this is real captured data; "
              "recovery is judged by peak-correlation confidence, not by comparison.)")

    if args.plot:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import os
        os.makedirs("results", exist_ok=True)
        fig, axes = plt.subplots(4, 4, figsize=(16, 10), sharex=True)
        for i, ax in enumerate(axes.flat):
            corr = corr_matrices[i]
            ax.plot(np.nanmax(np.abs(corr), axis=0), linewidth=0.8)
            ax.set_title(f"byte {i} -> 0x{recovered_key[i]:02x} (|r|={confidence[i]:.2f})", fontsize=8)
        fig.suptitle(f"CPA per-byte max |correlation| across samples -- {args.dataset}")
        fig.tight_layout()
        out_path = f"results/cpa_{os.path.basename(args.dataset).replace('.npz', '')}.png"
        fig.savefig(out_path, dpi=120)
        print(f"\nSaved plot: {out_path}")


if __name__ == "__main__":
    main()
