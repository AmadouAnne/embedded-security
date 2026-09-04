"""Simulated power-trace generator for the P2/CPA demo.

IMPORTANT: these are *simulated* traces (Hamming-weight leakage model +
Gaussian noise), not real oscilloscope captures. Real hardware traces go
under traces/real/ once captured (see README.md) and are loaded through the
same cpa_attack.load_dataset() interface -- nothing else in this project
changes when real traces become available.

Leakage model, per trace t and key byte i:
    sample[t, leak_index[i]] = scale * HW(SBox(plaintext[t,i] XOR key[i]) [XOR mask[t]]) + noise
All other samples are pure Gaussian noise, mimicking the fact that a real
trace captures the whole execution and only a handful of samples actually
correspond to the operation under attack.

With --masked, an independent random per-trace mask is XORed into the
S-box output before taking the Hamming weight (first-order boolean
masking): HW(v) becomes uncorrelated with HW(v XOR key-dependent-value)
when averaged over random masks, which is exactly what defeats naive
first-order CPA -- see masking_demo.py.
"""
import argparse
import numpy as np

from aes_sbox import sbox_out, hamming_weight

KEY_BYTES = 16


def generate(n_traces: int, n_samples: int, key: np.ndarray, noise_std: float,
             masked: bool, scale: float, seed: int):
    rng = np.random.default_rng(seed)

    plaintexts = rng.integers(0, 256, size=(n_traces, KEY_BYTES), dtype=np.uint8)
    traces = rng.normal(0.0, noise_std, size=(n_traces, n_samples)).astype(np.float32)

    # Spread the 16 leaking samples across the trace, in order, like a real
    # SubBytes loop executing byte-by-byte over time.
    leak_indices = np.linspace(10, n_samples - 10, KEY_BYTES, dtype=int)

    masks = None
    if masked:
        masks = rng.integers(0, 256, size=n_traces, dtype=np.uint8)

    for i in range(KEY_BYTES):
        sbox_output = sbox_out(plaintexts[:, i], int(key[i]))
        if masked:
            leaking_value = np.bitwise_xor(sbox_output, masks)
        else:
            leaking_value = sbox_output
        hw = hamming_weight(leaking_value).astype(np.float32)
        traces[:, leak_indices[i]] += scale * hw

    return traces, plaintexts, leak_indices, masks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-traces", type=int, default=3000)
    ap.add_argument("--n-samples", type=int, default=200)
    ap.add_argument("--noise-std", type=float, default=1.0, help="Stddev of Gaussian measurement noise")
    ap.add_argument("--scale", type=float, default=1.0, help="Leakage amplitude per Hamming-weight unit")
    ap.add_argument("--masked", action="store_true", help="Simulate a first-order masked implementation")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--key", type=str, default="2b7e151628aed2a6abf7158809cf4f3c",
                     help="32 hex chars = 16-byte AES key used to generate leakage (known, since these are simulated traces)")
    ap.add_argument("-o", "--output", type=str, default=None,
                     help="Output .npz path (default: traces/simulated[_masked].npz)")
    args = ap.parse_args()

    key = np.frombuffer(bytes.fromhex(args.key), dtype=np.uint8)
    assert len(key) == KEY_BYTES, "--key must be exactly 16 bytes (32 hex chars)"

    traces, plaintexts, leak_indices, masks = generate(
        args.n_traces, args.n_samples, key, args.noise_std, args.masked, args.scale, args.seed)

    out = args.output or f"traces/simulated{'_masked' if args.masked else ''}.npz"
    np.savez(out, traces=traces, plaintexts=plaintexts, key=key, leak_indices=leak_indices,
              masked=args.masked)
    print(f"Wrote {out}: traces={traces.shape}, plaintexts={plaintexts.shape}, "
          f"key={key.tobytes().hex()}, masked={args.masked}")


if __name__ == "__main__":
    main()
