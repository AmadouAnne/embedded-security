# P6 — Correlation Power Analysis on AES-128

Recovers an AES-128 key byte-by-byte from power traces using Correlation
Power Analysis (CPA): for each of the 16 key bytes, correlate a
Hamming-weight hypothesis of the first-round SubBytes output against every
sample of every trace, and pick the candidate with the strongest
correlation (Pearson's r).

**Status: validated on simulated traces (Hamming-weight leakage model +
Gaussian noise). Real oscilloscope captures are pending hardware access —
see "Simulated vs. real" below. Nothing here claims a real-hardware result
that hasn't actually been produced.**

## Layout

- `aes_sbox.py` — AES S-box + Hamming-weight helper.
- `simulate_traces.py` — generates simulated traces (`--masked` for a
  first-order boolean-masked variant).
- `cpa_attack.py` — the actual CPA attack; works on any `.npz` dataset with
  `traces`/`plaintexts` (and optionally `key`, for scoring).
- `masking_demo.py` — runs the identical attack on matched masked/unmasked
  datasets and contrasts the outcome.
- `traces/real/` — real captured traces go here once available (empty for
  now, kept in git via `.gitkeep`).
- `results/` — correlation plots (`--plot`), gitignored (regenerate them).

## Results (simulated, 3000 traces, noise σ=1.0)

```
$ python3 simulate_traces.py --n-traces 3000
$ python3 cpa_attack.py traces/simulated.npz --plot
...
Recovered key: 2b7e151628aed2a6abf7158809cf4f3c
True key:      2b7e151628aed2a6abf7158809cf4f3c
Bytes correct: 16/16  -- FULL KEY RECOVERED
```

```
$ python3 masking_demo.py
=== UNMASKED implementation (3000 traces) ===
Bytes correct: 16/16   mean peak |r| = 0.818

=== MASKED implementation (3000 traces) ===
Bytes correct: 0/16   mean peak |r| = 0.079
```

The masked run's correlation (~0.08) sits at the noise floor for this
number of traces (256 candidates × 200 samples of pure chance), versus
~0.82 for the true key byte when unmasked — the countermeasure isn't just
"harder to break", the naive first-order distinguisher carries no signal
at all once a random per-trace mask decorrelates the Hamming weight from
any single observed share.

## Simulated vs. real

`simulate_traces.py`'s leakage model is intentionally simple and explicit:
`scale * HW(SBox(plaintext ^ key) [^ mask]) + Gaussian noise`, injected at
one known sample per key byte, everything else pure noise. This validates
that `cpa_attack.py`'s Pearson-correlation distinguisher and
`masking_demo.py`'s contrast are implemented correctly — it does **not**
validate against real side-channel effects (EM coupling, non-Gaussian
noise, misaligned traces needing resynchronization, actual leakage-model
mismatch on real silicon). `cpa_attack.load_dataset()` accepts any `.npz`
with the same `traces`/`plaintexts` shape regardless of origin, so once
real captures land in `traces/real/`, the same `cpa_attack.py` /
`masking_demo.py` run against them unchanged — no code here is simulation-
specific outside of `simulate_traces.py` itself.

## Usage

```sh
pip install -r requirements.txt
python3 simulate_traces.py --n-traces 3000
python3 simulate_traces.py --n-traces 3000 --masked -o traces/simulated_masked.npz
python3 cpa_attack.py traces/simulated.npz --plot
python3 masking_demo.py
```
