# Methodology — ML-KEM Side-Channel Analysis on STM32

Working document, updated as the project progresses. Written to be reused
directly as the basis for a paper draft (target: CASCADE, or IEEE Access /
MDPI Cryptography) — every claim below is either already backed by a
result in [`../README.md`](../README.md) or explicitly marked as planned,
never presented as done.

## 1. Scientific objective

ML-KEM (Kyber), standardized by NIST as FIPS 203, is the leading
post-quantum key-encapsulation mechanism and is already being deployed in
TLS and other protocols ahead of a full PQC migration. Its adoption on
constrained embedded devices (smart cards, IoT, automotive) makes
power/EM side-channel resistance a practical deployment concern, not just
a theoretical one — unlike a server-class implementation, an embedded
implementation is physically reachable by an attacker with a probe.

The public literature already establishes that naive ML-KEM/Kyber
implementations leak through power analysis, primarily in three places:
the Number-Theoretic Transform (NTT) and inverse-NTT used for polynomial
multiplication, the Centered Binomial Distribution (CBD) noise sampler
used during key generation and encapsulation, and — most critically —
the message re-encryption/comparison step inside decapsulation (the
Fujisaki-Okamoto transform's implicit-rejection check), which several
published chosen-ciphertext power-analysis attacks use to recover the
long-term secret key.

**This project's objective**: reproduce this class of analysis on a
concrete, openly documented, reproducible target — [PQM4](https://github.com/mupq/pqm4)'s
optimized Cortex-M4 ML-KEM-512 implementation running on an off-the-shelf
Nucleo-F411RE — using the same statistical methodology already validated
in this repo's [P6 (AES-128 CPA)](../side-channel), and to document
whatever is actually found (leakage confirmed or not) with the same
standard of evidence: real captured traces, real correlation values, no
claim not backed by an actual command's output.

**Novelty/contribution to aim for** (to refine once results exist): most
published PQM4/Kyber SCA work targets either the reference or the
`clean`/`opt` implementations; this project specifically targets the
hand-optimized Cortex-M4 assembly (`m4fspeed`), which is what a real
embedded deployment would actually ship — leakage behavior of hand-tuned
assembly (register allocation, instruction-level parallelism) does not
necessarily match the reference C implementation most published attacks
analyze.

## 2. Threat model

- **Attacker capability**: physical access to the device, able to
  measure power consumption (shunt resistor on the supply rail) or EM
  emanation during execution, with a known/controllable trigger signal
  (GPIO toggled by the firmware around the operation under test — same
  approach as P6). Not a remote/network attacker.
- **Target operation**: `crypto_kem_dec` (decapsulation). Chosen because
  (a) it is where the highest-value secret (the long-term secret key)
  is used on every single call, and (b) unlike `crypto_kem_keypair`/
  `crypto_kem_enc`, it needs **no randomness** — fully determined by the
  secret key and an attacker-supplied ciphertext, which sidesteps this
  project's [known RNG limitation](../README.md) entirely and gives an
  attacker full control over the input distribution across traces
  (important for both CPA, which needs known/varying inputs, and for
  chosen-ciphertext attacks specifically).
- **Attacker knowledge**: knows the public key, can submit arbitrary
  ciphertexts (chosen-ciphertext model, standard for KEM decapsulation
  SCA), does not know the secret key (that is the recovery target) and
  does not know the shared secret output.
- **Out of scope**: fault injection, remote timing side-channels, attacks
  on `crypto_kem_keypair`/`crypto_kem_enc` (would require solving the RNG
  limitation properly first — noted as a possible extension, not part of
  this project's initial scope).

## 3. Methodology (planned — mirrors [P6](../side-channel))

1. **Trace acquisition**: capture power traces during `crypto_kem_dec`
   for a batch of chosen ciphertexts against a fixed secret key, with a
   GPIO trigger bracketing the operation. Exact acquisition hardware and
   sample rate to be documented here once the setup (pending, see
   [README](../README.md)) is available — nothing here should be assumed
   about acquisition parameters until real traces exist.
2. **Leakage hypotheses**: Hamming-weight/Hamming-distance models against
   intermediate values of, in order of expected attack cost/practicality:
   - the CBD-derived / re-encryption comparison step (implicit-rejection
     check) — the highest-value target per the literature;
   - the inverse-NTT butterfly operations consuming secret-key
     coefficients;
   - the message-decoding step recovering the raw polynomial before
     re-encryption.
3. **Statistical distinguisher**: Pearson correlation (CPA), same
   distinguisher and same `numpy`/`scipy` toolchain as
   [`side-channel/cpa_attack.py`](../side-channel/cpa_attack.py), adapted
   to the relevant intermediate values above instead of AES's SubBytes
   output. TVLA (Test Vector Leakage Assessment, fixed-vs-random
   ciphertext classes) as a complementary, weaker-assumption leakage
   *detection* step before attempting full key recovery — useful to
   confirm a leak exists even where a full CPA attack doesn't
   immediately succeed.
4. **Honesty discipline** (carried over from P6): every result reported
   here or in the README will show the exact command and its real
   output. A negative result (no leak found at N traces) is reported as
   such, not omitted. If a leak is confirmed, a countermeasure (masking,
   following the same pattern as P6's boolean masking of AES) will be
   evaluated the same way P6 evaluates its countermeasure: same attack,
   contrasted correlation with and without the countermeasure.

## 4. Current status (see [README](../README.md) for full detail and exact commands)

- Toolchain and PQM4 (forked, board-ported to the Nucleo-F411RE) set up
  and working.
- ML-KEM-512/768/1024 functionally validated on real hardware — both the
  deterministic testvectors cross-check and the full (RNG-fallback-based)
  Alice/Bob self-test pass for `clean`/`m4fspeed`/`m4fstack`.
- The CPA/masking analysis pipeline (Section 3, coefficient-wise attack
  on simulated NTT-domain pointwise multiplication) is built and
  validated against simulated traces: 16/16 targeted coefficients
  recovered unmasked, 0/16 with a (correctly per-execution-randomized)
  first-order additive mask, correlation collapsing to the noise floor.
  One methodological pitfall caught in the process, worth keeping in mind
  for the eventual real masked-countermeasure evaluation too: a mask that
  isn't freshly randomized on every single execution provides no
  protection at all — CPA recovers a fixed mask share exactly as easily
  as it recovers the unmasked secret, while still producing a "0/16
  correct" result that looks superficially like a working countermeasure
  unless the correlation magnitude itself is also checked, not just
  whether the exact secret value was recovered.
- **No power trace has been captured. No side-channel analysis against
  the real firmware has started. No leakage result, positive or
  negative, exists yet about real hardware.**
- Power acquisition setup: pending, being explored via UBO's lab (DIY
  oscilloscope+shunt vs. ChipWhisperer-class target — not yet decided).

## 5. Known limitations affecting scope/interpretation

- The board's software RNG fallback (fixed seed, non-cryptographic — see
  README) means any *keypair generated on-device* during this project's
  testing is not itself unpredictable. This does not affect the planned
  attack (Section 2: `crypto_kem_dec` needs no randomness, and a fixed
  known test key is in fact what a CPA campaign wants for
  reproducibility across the trace set) — noted here so it is never
  conflated with a claim about the *target implementation's* security
  against an attacker who doesn't know the key, which is the actual
  threat model above.
- No EM/power acquisition hardware in hand yet — everything in Sections
  1–2 above is a plan, not a result.
