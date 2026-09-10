# P8 — ML-KEM (Kyber) Side-Channel Analysis on STM32

Power side-channel evaluation of ML-KEM (Kyber), built on [PQM4](https://github.com/mupq/pqm4)
on a Cortex-M4 (Nucleo-F411RE, same board as [P1](../freertos-stm32)). Same methodology as
[P6](../side-channel)'s AES-128 CPA: capture power traces during
encapsulation/decapsulation, build leakage hypotheses against the sensitive
operations (NTT, noise sampling, decapsulation re-encryption check),
correlate against real captures, and — if a leak is confirmed — evaluate a
countermeasure. See [`docs/methodology.md`](docs/methodology.md) for the
full scientific objective, threat model, and methodology.

**Status: ML-KEM runs and is functionally validated on real Nucleo-F411RE
hardware (all three parameter sets, cross-checked against the host
reference implementation). The CPA/masking analysis pipeline is built and
validated against simulated traces (same simulated-first approach P6
used before real hardware access). No real power trace has been
captured yet — no side-channel result about the real firmware exists.
This README will be updated at each real milestone (first real trace
capture, first leakage result on real traces) — nothing here should be
read as a result about the actual hardware until an actual command
output against real traces is shown.**

- `arm-none-eabi-gcc` 16.2.0, OpenOCD 0.12.0, `make`, `cmake` — already
  present, nothing to install.
- [PQM4](https://github.com/mupq/pqm4) forked to
  [`AmadouAnne/pqm4`](https://github.com/AmadouAnne/pqm4), branch
  `nucleo-f411re-sca`, vendored here as a real git submodule (pinned
  commit, `libopencm3`/`mupq`/`pqclean` as its own nested submodules —
  `git submodule update --init --recursive` after cloning this repo).
  The fork adds board support for the Nucleo-F411RE
  (`mk/nucleo-f411re.mk` + a board branch in `common/hal-opencm3.c`,
  closely mirroring PQM4's existing `stm32f4discovery` (STM32F407VG)
  support since both are STM32F4/Cortex-M4F) — not upstreamed, upstream
  pqm4 only supports the F407VG Discovery and CW308T boards on this
  family.
- **Known limitation, worked around:** the F411 die has no hardware RNG
  peripheral (unlike the F407VG PQM4 already supports), so
  `rng_get_random_blocking()` hung forever against a peripheral that
  isn't physically there. Fixed by routing this board to PQM4's existing
  fixed-seed fallback PRNG (`common/randombytes.c`, same one
  `mps2-an386` already uses upstream). **This is not real entropy** —
  same sequence every boot, fine only for `*_test`/`*_speed`/`*_stack`'s
  internal keypair/enc calls as a functional demo. It does not affect
  this project's actual side-channel target: `crypto_kem_dec` is
  deterministic given `sk`/`ct` (no randomness involved), and
  `*_testvectors` was already fully deterministic by design regardless.
  A real hardware-seeded entropy source would still be needed before any
  claim about the security (not just function) of on-device keypair
  generation.
- Two real, on-hardware bugs found and fixed getting here (both fixed in
  the fork, see its commit history): the board's `clock_setup()` first
  hung forever waiting on an HSE oscillator that isn't actually running
  on this board (P1/freertos-stm32 already hit and worked around the
  same issue with HSI — missed that the first time); and OpenOCD's
  `program <file.bin> verify reset exit` with no explicit load address
  intermittently flashed to the wrong address — switched to `.hex`
  output (self-describing addresses), the same fix nucleo-l4r5zi already
  uses upstream for the same reason.

### First real result: functional validation on hardware

```
$ python3 testvectors.py --platform nucleo-f411re -u /dev/ttyACM0 \
    ml-kem-512 ml-kem-768 ml-kem-1024
...
ml-kem-1024 - m4fspeed SUCCESSFUL
ml-kem-1024 - m4fstack SUCCESSFUL
ml-kem-512 - m4fspeed SUCCESSFUL
ml-kem-512 - m4fstack SUCCESSFUL
ml-kem-768 - m4fspeed SUCCESSFUL
ml-kem-768 - m4fstack SUCCESSFUL
ml-kem-1024 - clean SUCCESSFUL
ml-kem-512 - clean SUCCESSFUL
ml-kem-768 - clean SUCCESSFUL
```

All 9 implementations (3 parameter sets × `clean`/`m4fspeed`/`m4fstack`)
flash to the real board and pass PQM4's own cross-check: the board
generates keypair/ciphertext/shared-secret from a deterministic seed and
PQM4's `testvectors.py` verifies them against the same computation run
by the reference implementation on the host. This is functional
correctness, not a side-channel result — no trace has been captured
against any of these runs yet.

With the RNG fallback fix above, the plain (non-KAT) self-test also
passes on real hardware:

```
$ python3 test.py --platform nucleo-f411re -u /dev/ttyACM0 ml-kem-512
...
ml-kem-512 - m4fspeed SUCCESSFUL
ml-kem-512 - m4fstack SUCCESSFUL
ml-kem-512 - clean SUCCESSFUL
```

This one generates its own keypair on-device (via the fixed-seed
fallback PRNG, see the RNG limitation note above) and does a full
Alice/Bob encaps/decaps round trip — still functional validation, not a
side-channel result.

### Analysis pipeline validated on simulated traces (no real hardware involved)

Before any acquisition hardware is available, the actual statistical
pipeline (leakage hypothesis, Pearson-correlation distinguisher,
masking contrast) was built and validated against simulated traces —
same reasoning as [P6](../side-channel): prove the analysis code is
correct against a known, controlled leakage model before pointing it at
real captures. See [`docs/methodology.md`](docs/methodology.md) for
exactly what real ML-KEM operation this simulates (coefficient-wise
NTT-domain pointwise multiplication during decryption) and why.

```
$ python3 analysis/masking_demo.py
=== UNMASKED implementation (3000 traces) ===
Coefficients correct: 16/16   mean peak |r| = 0.853

=== MASKED implementation (3000 traces) ===
Coefficients correct: 0/16   mean peak |r| = 0.092
```

Same qualitative result as P6's AES masking demo: the unmasked model's
16 targeted NTT coefficients are all correctly recovered, and the
masked variant's correlation collapses to the noise floor (256
candidates × 500 samples of pure chance) with 0/16 recovered — a
first-order additive-mod-Q mask (a fresh, independent per-execution
random share, mirroring how a real masked ML-KEM implementation would
re-randomize on every call) defeats this naive first-order distinguisher
completely. Caught and fixed one real bug building this: an early
version drew the mask once for the whole simulated dataset instead of
once per trace, which produced a misleadingly "secure-looking" 0/16 result
that was actually just recovering the (fixed, therefore attackable) mask
share itself instead of the secret — same peak correlation (~0.85) as
the unmasked case. Re-randomizing the mask per trace, as a real
countermeasure must, produces the collapse shown above.

**This validates the CPA code, not the real PQM4 firmware.** The
simulation's leakage model is intentionally simple and explicit — see
[`analysis/simulate_traces.py`](analysis/simulate_traces.py) — and does
not model the actual `m4fspeed` assembly's real intermediate values,
register widths, or instruction scheduling. Once real traces exist,
[`analysis/cpa_attack.py`](analysis/cpa_attack.py) runs unchanged against
them (same `.npz` contract: `traces` + `ciphertext_coeffs`, optionally
`secret_coeffs` for scoring) — nothing in it is simulation-specific.

## Planned layout

- `firmware/pqm4/` — PQM4 fork (submodule, see above), Cortex-M4
  ML-KEM-512/768/1024 targets.
- `firmware/openocd/nucleo-f411re.cfg` — same file as
  [P1's](../freertos-stm32/openocd/stm32f4.cfg), already proven on this
  exact board.
- `acquisition/` — trace capture scripts once the power measurement setup
  is available (oscilloscope/shunt — pending, see below). Not started.
- `analysis/` — `kyber_math.py` (NTT-domain arithmetic + Hamming weight,
  role of [`side-channel/aes_sbox.py`](../side-channel/aes_sbox.py)),
  `simulate_traces.py`, `cpa_attack.py` (works on any `.npz` with
  `traces`/`ciphertext_coeffs`, real or simulated), `masking_demo.py` —
  see the simulated-pipeline results above.
- `traces/real/` — real captures once available (tracked via `.gitkeep`,
  empty for now). `traces/*.npz` (simulated) gitignored, regenerable.
- `results/` — plots, gitignored, regenerable from `analysis/`.
- `docs/methodology.md` — scientific objective, threat model, and
  methodology notes, written up as we go — meant to be reused directly as
  the basis for a paper draft (target: CASCADE, or IEEE Access / MDPI
  Cryptography).

## Hardware

- Target: Nucleo-F411RE (Cortex-M4, same board as P1).
- Power acquisition: not yet available — to be set up later (oscilloscope
  or ChipWhisperer-class capture, shunt resistor on the target's power
  rail, GPIO trigger from firmware). Until then, functional validation and
  initial leakage-model work proceed without real traces, mirroring P6's
  simulated-first approach — real captures will replace/extend that, never
  be presented as equivalent to it.

## Next steps

1. ~~Toolchain check (`arm-none-eabi-gcc`, OpenOCD) and PQM4 setup for
   Cortex-M4.~~ Done.
2. ~~First functional ML-KEM encaps/decaps run on the Nucleo-F411RE,
   known-answer-test validation.~~ Done — see above.
3. ~~Validate the CPA/masking analysis pipeline against simulated
   traces.~~ Done — see above. Not yet done: TVLA as a complementary
   detection step (see `docs/methodology.md`).
4. Trace acquisition setup once hardware is available (equipment access
   being explored via UBO's lab — not yet decided between a DIY
   oscilloscope+shunt setup and a ChipWhisperer-class target).
5. Point `analysis/cpa_attack.py` at real traces once captured; leakage
   analysis on the real `crypto_kem_dec` (NTT, noise sampling,
   re-encryption check), countermeasure evaluation if a leak is
   confirmed.
6. `docs/methodology.md` kept current throughout, as the paper draft base.
