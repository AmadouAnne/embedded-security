# P8 — ML-KEM (Kyber) Side-Channel Analysis on STM32

Power side-channel evaluation of ML-KEM (Kyber), built on [PQM4](https://github.com/mupq/pqm4)
on a Cortex-M4 (Nucleo-F411RE, same board as [P1](../freertos-stm32)). Same methodology as
[P6](../side-channel)'s AES-128 CPA: capture power traces during
encapsulation/decapsulation, build leakage hypotheses against the sensitive
operations (NTT, noise sampling, decapsulation re-encryption check),
correlate against real captures, and — if a leak is confirmed — evaluate a
countermeasure.

**Status: directory structure only. Nothing has been built, flashed, or
measured yet. No PQM4 code is vendored, no firmware compiles, no trace has
been captured. This README will be updated at each real milestone (first
functional ML-KEM run on hardware, first trace capture, first leakage
result) — nothing here should be read as a result until an actual command
output is shown, exactly as in P6.**

## Planned layout

- `firmware/pqm4/` — vendored PQM4, Cortex-M4 (`mlkem512`/`kyber512`) target.
- `firmware/Core/` — board glue (UART reporting, GPIO trigger for the
  acquisition setup, HAL init) — same pattern as
  [`freertos-stm32/Core`](../freertos-stm32/Core).
- `firmware/openocd/`, `firmware/STM32F411RETx_FLASH.ld` — reused/adapted
  from [P1](../freertos-stm32) (same Nucleo-F411RE board).
- `acquisition/` — trace capture scripts once the power measurement setup
  is available (oscilloscope/shunt — pending, see below).
- `analysis/` — leakage models and the CPA/TVLA distinguishers, following
  the same structure as [`side-channel/cpa_attack.py`](../side-channel/cpa_attack.py).
- `traces/real/` — real captures once available (tracked via `.gitkeep`,
  empty for now).
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

1. Toolchain check (`arm-none-eabi-gcc`, OpenOCD) and PQM4 setup for
   Cortex-M4.
2. First functional ML-KEM encaps/decaps run on the Nucleo-F411RE, with
   known-answer-test validation before any side-channel work starts.
3. Trace acquisition setup once hardware is available at home.
4. Leakage analysis (NTT, noise sampling, decapsulation), countermeasure
   evaluation if a leak is confirmed.
5. `docs/methodology.md` kept current throughout, as the paper draft base.
