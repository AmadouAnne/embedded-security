# Security-Aware Real-Time Execution in Safety-Critical Embedded Systems

Hardware-in-the-loop testbed, dataset and paper sources for an experimental
study of how security mechanisms and attacks perturb the timing of an
avionics-inspired FreeRTOS workload on an STM32 (Cortex-M4F).

```
firmware/   FreeRTOS application for NUCLEO-F411RE (100 MHz) (CMake, arm-none-eabi-gcc)
hil/        host-side orchestrator (Linux PC): flight model, attack injection, trace capture
analysis/   metrics (sare.py), IEEE-formatted figures (figures.py), tests
paper/      IEEEtran manuscript (kept private until submission)
data/raw/   per-run traces (*.trace.csv, *.stats.csv, *.meta.json) — not in git
```

## Research questions → experiments

| RQ | Scenarios (`hil/campaign.toml`) | Measured |
|----|----|----|
| RQ1 baseline | `E1_baseline` (2700 s, ~1.03e6 jobs) | mOET / MOET, response time R, jitter, CPU load |
| RQ2 perturbation | `E2_*` CPU hog at 4 loads × 3 priorities, `E3_*` link flooding, `E4_*` data perturbation | same, vs. baseline |
| RQ3 detection & cost | `E1_baseline_monitor`, `E5_*_detect` | false-alarm rate, detection lead time, monitor cycles |
| RQ4 mitigation | `E5_*_demote`, `E5_*_throttle`, `E5_*_guard` | deadline misses avoided |

## Measurement method

* **Release instants** come from the SysTick hardware reload, related to the
  DWT cycle counter (both clocked by the core), so job *k* is released at
  exactly `epoch_cyc + k·T` cycles.
* **Execution time** per job is accumulated in FreeRTOS
  `traceTASK_SWITCHED_IN/OUT` hooks. It excludes preemption by other tasks and
  *includes* ISR time, so link flooding shows up as execution-time inflation.
* Each job produces a 24-byte record: task, flags (miss, alarm, mitigation,
  slow path, data reject), job index, release, start latency, response, exec,
  monitor cost. The Logging task sends the records to the host over DMA.
* The instrumentation costs a few hundred cycles per job, plus the Logging
  task's transfers. That is small but **not zero**: measure it and report it.
* Observed maxima are **MOET**, not WCET bounds.

## Wiring (measurement setup)

The host link carries all stimuli and traces, so it must not lose bytes. The
ST-LINK virtual COM port (USB bridge) was measured to drop data in both
directions at the same instant, about once per 5 minutes (bring-up of
2026-09-30). It is used only for flashing and resetting the DUT. The data link
is a direct 3.3 V UART to an **ESP32-S3 transparent bridge**
(`firmware/tools/esp32s3_bridge`) that connects to the host PC over USB.

| NUCLEO-F411RE | | ESP32-S3 board |
|---|---|---|
| D2 (PA10, USART1 RX) | ← | "TX" (GPIO43) |
| D8 (PA9, USART1 TX)  | → | "RX" (GPIO44) |
| GND                  | — | GND |

Three wires, including a direct GND–GND connection. During set-up, placements
of the ground wire that were not verified to be on the NUCLEO GND pin gave 29
to 1,044 UART noise flags (NE) per run. With the wire on GND, 2-minute test
runs gave 0–1 noise flag per ~868,000 bytes and no corrupted frame. Every run
records the UART noise, framing and overrun counts separately, and
`analysis/validate.py` checks them.

* The STM32 firmware is built with `-DLINK_UART=1`.
* The bridge uses **TinyUSB CDC with `enableReboot(false)`**. In the default
  USB-Serial/JTAG mode, opening the tty reset the S3 into ROM download mode.
  The host asserts DTR, because TinyUSB only transmits to a "connected" host.
  To re-flash the bridge, hold BOOT and press RESET.
* `hil/orchestrator.py` finds the bridge by its stable `/dev/serial/by-id`
  name. Long campaigns run under
  `systemd-inhibit --what=sleep:idle:handle-lid-switch --mode=block`.

The original design used a Raspberry Pi 4 host. The unit available turned out
to be defective: it read neither SD nor USB boot media, and even the EEPROM
recovery never ran.
Three firmware comments still say "Raspberry Pi" (`link.h`, `bsp_stm32f411.c`,
`CMakeLists.txt`). They are left unchanged during the campaign because the
firmware build ID is a hash of these sources, and it must match the flashed binary.

## Replicating

```sh
make deps            # pinned FreeRTOS / CMSIS sources + Python venv
make firmware flash  # needs arm-none-eabi-gcc, cmake, stlink
make test            # codec cross-check (C vs Python) + pipeline test

# on the host PC (link port auto-detected: ESP32-S3 bridge by stable name):
cd hil && python3 orchestrator.py campaign.toml --dry-run
python3 orchestrator.py campaign.toml --out ../data/raw --rerun-invalid
#   the DUT is reset through the ST-LINK before every run
#   --only E1_baseline E2_p13_l400   to run a subset

make figures         # tables -> data/processed, vector PDFs -> paper/figures
make paper
```

Every run is one board reset plus one configuration, with a fixed seed per run
(`campaign.seed`, scenario, repetition), so any run can be reproduced on its own.

## Data and reproduction of the ESL letter

The measurements used by the letter submitted to IEEE Embedded Systems
Letters (61 validated runs of E1, C0, E2 and X1, the X2 overload runs, every
rejected run with its reason, the flashed firmware binary and the checksums)
are archived on Zenodo: [doi:10.5281/zenodo.23079750](https://doi.org/10.5281/zenodo.23079750).
From the unpacked record:

```sh
cd code/analysis
python validate.py ../../raw/campaign_v1                       # 61/61 runs valid
python figures.py ../../raw/campaign_v1 --out ../../results/figures \
       --tables ../../processed --latex ../../results/tables  # tables + figures
python x2_analysis.py ../../raw/overload_x2 ../../processed    # X2 overload table
python esl_numbers.py ../../processed ../../results/tables     # every number quoted in the letter
```

`analysis/rta.py` compares the measured worst responses with fixed-priority
response-time analysis fed with the measured execution times, without and with
the measured kernel release latency. The X2 overload runs (`hil/overload_x2.*`)
read the on-target monitor state over the ST-LINK after each run
(`hil/overload_readout.py`).

## Before the campaign: calibration

The `work_units` in `campaign.toml` set each task's computational cost. Tune
them on the board with a short `E1` run so the nominal utilisation is known
(about 40–50 % leaves room for E2 to cause misses), then freeze them and
record the values in the paper.

`analysis/tests/synthetic.py` fabricates data **only** to test the pipeline.
Never use its output in the paper.
