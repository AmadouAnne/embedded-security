# Pre-specified analysis plan

Written 2026-09-30, **before** any campaign data were collected. The only data
seen so far are bring-up runs (`data/bringup/`), used for instrumentation
debugging and workload calibration, never for results. Any change to this
plan after campaign data exist must be listed in the paper as a deviation,
with its reason.

## 1. Units and data

| Term | Definition |
|---|---|
| Run | One board reset, one `RunConfig`, one seed. The **experimental unit**. |
| Job | One execution of a periodic task. Jobs are *not* independent (Sec. 5). |
| R | Response time = finish − nominal release (cycles, reported in µs). |
| S | Start latency = start − nominal release. |
| C | Execution time excluding preemption, including ISR time. |
| mOET / MOET | Minimum / maximum **observed** execution time (not WCET bounds). |
| RJ, SLJ | Response-time jitter max(R) − min(R); start-latency jitter max(S) − min(S). |
| U | CPU utilisation per 500 ms window = 1 − idle / window. |

Nominal release instants come from the SysTick hardware reload aligned with
DWT CYCCNT, so R and S are exact in cycles. The probe cost (DWT read, trace
push, context-switch hooks) is measured on-target at the start of every run
(`calibration` in the run metadata) and reported.

## 2. Validity and exclusion (fixed in code: `analysis/validate.py`)

A run is **valid** iff every check passes: END frame received; no trace
records dropped; no corrupted DUT→host frame; contiguous job indices and the
exact expected job count per task; release spacing equal to the period in
cycles; causality (S ≤ R) and C ≤ finish − start; the stimulus rate is
200 ± 1 Hz with p99 inter-frame gap < 10 ms; the idle-based and task-sum
utilisations agree (gap in [−0.5, +3] %); no bad link frames in non-flooding
scenarios; a single firmware build across the campaign.

**Amendment A1 (2026-09-30, made after the C0 calibration runs and before
any evaluation run).** On the host→DUT stimulus direction, whole sensor
frames are occasionally lost, at about 1 in 5·10⁴. The symptom is the same
with three different links (ST-LINK VCP, and ESP32-S3 bridge in USB-JTAG and
in TinyUSB mode), with no UART error on the DUT, so it originates upstream of
the bridge. Losing a sensor frame only makes the Sensor job reuse the
previous sample; the timing measurement is unaffected. The check therefore
tolerates at most 10⁻⁴ lost frames per received frame, and at most 10⁻⁵ UART
noise flags (NE) per received byte. For NE the value is recovered by
3-sample majority vote, and no frame corruption was observed. Any UART
framing or overrun error, any DUT→host loss, and any trace-record loss still
invalidates a run. The per-run loss counts are published.

Invalid runs are **re-run, not repaired**. Every invalid run and its failed
checks are listed in the supplementary material (`validation.csv`). Figures
refuse invalid runs unless explicitly overridden, and that override is never
used for the paper.

## 3. Descriptive statistics (RQ1, RQ2)

Per run and task: jobs, mOET, mean C, p99 C, MOET, R_min, R_mean, R_p99.9,
R_max, RJ, SLJ, deadline misses, slow-path fraction. Per scenario, the
run-level values are summarised by their mean with a **95 % percentile
bootstrap CI over runs** (10 000 resamples, seed 2027).

## 4. Comparisons against the baseline (RQ2–RQ4)

The reference is `E1_ref` (5 × 120 s, nominal, monitor off): same duration
and repetitions as the attack scenarios. The single long `E1_baseline` run
serves RQ1 only (distribution shape, rare events). For each
scenario × critical task (Sensor, Control, Nav) × primary metric
{R_max, RJ, miss ratio, mean U}:

- effect ratio mean(scenario) / mean(baseline) with a bootstrap CI
  (independent resampling of both groups);
- **Cliff's δ** with the Romano et al. magnitude labels;
- two-sided Mann–Whitney U p-value, **Holm-adjusted** within each RQ family.

With 5 runs per group the smallest attainable p is ≈ 0.008, so conclusions
rest on effect sizes and CIs. p-values are secondary.

## 5. Probabilistic WCET (EVT)

Bring-up probe (20 s nominal run, 2026-09-30): raw per-job execution times
**fail** the i.i.d. tests for every task (Ljung–Box, KS between halves and
Wald–Wolfowitz runs test, all p < 10⁻³). Per-hyperperiod (500 ms) maxima
pass for Sensor but still fail for Control and Nav, because of slow drifts.
EVT on raw job samples would therefore be invalid.

Protocol **E6**: 200 independent runs of 30 s (reset + distinct seed), nominal
configuration. Take the **per-run maximum** of C for each critical task, test
it for i.i.d. (same three tests), fit a GEV by maximum likelihood, and check
the fit (KS on the maxima). The pWCET is reported at per-run exceedance
probabilities 10⁻³, 10⁻⁶ and 10⁻⁹, **only if** the i.i.d. tests and the fit
pass. Otherwise it is reported as not applicable, with the failing test. The
pWCET is a measurement-based estimate for this platform and configuration,
not a static bound.

## 6. Timing monitor (RQ3)

- **Calibration** (scenario `C0_monitor_calibration`, 5 × 120 s, nominal, with
  the monitor in detect mode): choose `k_sigma`, the sigma floor and the
  warm-up, to minimise detection threshold subject to a false-alarm rate of
  ≤ 10⁻⁴ per job for Sensor, Control and Nav, and no mitigation trigger.
  Replay is done offline on the recorded response times with a bit-exact
  model of `monitor.c` (`analysis/monitor_replay.py`, float32 arithmetic in
  the C order, firmware built with `-ffp-contract=off`). The model is checked
  against `monitor.c` compiled for the host (unit tests) and, for every
  monitored campaign run, against the alarms recorded on the target
  (validation check `monitor_replay_exact`).
- Grid (`analysis/calibrate_monitor.py`): α ∈ {0.02, 0.05, 0.1}, warm-up
  ∈ {100, 200, 500}, k ∈ {2, 3, 4, 5, 6, 8, 10}, σ floor ∈ {0, 0.005, 0.01,
  0.02, 0.05, 0.1}; guard ratio 0.8; frozen baseline; one parameter set for
  all tasks. Among the feasible sets, the one with the lowest worst-case
  threshold min(μ + kσ, 0.8 D)/D is chosen. Generalisation is reported by
  leave-one-run-out (select on four runs, false-alarm rate on the fifth). If
  no set is feasible, the grid is widened and the change is reported.
- The parameters are **frozen** before the evaluation runs. Evaluation uses
  `E1_baseline_monitor` (false-alarm rate) and the `E5_*` scenarios
  (detection), which are disjoint from C0.
- Detection metrics per run: time of the first alarm, time of the first
  deadline miss, lead time (first miss − first alarm), whether detection
  happened before the first miss, false-alarm rate on nominal runs.
  Overhead: distribution of monitor cycles per job (mean, p99, max).

## 7. Mitigation (RQ4)

Deadline-miss ratio and R_max of the critical tasks with and without each
mitigation, under the same attack (Sec. 4 comparisons), plus the cost of the
mitigation: attack-task throughput lost (demotion), sensor frames dropped
(RX throttle), sensor samples rejected (plausibility guard).

## 8. Reporting

All figures are generated by `analysis/figures.py` from raw CSVs, so a single
command rebuilds them. The raw data, firmware build ID and host provenance
are archived with a DOI. Threats to validity: a single MCU family and
compiler configuration, a synthetic workload, modelled attacks, and a
bring-up–derived calibration.
