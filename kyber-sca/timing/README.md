# Timing side-channel analysis (dudect methodology)

Host-side half of the timing-SCA extension to P8 (see
[`../docs/methodology.md`](../docs/methodology.md) Section 5 for the full
write-up). Firmware half lives in the PQM4 fork submodule:
[`../firmware/pqm4/common/dudect.c`](../firmware/pqm4/common/dudect.c) and
[`../firmware/pqm4/common/keypair_control.c`](../firmware/pqm4/common/keypair_control.c),
built via [`../firmware/pqm4/mk/dudect.mk`](../firmware/pqm4/mk/dudect.mk) --
see that file's header comment for why the harness sources live directly in
the fork's own `common/` instead of the (unforked) `mupq` submodule.

This directory only needs the board flashed with the relevant `.hex`
(built from the fork above); no oscilloscope, shunt, or any external
measurement equipment -- everything here reads the Cortex-M4's own
DWT->CYCCNT register, streamed to the host over the board's existing USB-UART.

## Scripts

- `capture.py` -- resets the board (via OpenOCD) while already listening on
  the serial port, and records one `class,cycles` CSV row per trial from
  `dudect.c`'s output.
- `welch_ttest.py` -- Welch's t-test on a captured CSV (dudect/TVLA
  convention: `|t| > 4.5` = leak detected). Explicitly reports a
  zero-variance ("degenerate") result rather than dividing by zero or
  hiding it -- see the Honesty discipline note in `docs/methodology.md`.
- `plot_tstat.py` -- running Welch's t-statistic vs. number of traces
  (the standard dudect plot). Also handles the degenerate case, plotting
  `t=0` at each step with an explicit annotation rather than `NaN`.
- `plot_keypair_control.py` -- histogram of the keypair-generation control
  measurement (see below).

## Reproducing the current result

```
# 1. Build and flash the dudect harness (from firmware/pqm4/):
make PLATFORM=nucleo-f411re bin/crypto_kem_ml-kem-512_m4fspeed_dudect.hex
openocd -f ../openocd/nucleo-f411re.cfg \
  -c "program bin/crypto_kem_ml-kem-512_m4fspeed_dudect.hex verify reset exit"

# 2. Capture (from this directory):
python3 capture.py --out ../traces/timing/run1_100k.csv --n 100000 --timeout-s 900

# 3. Analyze:
python3 welch_ttest.py ../traces/timing/run1_100k.csv
python3 plot_tstat.py ../traces/timing/run1_100k.csv ../results/timing/tstat_run1.png
```

## Current status: crypto_kem_dec shows zero measured cycle-count variance

`ml-kem-512`'s hand-optimized Cortex-M4 assembly implementation
(`m4fspeed`) was tested with a classic dudect fixed-vs-random design against
`crypto_kem_dec`: class 0 always decapsulates a single fixed valid
ciphertext (accept path), class 1 decapsulates a fresh random byte string
each trial (almost certainly invalid, exercising the FO-transform implicit
rejection path). See `docs/methodology.md` Section 2 for why this specific
operation and this specific attacker model.

```
$ python3 welch_ttest.py ../traces/timing/run1_100k.csv
class 0 (fixed):  n=  45057  mean=408562.000  var=0
class 1 (random): n=  45467  mean=408562.000  var=0
Welch's t-test: DEGENERATE (zero pooled variance -- both classes' cycle
counts have zero within-class variance)...
mean0 == mean1 exactly: no distinguishable timing difference was observed
between the two classes at this sample size.
```

N=90,525 trials (45,057 fixed / 45,467 random) captured from real hardware
(capture stopped by the campaign timeout, not by the board) -- **every
single trial in both classes took exactly 408,562 cycles.** Zero variance,
not just a low t-statistic: `mean0 == mean1` bit-for-bit, `var0 == var1 ==
0`. See [`../results/timing/tstat_run1.png`](../results/timing/tstat_run1.png).

### Is this a real result or a broken measurement harness?

Zero variance across tens of thousands of trials is exactly what a
measurement bug (e.g. the cycle counter not actually running) would also
produce, so this is not accepted at face value. **Control experiment:**
the identical DWT-based harness, applied to `crypto_kem_keypair` instead
(which is known to have data-dependent timing -- rejection sampling in
uniform polynomial generation loops a variable number of times depending on
random byte values), shows real, substantial variance:

```
$ python3 plot_keypair_control.py ../traces/timing/keypair_control_5k.csv \
    ../results/timing/keypair_control_hist.png
N=5000 unique=1083 min=377893 max=389791 mean=378942.1
```

See [`../results/timing/keypair_control_hist.png`](../results/timing/keypair_control_hist.png):
a clear bimodal distribution (main cluster ~378,300-379,200 cycles, a
second cluster ~389,000-389,800 cycles roughly one extra
rejection-sampling round later) -- the harness clearly detects real
variance when it is present. This rules out "the DWT harness is broken" as
the explanation for `crypto_kem_dec`'s zero-variance result, on the same
board, same toolchain, same measurement code style, in the same session.

**Interpretation (not yet a finished claim -- see Next steps):**
`crypto_kem_dec` on this implementation appears to execute a fixed,
data-independent sequence of instructions and memory accesses regardless of
whether the ciphertext is valid (accept path) or not (implicit-rejection
path via `cmov_int16.S`, visible in `crypto_kem/ml-kem-512/m4fspeed/`) --
consistent with the implementation being genuinely branch-free/constant-time
at the cycle-count level for this specific differential test, on this
specific board, at this specific optimization level. This is a clean
negative result, reported as such, not a claim that no timing side channel
exists anywhere in the implementation (see Next steps).

## Next steps

- Push N well beyond 100k (dudect campaigns in the literature often run into
  the millions) to rule out a very rare, low-probability code path this
  sample size wouldn't catch.
- Try additional differential classes beyond "valid vs random-invalid":
  e.g. ciphertexts that are invalid in different specific ways (corrupt only
  the last byte, only the first polynomial coefficient) to probe whether
  the implicit-rejection `cmov` path specifically is constant-time, not just
  the aggregate call.
- Repeat against `m4fstack` (the other real implementation already
  validated on this hardware, optimized for RAM instead of speed) and
  against `ml-kem-768`/`ml-kem-1024` -- a result this clean on one
  parameter set/implementation should be checked for generality before
  being written up as a general claim.
- Cross-reference against the known KyberSlash timing CVE class (variable-time
  division in `poly_compress`/`poly_tomsg`): already checked, this vendored
  PQClean-derived `clean` reference implementation uses `cmov`/fixed-point
  multiplication instead of division in the relevant functions (no raw
  `/KYBER_Q` in the ML-KEM-512 `clean` reference used for the KAT
  cross-check outside of comments), consistent with a post-KyberSlash-fix
  codebase -- worth stating explicitly in the eventual paper as a targeted
  check, not just an implicit assumption.
