"""Statistical methods of the paper (see docs/analysis_plan.md).

Principles
- The experimental unit is the RUN (one board reset + one configuration).
  Jobs inside a run are autocorrelated, so they are summarised per run first
  and inference is done across runs (repetitions).
- Every comparison reports an effect size with a confidence interval, not
  only a p-value.
- pWCET estimates (EVT) are reported only together with the i.i.d. tests
  they rely on; if a test fails, the estimate is flagged, not hidden.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy import stats

RNG_SEED = 2027


# ------------------------------------------------------------- bootstrap CIs

def bootstrap_ci(values, stat=np.mean, n_boot: int = 10_000, level: float = 0.95,
                 seed: int = RNG_SEED) -> tuple[float, float, float]:
    """Percentile bootstrap CI of `stat` over run-level values.

    Returns (estimate, low, high). With the 5 repetitions per scenario the
    interval is wide on purpose: it reflects run-to-run variability honestly.
    """
    x = np.asarray(values, dtype=float)
    if len(x) < 2:
        return float(stat(x)) if len(x) else np.nan, np.nan, np.nan
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(x), size=(n_boot, len(x)))
    boots = np.apply_along_axis(stat, 1, x[idx])
    a = (1 - level) / 2
    return float(stat(x)), float(np.quantile(boots, a)), float(np.quantile(boots, 1 - a))


# ------------------------------------------------------- scenario comparison

def cliffs_delta(a, b) -> float:
    """Cliff's delta: P(A > B) - P(A < B), in [-1, 1]. Robust, distribution-free."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    if len(a) == 0 or len(b) == 0:
        return np.nan
    gt = (a[:, None] > b[None, :]).sum()
    lt = (a[:, None] < b[None, :]).sum()
    return float((gt - lt) / (len(a) * len(b)))


def delta_magnitude(d: float) -> str:
    """Romano et al. (2006) thresholds."""
    d = abs(d)
    return "negligible" if d < 0.147 else "small" if d < 0.33 else "medium" if d < 0.474 else "large"


@dataclass
class Comparison:
    metric: str
    baseline_mean: float
    scenario_mean: float
    ratio: float
    ratio_ci: tuple[float, float]
    cliffs_delta: float
    magnitude: str
    p_value: float


def compare_runs(baseline, scenario, metric: str, n_boot: int = 10_000, seed: int = RNG_SEED) -> Comparison:
    """Compare run-level values of one metric between two scenarios.

    ratio = mean(scenario) / mean(baseline) with a bootstrap CI (independent
    resampling of both groups); Mann-Whitney U two-sided p-value. With n = 5
    per group the smallest attainable p is ~0.008, which is why effect sizes
    and CIs, not p-values, carry the conclusions.
    """
    a, b = np.asarray(baseline, float), np.asarray(scenario, float)
    rng = np.random.default_rng(seed)
    ra = a[rng.integers(0, len(a), (n_boot, len(a)))].mean(axis=1)
    rb = b[rng.integers(0, len(b), (n_boot, len(b)))].mean(axis=1)
    d = cliffs_delta(b, a)
    p = stats.mannwhitneyu(b, a, alternative="two-sided").pvalue if len(a) > 1 and len(b) > 1 else np.nan
    if a.mean() > 0:            # a ratio is undefined for a zero baseline (callers then use diff_ci)
        with np.errstate(divide="ignore", invalid="ignore"):   # resamples of all-zero runs
            ratios = rb / ra
        ratio, ci = float(b.mean() / a.mean()), (float(np.nanquantile(ratios, 0.025)), float(np.nanquantile(ratios, 0.975)))
    else:
        ratio, ci = np.nan, (np.nan, np.nan)
    return Comparison(metric, float(a.mean()), float(b.mean()), ratio, ci, d, delta_magnitude(d), float(p))


def diff_ci(baseline, scenario, n_boot: int = 10_000, seed: int = RNG_SEED) -> tuple[float, float, float]:
    """mean(scenario) - mean(baseline) with a bootstrap CI (independent groups).
    Used instead of a ratio when the baseline mean is zero (e.g. miss ratios)."""
    a, b = np.asarray(baseline, float), np.asarray(scenario, float)
    rng = np.random.default_rng(seed)
    d = b[rng.integers(0, len(b), (n_boot, len(b)))].mean(axis=1) - a[rng.integers(0, len(a), (n_boot, len(a)))].mean(axis=1)
    return float(b.mean() - a.mean()), float(np.quantile(d, 0.025)), float(np.quantile(d, 0.975))


def holm(pvalues) -> np.ndarray:
    """Holm-Bonferroni adjusted p-values (family = all comparisons of one RQ)."""
    p = np.asarray(pvalues, float)
    order = np.argsort(p)
    adj = np.empty_like(p)
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(p) - rank) * p[i]))
        adj[i] = running
    return adj


# --------------------------------------------------------------- EVT / pWCET

@dataclass
class IIDReport:
    n: int
    ljung_box_p: float        # H0: no autocorrelation (lags 1..20)
    ks_halves_p: float        # H0: first and second half identically distributed
    runs_test_p: float        # H0: randomness (Wald-Wolfowitz on median)

    def ok(self, alpha: float = 0.05) -> bool:
        return min(self.ljung_box_p, self.ks_halves_p, self.runs_test_p) >= alpha


def iid_tests(x, lags: int = 20) -> IIDReport:
    """Tests required before applying EVT (MBPTA practice, Cucu-Grosjean et al. 2012)."""
    from statsmodels.sandbox.stats.runs import runstest_1samp
    from statsmodels.stats.diagnostic import acorr_ljungbox

    x = np.asarray(x, float)
    lb = acorr_ljungbox(x, lags=[lags], return_df=True)["lb_pvalue"].iloc[0]
    h = len(x) // 2
    ks = stats.ks_2samp(x[:h], x[h:]).pvalue
    _, rp = runstest_1samp(x, cutoff="median", correction=False)
    return IIDReport(len(x), float(lb), float(ks), float(rp))


@dataclass
class PWCET:
    block: int
    n_blocks: int
    shape: float              # GEV shape xi (scipy's c = -xi); xi <= 0 expected for bounded timing
    loc: float
    scale: float
    moet: float               # maximum observed execution time, for reference
    quantiles: dict           # exceedance probability per job -> pWCET estimate
    gof_p: float              # Kolmogorov-Smirnov goodness of fit on block maxima
    iid: IIDReport


def pwcet_gev(x, block: int = 100, probs=(1e-3, 1e-6, 1e-9, 1e-12)) -> PWCET:
    """Block-maxima EVT: fit a GEV to maxima of consecutive blocks of `block`
    jobs and extrapolate the per-job exceedance quantiles.

    The per-job exceedance p maps to a per-block exceedance 1 - (1 - p)^block.
    The result is a *measurement-based probabilistic* bound, conditional on the
    i.i.d. report; it is not a static WCET.
    """
    x = np.asarray(x, float)
    nb = len(x) // block
    if nb < 30:
        raise ValueError(f"need >= 30 blocks for a GEV fit, have {nb}")
    maxima = x[: nb * block].reshape(nb, block).max(axis=1)
    c, loc, scale = stats.genextreme.fit(maxima)
    q = {}
    for p in probs:
        pb = 1 - (1 - p) ** block
        q[p] = float(stats.genextreme.isf(pb, c, loc, scale))
    gof = stats.kstest(maxima, "genextreme", args=(c, loc, scale)).pvalue
    return PWCET(block, nb, float(-c), float(loc), float(scale), float(x.max()), q, float(gof), iid_tests(x))
