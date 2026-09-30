"""Checks that the statistical estimators recover known ground truth."""
import sys
from pathlib import Path

import numpy as np
from scipy import stats as sst

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stats  # noqa: E402


def test_bootstrap_ci_covers_mean():
    rng = np.random.default_rng(0)
    covered = 0
    for _ in range(200):
        x = rng.normal(10, 1, size=20)
        est, lo, hi = stats.bootstrap_ci(x, n_boot=2000, seed=int(rng.integers(1e9)))
        covered += lo <= 10 <= hi
    assert 0.88 <= covered / 200 <= 0.99          # ~95 % nominal coverage


def test_cliffs_delta_extremes():
    assert stats.cliffs_delta([5, 6, 7], [1, 2, 3]) == 1.0
    assert stats.cliffs_delta([1, 2, 3], [1, 2, 3]) == 0.0
    assert stats.delta_magnitude(0.5) == "large"


def test_compare_runs_detects_increase():
    c = stats.compare_runs([100, 101, 99, 100, 102], [150, 149, 152, 151, 148], "R_max")
    assert c.ratio_ci[0] > 1.4 and c.magnitude == "large" and c.p_value < 0.05


def test_holm_monotone():
    adj = stats.holm([0.01, 0.04, 0.03, 0.5])
    assert np.allclose(adj, [0.04, 0.09, 0.09, 0.5])


def test_iid_detects_autocorrelation():
    rng = np.random.default_rng(1)
    iid = rng.normal(size=5000)
    ar = np.zeros(5000)
    for i in range(1, 5000):
        ar[i] = 0.8 * ar[i - 1] + rng.normal()
    assert stats.iid_tests(iid).ok()
    assert not stats.iid_tests(ar).ok()


def test_pwcet_recovers_known_gumbel_tail():
    # Per-job samples from a Gumbel: block maxima are exactly Gumbel as well,
    # so the extrapolated quantile must match the analytic one.
    rng = np.random.default_rng(2)
    x = sst.gumbel_r.rvs(loc=1000, scale=10, size=200_000, random_state=rng)
    r = stats.pwcet_gev(x, block=100, probs=(1e-6,))
    truth = sst.gumbel_r.isf(1e-6, loc=1000, scale=10)
    assert abs(r.quantiles[1e-6] - truth) / truth < 0.01
    assert abs(r.shape) < 0.1 and r.iid.ok() and r.quantiles[1e-6] >= r.moet * 0.99
