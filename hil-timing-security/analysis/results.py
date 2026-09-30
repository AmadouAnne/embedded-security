"""Result tables and the EVT figure of the paper, computed from validated runs
following docs/analysis_plan.md. Called by figures.py; every table is written
both as CSV (data/processed) and as a LaTeX booktabs fragment (paper/tables)
that main.tex includes, so no number is ever copied by hand.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats as sst

import sare
import stats

CRITICAL = ("sensor", "control", "nav")
REF = "E1_ref"
METRICS = {"R_max_us": "ratio", "RJ_us": "ratio", "miss_ratio": "diff"}


def run_metrics(tr: pd.DataFrame) -> pd.DataFrame:
    """One row per scenario x run x task: the run-level values used for inference."""
    g = tr[tr["task"].isin(CRITICAL)].groupby(["scenario", "run", "task"], observed=True)
    rm = g.agg(jobs=("response_us", "size"), R_max_us=("response_us", "max"),
               R_min_us=("response_us", "min"), MOET_us=("exec_us", "max"),
               mean_exec_us=("exec_us", "mean"), misses=("miss", "sum")).reset_index()
    rm["RJ_us"] = rm["R_max_us"] - rm["R_min_us"]
    rm["miss_ratio"] = rm["misses"] / rm["jobs"]
    return rm


def family(scenario: str) -> str:
    return "RQ4" if scenario.startswith("E5") else "RQ2"


def comparisons(rm: pd.DataFrame, ref: str = REF) -> pd.DataFrame:
    """Every scenario vs the reference, per critical task and primary metric;
    Holm adjustment within each RQ family (analysis plan §4)."""
    base = rm[rm["scenario"] == ref]
    if base["run"].nunique() < 2:
        raise ValueError(f"reference {ref} needs >= 2 valid runs")
    rows = []
    for sc in sorted(set(rm["scenario"]) - {ref}):
        if not sc.startswith(("E2", "E3", "E4", "E5")):
            continue
        s = rm[rm["scenario"] == sc]
        if s["run"].nunique() < 2:
            continue
        for task in CRITICAL:
            a = base.loc[base["task"] == task]
            b = s.loc[s["task"] == task]
            for metric, kind in METRICS.items():
                c = stats.compare_runs(a[metric], b[metric], metric)
                est, lo, hi = (c.ratio, *c.ratio_ci) if kind == "ratio" and c.baseline_mean > 0 \
                    else stats.diff_ci(a[metric], b[metric])
                rows.append({"family": family(sc), "scenario": sc, "task": task, "metric": metric,
                             "effect": "ratio" if kind == "ratio" and c.baseline_mean > 0 else "diff",
                             "ref_mean": c.baseline_mean, "scen_mean": c.scenario_mean,
                             "estimate": est, "ci_low": lo, "ci_high": hi, "cliffs_delta": c.cliffs_delta,
                             "magnitude": c.magnitude, "p": c.p_value, "n_ref": len(a), "n_scen": len(b)})
    df = pd.DataFrame(rows)
    if not df.empty:
        df["p_holm"] = np.nan
        for fam, idx in df.groupby("family").groups.items():
            df.loc[idx, "p_holm"] = stats.holm(df.loc[idx, "p"].fillna(1.0))
    return df


# ------------------------------------------------------------------ EVT (E6)

def evt(tr: pd.DataFrame, scenario: str = "E6_evt_nominal",
        probs=(1e-3, 1e-6, 1e-9)) -> tuple[pd.DataFrame, dict]:
    """Per-run maxima of C for each critical task -> i.i.d. tests -> GEV fit.
    A pWCET is reported only when the tests and the fit pass (plan §5)."""
    d = tr[(tr["scenario"] == scenario) & tr["task"].isin(CRITICAL)]
    rows, fits = [], {}
    for task in CRITICAL:
        m = d[d["task"] == task].groupby("run")["exec_us"].max().sort_index().to_numpy()
        if len(m) < 30:
            continue
        r = stats.pwcet_gev(m, block=1, probs=probs)
        ok = r.iid.ok() and r.gof_p >= 0.05
        fits[task] = (m, r)
        rows.append({"task": task, "runs": len(m), "MOET_us": r.moet,
                     "ljung_box_p": r.iid.ljung_box_p, "ks_halves_p": r.iid.ks_halves_p,
                     "runs_test_p": r.iid.runs_test_p, "gof_p": r.gof_p, "xi": r.shape, "valid": ok,
                     **{f"pWCET_{p:.0e}_us": (r.quantiles[p] if ok else np.nan) for p in probs}})
    return pd.DataFrame(rows), fits


def fig_evt(fits: dict, out: Path, style) -> None:
    if not fits:
        return
    fig, axes = plt.subplots(1, len(fits), figsize=(style.TEXT_W, 1.9))
    axes = np.atleast_1d(axes)
    for ax, (task, (m, r)) in zip(axes, fits.items()):
        x = np.sort(m)
        ccdf = 1 - np.arange(1, len(x) + 1) / (len(x) + 1)
        ax.semilogy(x, ccdf, linestyle="none", marker="o", markersize=2.5, color=style.SERIES[0],
                    label="per-run maxima")
        grid = np.linspace(x.min(), max(r.quantiles.values()) * 1.02, 300)
        ax.semilogy(grid, sst.genextreme.sf(grid, -r.shape, r.loc, r.scale), color=style.SERIES[1],
                    linestyle=style.STYLES[1], label="GEV fit")
        ax.axvline(r.moet, color=style.MUTED, linewidth=0.8)
        ax.set_ylim(1e-9, 1)
        ax.set_title(task.capitalize(), fontsize=8)
        ax.set_xlabel("execution time (µs)")
    axes[0].set_ylabel("exceedance probability per run")
    axes[0].legend(frameon=False, loc="lower left")
    style.save(fig, out, "fig_evt")


# ------------------------------------------------------------- LaTeX export

def _fmt(v, nd=2):
    if isinstance(v, (bool, np.bool_)):
        return "yes" if v else "no"
    if isinstance(v, (float, np.floating)):
        if np.isnan(v):
            return "--"
        return f"{v:.2e}" if (abs(v) < 1e-2 and v != 0) else f"{v:.{nd}f}"
    return str(v).replace("_", r"\_")


def to_latex(df: pd.DataFrame, cols: dict, path: Path, caption: str, label: str) -> None:
    """Minimal booktabs table; `cols` maps column -> header."""
    lines = [r"\begin{table}[t]", r"\centering", r"\scriptsize", rf"\caption{{{caption}}}", rf"\label{{{label}}}",
             r"\begin{tabular}{" + "l" * 1 + "r" * (len(cols) - 1) + "}", r"\toprule",
             " & ".join(cols.values()) + r" \\", r"\midrule"]
    for _, row in df.iterrows():
        lines.append(" & ".join(_fmt(row[c]) for c in cols) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))
