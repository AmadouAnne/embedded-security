#!/usr/bin/env python3
"""Generate the paper's tables and vector figures from a campaign directory.

  python3 figures.py ../data/raw/campaign_v1 --out ../paper/figures --tables ../data/processed
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

import results
import sare
import validate

# IEEE column geometry and type (IEEEtran: 3.5 in column, 7.16 in text width).
COL_W, TEXT_W = 3.5, 7.16
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "STIXGeneral", "DejaVu Serif"],
    "mathtext.fontset": "stix", "font.size": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": "#e4e4e0", "grid.linewidth": 0.5,
    "lines.linewidth": 1.2, "lines.markersize": 4,
    "pdf.fonttype": 42, "ps.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})
# Validated categorical order (CVD-safe adjacent pairs); markers/linestyles are
# the secondary encoding for grayscale print.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
MARKERS = ["o", "s", "^", "D", "v"]
STYLES = ["-", "--", "-.", ":", (0, (3, 1, 1, 1))]
INK, MUTED = "#1f1f1e", "#6b6a64"


def save(fig, out: Path, name: str) -> None:
    fig.savefig(out / f"{name}.pdf")
    plt.close(fig)


def fig_response_ecdf(tr, out, scenarios, tasks=("sensor", "control", "nav")):
    """Response-time ECDF (normalised by the deadline) per critical task."""
    fig, axes = plt.subplots(1, len(tasks), figsize=(TEXT_W, 2.2), sharey=True)
    for ax, task in zip(axes, tasks):
        D = sare.PERIOD_MS[task] * 1e3
        for i, sc in enumerate(scenarios):
            r = np.sort(tr.loc[(tr["scenario"] == sc) & (tr["task"] == task), "response_us"].to_numpy()) / D
            if len(r) == 0:
                continue
            ax.step(r, np.arange(1, len(r) + 1) / len(r), where="post", color=SERIES[i % 5],
                    linestyle=STYLES[i % 5], label=sc)
        ax.axvline(1.0, color=INK, linewidth=0.8)
        ax.text(1.0, 0.03, " D", color=INK, fontsize=7)
        ax.set_xscale("log")
        ax.set_title(task.capitalize(), fontsize=8)
        ax.set_xlabel(r"$R / D$")
    axes[0].set_ylabel("ECDF")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=len(labels), frameon=False, bbox_to_anchor=(0.5, -0.02))
    fig.subplots_adjust(bottom=0.33)
    save(fig, out, "fig_response_ecdf")


def fig_e2_load(tm, out, prios=(13, 9, 3), task="control"):
    """E2: MOET-normalised worst response and miss ratio vs attack load."""
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(COL_W, 3.0), sharex=True)
    for i, p in enumerate(prios):
        rows = tm[tm["scenario"].str.match(rf"E2_p{p}_l\d+$") & (tm["task"] == task)].copy()
        if rows.empty:
            continue
        rows["load"] = rows["scenario"].str.extract(r"_l(\d+)$")[0].astype(int) / 10
        rows = rows.sort_values("load")
        kw = dict(color=SERIES[i], marker=MARKERS[i], linestyle=STYLES[i], label=f"attack prio {p}")
        a1.plot(rows["load"], rows["R_max_over_D"], **kw)
        a2.plot(rows["load"], rows["miss_ratio"] * 100, **kw)
    a1.axhline(1.0, color=INK, linewidth=0.8)
    a1.set_ylabel(r"$R_{max}/D$ (" + task + ")")
    a2.set_ylabel("deadline misses (%)")
    a2.set_xlabel("attack CPU demand (% of its period)")
    a1.legend(frameon=False)
    save(fig, out, "fig_e2_load")


def fig_cpu_load(st, out, scenarios):
    fig, ax = plt.subplots(figsize=(COL_W, 1.9))
    data = [st.loc[st["scenario"] == sc, "cpu_load"].to_numpy() * 100 for sc in scenarios]
    ax.boxplot(data, orientation="horizontal", widths=0.5, showfliers=False,
               medianprops=dict(color=SERIES[0], linewidth=1.5),
               boxprops=dict(color=MUTED), whiskerprops=dict(color=MUTED), capprops=dict(color=MUTED))
    ax.set_yticks(range(1, len(scenarios) + 1), scenarios)
    ax.set_xlabel("CPU utilisation per 500 ms window (%)")
    save(fig, out, "fig_cpu_load")


def fig_monitor_cost(tr, out):
    m = tr[tr["task"].isin(["sensor", "control", "nav"]) & (tr["mon_cost"] > 0)]
    if m.empty:
        return
    fig, ax = plt.subplots(figsize=(COL_W, 1.6))
    ax.hist(m["mon_cost"], bins=60, color=SERIES[0], edgecolor="white", linewidth=0.4)
    ax.set_xlabel("timing-monitor cost per job (cycles)")
    ax.set_ylabel("jobs")
    ax.text(0.98, 0.9, f"max {m['mon_cost'].max()} cyc", transform=ax.transAxes, ha="right", fontsize=7, color=INK)
    save(fig, out, "fig_monitor_cost")


def fig_detection_timeline(tr, out, scenario, run=0, task="control", window_s=(0, 20)):
    d = tr[(tr["scenario"] == scenario) & (tr["run"] == run) & (tr["task"] == task)]
    d = d[(d["t_s"] >= window_s[0]) & (d["t_s"] <= window_s[1])]
    if d.empty:
        return
    D = sare.PERIOD_MS[task] * 1e3
    fig, ax = plt.subplots(figsize=(COL_W, 1.8))
    ax.plot(d["t_s"], d["response_us"] / D, color=SERIES[0], linewidth=0.6, label="R/D")
    a = d[d["alarm"]]
    ax.scatter(a["t_s"], a["response_us"] / D, s=10, marker="^", color=SERIES[1], label="alarm", zorder=3)
    mi = d[d["miss"]]
    ax.scatter(mi["t_s"], mi["response_us"] / D, s=10, marker="x", color=INK, label="deadline miss", zorder=3)
    ax.axhline(1.0, color=INK, linewidth=0.8)
    ax.set_xlabel("time since epoch (s)")
    ax.set_ylabel(f"$R/D$ ({task})")
    ax.legend(frameon=False, ncol=3, loc="upper left")
    save(fig, out, f"fig_timeline_{scenario}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign", type=Path)
    ap.add_argument("--out", type=Path, default=Path("../paper/figures"))
    ap.add_argument("--tables", type=Path, default=Path("../data/processed"))
    ap.add_argument("--latex", type=Path, default=Path("../paper/tables"), help="LaTeX table fragments")
    ap.add_argument("--include-invalid", action="store_true", help="do not drop runs failing validate.py (never for the paper)")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    args.tables.mkdir(parents=True, exist_ok=True)

    tr, st, _ = sare.load_campaign(args.campaign)
    val = validate.validate_campaign(args.campaign)
    val.to_csv(args.tables / "validation.csv", index=False)
    runs_ok = val[val["run"] >= 0].groupby(["scenario", "run"])["ok"].all()
    invalid = set(runs_ok[~runs_ok].index)
    if invalid and not args.include_invalid:
        print(f"excluding {len(invalid)} invalid runs (see validation.csv): {sorted(invalid)}")
        keep = lambda df: df[[(s, r) not in invalid for s, r in zip(df["scenario"], df["run"])]]
        tr, st = keep(tr), keep(st)
    if tr.empty:
        raise SystemExit("no valid run left: fix the data (see validation.csv) before plotting")
    tm = sare.task_metrics(tr)
    tm.to_csv(args.tables / "task_metrics.csv", index=False)
    sare.load_metrics(st).to_csv(args.tables / "cpu_load.csv", index=False)
    sare.detection_metrics(tr).to_csv(args.tables / "detection.csv", index=False)

    present = set(tr["scenario"])
    pick = lambda names: [s for s in names if s in present]
    fig_response_ecdf(tr, args.out, pick(["E1_baseline", "E2_p13_l400", "E3_random_85k", "E4_spike_50pct"]))
    fig_e2_load(tm, args.out)
    fig_cpu_load(st, args.out, pick(["E1_baseline", "E2_p13_l400", "E2_p13_l800", "E3_random_85k", "E4_spike_50pct"]))
    fig_monitor_cost(tr, args.out)
    for sc in pick(["E5_E2_p13_l400_detect", "E5_E2_p13_l400_demote"]):
        fig_detection_timeline(tr, args.out, sc)

    # Inference tables (analysis plan §4-5): CSV for the record, LaTeX for the paper.
    style = sys.modules[__name__]
    rm = results.run_metrics(tr)
    rm.to_csv(args.tables / "run_metrics.csv", index=False)
    if results.REF in present:
        cmp_ = results.comparisons(rm)
        cmp_.to_csv(args.tables / "comparisons.csv", index=False)
        if not cmp_.empty:
            t = cmp_[cmp_["metric"] == "R_max_us"].copy()
            t["ci"] = [f"[{lo:.2f}, {hi:.2f}]" for lo, hi in zip(t["ci_low"], t["ci_high"])]
            results.to_latex(t, {"scenario": "Scenario", "task": "Task", "estimate": r"$R_{max}$ ratio",
                                 "ci": "95\,\% CI", "cliffs_delta": r"Cliff's $\delta$", "p_holm": "$p$ (Holm)"},
                             args.latex / "tab_comparisons.tex",
                             "Worst observed response time relative to " + results.REF.replace("_", r"\_") + " (run-level, bootstrap CI)",
                             "tab:comparisons")
    evt_tab, fits = results.evt(tr)
    if not evt_tab.empty:
        evt_tab.to_csv(args.tables / "evt.csv", index=False)
        results.to_latex(evt_tab, {"task": "Task", "runs": "Runs", "MOET_us": r"MOET ($\mu$s)",
                                   "ljung_box_p": "LB $p$", "runs_test_p": "Runs $p$", "gof_p": "KS $p$",
                                   "pWCET_1e-06_us": "pWCET@$10^{-6}$", "pWCET_1e-09_us": "pWCET@$10^{-9}$"},
                         args.latex / "tab_evt.tex", "EVT on per-run maxima of the execution time (E6)", "tab:evt")
        results.fig_evt(fits, args.out, style)
    print(f"tables -> {args.tables}, latex -> {args.latex}, figures -> {args.out}")


if __name__ == "__main__":
    main()
