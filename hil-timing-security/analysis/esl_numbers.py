#!/usr/bin/env python3
"""Write every number quoted in the ESL letter as LaTeX macros, computed from the
processed campaign tables, so no figure in the text is typed by hand.

  python3 esl_numbers.py ../data/processed ../paper/tables
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

import rta
from sare import PERIOD_MS

TASKS = ["sensor", "control", "nav", "health", "security", "logging"]
# Scenarios used by the letter (and released with it); E3-E6 belong to the journal article.
LETTER = r"^(E1_|C0_|E2_|X1_)"


def _fmt(v, nd):
    return f"{v:,.{nd}f}".replace(",", "{,}")


def numbers(proc: Path) -> dict[str, str]:
    tm = pd.read_csv(proc / "task_metrics.csv")
    rm = pd.read_csv(proc / "run_metrics.csv")
    cpu = pd.read_csv(proc / "cpu_load.csv").set_index("scenario")
    det = pd.read_csv(proc / "detection.csv")
    val = pd.read_csv(proc / "validation.csv")
    n = {}

    # validation (runs used by the letter only)
    val = val[val.scenario.str.match(LETTER) | (val.run < 0)]
    runs = val[val.run >= 0].groupby(["scenario", "run"])["ok"].all()
    n["NRuns"] = str(len(runs))
    n["NRunsValid"] = str(int(runs.sum()))
    n["NChecks"] = _fmt(len(val), 0)
    n["NCheckTypes"] = str(val[val.run >= 0].check.str.replace(r"^\w+:", "", regex=True).nunique())

    # RQ1: E1 baseline
    e1 = tm[tm.scenario == "E1_baseline"].set_index("task")
    n["EoneJobs"] = _fmt(e1.loc[TASKS, "jobs"].sum(), 0)
    n["EoneCpu"] = _fmt(100 * cpu.loc["E1_baseline", "cpu_mean"], 1)
    n["EoneCpuStd"] = _fmt(100 * cpu.loc["E1_baseline", "cpu_std"], 3)
    n["EoneMisses"] = str(int(e1.loc[TASKS, "misses"].sum()))
    n["EoneMaxRD"] = _fmt(e1.loc[TASKS, "R_max_over_D"].max(), 2)
    n["MonCost"] = _fmt(det[det.scenario == "E1_baseline_monitor"].mon_cost_mean_cyc.mean(), 0)

    # RQ2: E2 + X1, Control R_max ratio vs E1_ref (mean of per-run maxima)
    ref = rm[rm.scenario == "E1_ref"].groupby("task").R_max_us.mean()
    for sc, key in [("E2_p13_l100", "Ten"), ("E2_p13_l200", "Twenty"), ("E2_p13_l400", "Forty"),
                    ("X1_E2_p13_l450", "FortyFive"), ("X1_E2_p13_l500", "Fifty")]:
        s = rm[rm.scenario == sc].groupby("task").R_max_us.mean()
        n[f"CtlRatio{key}"] = _fmt(s["control"] / ref["control"], 2)
    p9 = rm[rm.scenario == "E2_p9_l400"].groupby("task").R_max_us.mean()
    n["PnineCtlRatio"] = _fmt(p9["control"] / ref["control"], 3)
    n["PnineNavRatio"] = _fmt(p9["nav"] / ref["nav"], 3)
    sec = tm.set_index(["scenario", "task"]).R_max_us
    n["SecRefMs"] = _fmt(sec["E1_ref", "security"] / 1e3, 1)
    n["SecPnineFortyMs"] = _fmt(sec["E2_p9_l400", "security"] / 1e3, 1)
    att3 = tm[(tm.scenario == "E2_p3_l800") & (tm.task == "attack")].iloc[0]
    n["PthreeAttJobs"] = _fmt(att3.jobs, 0)
    n["PthreeAttMisses"] = _fmt(att3.misses, 0)
    x50 = tm[tm.scenario == "X1_E2_p13_l500"].set_index("task")
    n["FiftyTotalLoad"] = _fmt(100 * cpu.loc["E1_ref", "cpu_mean"] + 50, 0)
    n["FiftyMisses"] = str(int(x50.loc[TASKS, "misses"].sum()))
    n["FiftyNavRD"] = _fmt(x50.loc["nav", "R_max_over_D"], 2)
    n["FiftySecRD"] = _fmt(x50.loc["security", "R_max_over_D"], 2)

    # RTA vs measurement
    scs = ["E1_ref", "E2_p13_l100", "E2_p13_l200", "E2_p13_l400", "X1_E2_p13_l450", "X1_E2_p13_l500",
           "E2_p9_l100", "E2_p9_l200", "E2_p9_l400", "E2_p3_l800"]
    c = rta.compare(tm, scs)
    nl = c[~c.self_suspending]
    n["RtaScen"] = str(len(scs))
    n["RtaPairs"] = str(len(nl))
    n["RtaNaiveFail"] = str(int((~nl.bound_holds).sum()))
    sens = nl[nl.task == "sensor"]
    n["RtaSensorExcessUs"] = _fmt((sens.R_meas_us - sens.R_rta_us).max(), 1)
    n["JminUs"] = _fmt(tm[tm.task == "sensor"].S_min_us.min(), 1)
    n["JmaxUs"] = _fmt(c.J_kernel_us.max(), 1)
    n["RtaJHold"] = str(int(nl.bound_j_holds.sum()))
    tight = (nl.R_meas_us / nl.R_rta_j_us)
    n["RtaTightMedian"] = _fmt(100 * tight.median(), 1)
    n["RtaTightMin"] = _fmt(100 * tight.min(), 0)
    lg = c[c.self_suspending]
    n["LogRtaExcess"] = _fmt((lg.R_meas_us / lg.R_rta_j_us).max(), 1)

    # X2 overload transition (exploratory; partial traces of the overloaded runs)
    x2f = proc / "x2_overload.csv"
    if x2f.exists():
        x2 = pd.read_csv(x2f)
        pred = json.loads((proc / "rta_predictions_preregistered.json").read_text())["predictions_R_over_D"]
        g = lambda sc, t: x2[(x2.scenario == sc) & (x2.task == t)]
        for load, key in [(600, "Sixty"), (700, "Seventy")]:
            sc = f"X2_p13_l{load}"
            c = g(sc, "control").R_max_over_D
            n[f"XtwoCtl{key}Lo"], n[f"XtwoCtl{key}Hi"] = _fmt(c.min(), 3), _fmt(c.max(), 3)
            n[f"XtwoCtl{key}Pred"] = _fmt(pred[f"p13_l{load}"]["control"], 3)
            nav = g(sc, "nav")
            n[f"XtwoNav{key}Miss"] = _fmt(nav.misses.sum(), 0)
            n[f"XtwoNav{key}Jobs"] = _fmt(nav.jobs.sum(), 0)
            n[f"XtwoNav{key}MaxRD"] = _fmt(nav.R_max_over_D.max(), 0 if nav.R_max_over_D.max() > 10 else 2)
        n["XtwoRuns"] = str(x2.groupby(["scenario", "rep"]).ngroups)
        n["XtwoTraceWindowS"] = _fmt(g("X2_p13_l600", "sensor").jobs.min() * PERIOD_MS["sensor"] / 1e3, 1)
        n["XtwoLogLateS"] = _fmt(g("X2_p13_l600", "logging").R_max_over_D.max() * PERIOD_MS["logging"] / 1e3, 0)
        n["XtwoEightyRecords"] = _fmt(x2[x2.scenario == "X2_p13_l800"].jobs.sum(), 0)
        n["XtwoFiftySecMaxRD"] = _fmt(g("X2_p13_l500_ctrl", "security").R_max_over_D.max(), 2)

    # probe cost (cycles), measured on the target at the start of every valid run
    import re
    cal = pd.DataFrame([json.loads(m.read_text()).get("calibration") or {}
                        for m in (proc.parent / "raw" / "campaign_v1").glob("*.meta.json")
                        if re.match(LETTER, m.name)]).dropna()
    n["ProbeDwt"] = _fmt(cal.dwt_read_min.min(), 0)
    n["ProbePushMin"], n["ProbePushMax"] = _fmt(cal.trace_push_min.min(), 0), _fmt(cal.trace_push_max.max(), 0)
    n["ProbeHookMin"], n["ProbeHookMax"] = _fmt(cal.acct_hooks_min.min(), 0), _fmt(cal.acct_hooks_max.max(), 0)
    return n


def tab_rq1(proc: Path) -> str:
    """Table: E1 baseline per task, with the RTA bound (measured MOET + kernel latency J)."""
    tm = pd.read_csv(proc / "task_metrics.csv")
    c = rta.compare(tm, ["E1_baseline"]).set_index("task")
    e1 = tm[tm.scenario == "E1_baseline"].set_index("task")
    lines = [r"\begin{tabular}{lrrrrr}", r"\toprule",
             r"Task & MOET & $R_{max}$ & $R_{max}/D$ & $R_{RTA}$ & $R_{max}/R_{RTA}$ \\",
             r" & ($\mu$s) & ($\mu$s) & & ($\mu$s) & \\", r"\midrule"]
    for t in TASKS:
        rr = c.loc[t, "R_rta_j_us"]
        note = r"$^\dagger$" if t in rta.SELF_SUSPENDING else ""
        lines.append(f"{t.capitalize()}{note} & {e1.loc[t,'MOET_us']:.0f} & {e1.loc[t,'R_max_us']:.0f} & "
                     f"{e1.loc[t,'R_max_over_D']:.3f} & {rr:.0f} & {e1.loc[t,'R_max_us']/rr:.3f} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def write(n: dict[str, str], out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    f = out / "esl_numbers.tex"
    f.write_text("% generated by analysis/esl_numbers.py from data/processed -- do not edit\n"
                 + "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in n.items()))
    return f


if __name__ == "__main__":
    proc, out = Path(sys.argv[1]), Path(sys.argv[2])
    print(write(numbers(proc), out))
    (out / "tab_rq1.tex").write_text(tab_rq1(proc))
    print(out / "tab_rq1.tex")
