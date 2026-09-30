import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import sare  # noqa: E402
from synthetic import make_campaign  # noqa: E402


def test_metrics_and_figures(tmp_path):
    camp = tmp_path / "camp"
    make_campaign(camp)
    tr, st, metas = sare.load_campaign(camp)
    tm = sare.task_metrics(tr)
    base = tm[(tm["scenario"] == "E1_baseline") & (tm["task"] == "sensor")].iloc[0]
    assert base["jobs"] == 2000 and base["mOET_us"] <= base["MOET_us"] and base["misses"] == 0
    assert (tm["RJ_us"] >= 0).all()
    det = sare.detection_metrics(tr)
    row = det[det["scenario"] == "E5_E2_p13_l400_detect"].iloc[0]
    assert row["first_alarm_s"] > 2.0 and row["mon_cost_max_cyc"] < 140

    figs = tmp_path / "figs"
    subprocess.run([sys.executable, HERE.parent / "figures.py", camp, "--out", figs,
                    "--tables", tmp_path / "tables", "--latex", tmp_path / "latex"], check=True, cwd=HERE.parent)
    names = {p.name for p in figs.glob("*.pdf")}
    assert {"fig_response_ecdf.pdf", "fig_e2_load.pdf", "fig_cpu_load.pdf", "fig_monitor_cost.pdf",
            "fig_evt.pdf"} <= names

    import pandas as pd
    cmp_ = pd.read_csv(tmp_path / "tables" / "comparisons.csv")
    ctl = cmp_[(cmp_.scenario == "E2_p13_l400") & (cmp_.task == "control") & (cmp_.metric == "R_max_us")].iloc[0]
    assert ctl.estimate > 1.5 and ctl.ci_low > 1 and ctl.cliffs_delta == 1.0      # injected slowdown is detected
    assert set(cmp_.family) == {"RQ2", "RQ4"} or set(cmp_.family) == {"RQ2"}
    evt = pd.read_csv(tmp_path / "tables" / "evt.csv")
    assert set(evt.task) == {"sensor", "control", "nav"} and (evt.runs == 40).all()
    tex = tmp_path / "latex"
    assert (tex / "tab_comparisons.tex").exists() and (tex / "tab_evt.tex").exists()
    evt_tex = (tex / "tab_evt.tex").read_text()
    assert r"\begin{tabular}" in evt_tex and "\t" not in evt_tex and r"$\mu$s" in evt_tex
    # synthetic data must never reach the manuscript folder
    assert not (HERE.parent.parent / "paper" / "tables").exists()


def test_validation_catches_corruption(tmp_path):
    import validate
    camp = tmp_path / "camp"
    make_campaign(camp)
    assert validate.validate_campaign(camp)["ok"].all()

    f = camp / "E1_baseline_r00.trace.csv"
    lines = f.read_text().splitlines()
    f.write_text("\n".join(lines[:100] + lines[101:]) + "\n")      # lose one sensor record
    df = validate.validate_campaign(camp)
    failed = set(df.loc[~df["ok"], "check"])
    assert {"sensor:seq_contiguous", "sensor:job_count", "sensor:release_spacing"} <= failed


def test_monitor_calibration_runs_end_to_end(tmp_path):
    import calibrate_monitor as cm
    from synthetic import make_run
    camp = tmp_path / "camp"
    camp.mkdir()
    for r in range(3):
        make_run(camp, "C0_monitor_calibration", r, seconds=6, seed=100 + r)
    runs = cm.load_c0(camp)
    small = dict(ewma_alpha=(0.05,), warmup_jobs=(100,), k_sigma=(3.0, 6.0, 10.0), sigma_floor=(0.01, 0.1))
    cm.GRID.clear(); cm.GRID.update(small)
    best, table = cm.select(runs, sorted(runs))
    assert best is not None and len(table) == 6
    e = cm.evaluate(runs, best, sorted(runs))
    assert e["fp_rate"] <= cm.FP_MAX and e["triggers"] == 0
    # the most sensitive feasible set is chosen: no feasible set has a lower threshold
    feas = table[table["feasible"]]
    assert e["thr_over_d"] == feas["thr_over_d"].min()


def test_latex_tables_compile(tmp_path):
    """The generated LaTeX fragments must compile inside an IEEEtran document."""
    import shutil
    camp = tmp_path / "camp"
    make_campaign(camp)
    subprocess.run([sys.executable, HERE.parent / "figures.py", camp, "--out", tmp_path / "f",
                    "--tables", tmp_path / "t", "--latex", tmp_path / "latex"], check=True, cwd=HERE.parent,
                   capture_output=True)
    doc = tmp_path / "doc.tex"
    doc.write_text("\\documentclass[conference]{IEEEtran}\\usepackage{booktabs}\\begin{document}\n"
                   + "".join(f"\\input{{{p}}}\n" for p in sorted((tmp_path / "latex").glob("*.tex")))
                   + "\\end{document}\n")
    if shutil.which("pdflatex") is None:
        return
    r = subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", doc.name],
                       cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:]
