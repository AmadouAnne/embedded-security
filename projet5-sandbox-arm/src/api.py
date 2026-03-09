#!/usr/bin/env python3
"""
api.py -- REST API pour le ARM Malware Sandbox
Endpoints :
  POST /api/analyze          -- upload + analyse un binaire
  GET  /api/reports          -- liste tous les rapports
  GET  /api/reports/<name>   -- rapport spécifique
  GET  /api/status           -- statut du sandbox
  POST /api/batch            -- analyse plusieurs binaires
"""

import os
import json
import threading
import time
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

api = Blueprint("api", __name__)

_THIS_DIR   = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(_THIS_DIR, "samples")
REPORTS_DIR = os.path.join(_THIS_DIR, "reports")
ALLOWED_EXT = {"", "elf", "bin", "arm", "mips", "out"}

# Jobs en cours (pour status temps réel)
_jobs = {}   # job_id -> {"status", "progress", "result"}

def _allowed(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in ALLOWED_EXT

def _run_analysis(binary_path, job_id):
    """Lance l'analyse dans un thread séparé."""
    import sys
    engine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine")
    sys.path.insert(0, engine_dir)

    _jobs[job_id]["status"]   = "running"
    _jobs[job_id]["progress"] = 10

    try:
        from analyzer import ARMAnalyzer
        from network import NetworkAnalyzer
        from report_gen import ReportGenerator

        target_name = os.path.basename(binary_path)

        # Analyse statique + dynamique
        _jobs[job_id]["progress"] = 20
        a = ARMAnalyzer(binary_path)
        a.calculate_entropy()
        _jobs[job_id]["progress"] = 50
        a.run_dynamic()
        _jobs[job_id]["progress"] = 70

        static  = {**a.report["static_analysis"],  "risk_score": a.report.get("risk_score", 0)}
        dynamic = {**a.report["dynamic_analysis"],  "risk_score": a.report["dynamic_analysis"].get("risk_score", 0)}

        # Réseau
        n = NetworkAnalyzer(binary_path)
        network = n.run()
        _jobs[job_id]["progress"] = 85

        # Rapport unifié
        gen = ReportGenerator(output_dir=REPORTS_DIR)
        report = gen.generate(static, dynamic, network, target_name)
        _jobs[job_id]["progress"] = 100
        _jobs[job_id]["status"]   = "done"
        _jobs[job_id]["result"]   = report

    except Exception as e:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"]  = str(e)


# ── Endpoints ────────────────────────────────────────────────────────────────

@api.route("/api/status")
def status():
    """Statut général du sandbox."""
    import shutil

    qemu_available = {}
    for qemu in ["qemu-arm-static", "qemu-mips-static", "qemu-ppc-static", "qemu-aarch64-static"]:
        qemu_available[qemu] = shutil.which(qemu) is not None

    reports = []
    if os.path.exists(REPORTS_DIR):
        reports = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")]

    samples = []
    if os.path.exists(SAMPLES_DIR):
        samples = [f for f in os.listdir(SAMPLES_DIR)
                   if os.path.isfile(os.path.join(SAMPLES_DIR, f))
                   and not f.endswith(".c")]

    return jsonify({
        "status":          "online",
        "version":         "2.0.0",
        "qemu":            qemu_available,
        "reports_count":   len(reports),
        "samples_count":   len(samples),
        "jobs_active":     sum(1 for j in _jobs.values() if j["status"] == "running"),
        "sandbox":         "ARM/MIPS/PPC QEMU Sandbox — UBO M1 LSE"
    })


@api.route("/api/samples")
def list_samples():
    """Liste les binaires disponibles dans samples/."""
    if not os.path.exists(SAMPLES_DIR):
        return jsonify({"samples": []})

    samples = []
    for fname in os.listdir(SAMPLES_DIR):
        fpath = os.path.join(SAMPLES_DIR, fname)
        if os.path.isfile(fpath) and not fname.endswith(".c"):
            samples.append({
                "name": fname,
                "size": os.path.getsize(fpath),
                "size_kb": round(os.path.getsize(fpath) / 1024, 1),
                "analyzed": os.path.exists(
                    os.path.join(REPORTS_DIR, f"report_{fname}.json")
                )
            })
    return jsonify({"samples": samples})


@api.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Upload + analyse un binaire.
    Accepte : multipart/form-data avec champ 'file'
    Ou      : JSON {"filename": "nom_dans_samples"}
    """
    import uuid

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {"status": "queued", "progress": 0, "result": None}

    # Cas 1 : analyse d'un fichier déjà dans samples/
    if request.is_json:
        data = request.get_json()
        filename = data.get("filename")
        if not filename:
            return jsonify({"error": "filename requis"}), 400

        binary_path = os.path.join(SAMPLES_DIR, secure_filename(filename))
        if not os.path.exists(binary_path):
            return jsonify({"error": f"Fichier {filename} introuvable dans samples/"}), 404

    # Cas 2 : upload d'un nouveau fichier
    elif "file" in request.files:
        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "Fichier vide"}), 400

        filename = secure_filename(f.filename)
        os.makedirs(SAMPLES_DIR, exist_ok=True)
        binary_path = os.path.join(SAMPLES_DIR, filename)
        f.save(binary_path)
        os.chmod(binary_path, 0o755)

    else:
        return jsonify({"error": "Fournissez un fichier (multipart) ou un JSON {filename}"}), 400

    # Lance l'analyse en arrière-plan
    t = threading.Thread(target=_run_analysis, args=(binary_path, job_id), daemon=True)
    t.start()

    return jsonify({
        "job_id":   job_id,
        "filename": os.path.basename(binary_path),
        "status":   "queued",
        "poll_url": f"/api/jobs/{job_id}"
    }), 202


@api.route("/api/jobs/<job_id>")
def job_status(job_id):
    """Statut d'un job d'analyse (polling)."""
    if job_id not in _jobs:
        return jsonify({"error": "Job introuvable"}), 404
    return jsonify({"job_id": job_id, **_jobs[job_id]})


@api.route("/api/batch", methods=["POST"])
def batch_analyze():
    """
    Analyse plusieurs binaires en parallèle.
    Body JSON : {"filenames": ["bin1", "bin2", ...]}  (max 10)
    """
    import uuid

    data = request.get_json()
    if not data or "filenames" not in data:
        return jsonify({"error": "JSON {filenames: [...]} requis"}), 400

    filenames = data["filenames"][:10]  # max 10
    jobs = []

    for filename in filenames:
        binary_path = os.path.join(SAMPLES_DIR, secure_filename(filename))
        if not os.path.exists(binary_path):
            jobs.append({"filename": filename, "error": "introuvable"})
            continue

        job_id = str(uuid.uuid4())[:8]
        _jobs[job_id] = {"status": "queued", "progress": 0, "result": None}

        t = threading.Thread(target=_run_analysis, args=(binary_path, job_id), daemon=True)
        t.start()

        jobs.append({
            "filename": filename,
            "job_id":   job_id,
            "poll_url": f"/api/jobs/{job_id}"
        })
        time.sleep(0.2)  # évite la surcharge

    return jsonify({"batch_size": len(jobs), "jobs": jobs}), 202


@api.route("/api/reports")
def list_reports():
    """Liste tous les rapports disponibles."""
    if not os.path.exists(REPORTS_DIR):
        return jsonify({"reports": []})

    reports = []
    for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(REPORTS_DIR, fname)) as f:
                d = json.load(f)
            reports.append({
                "filename":  fname,
                "target":    d.get("meta", {}).get("target", fname),
                "score":     d.get("risk", {}).get("score", 0),
                "level":     d.get("risk", {}).get("level", "?"),
                "timestamp": d.get("meta", {}).get("timestamp", ""),
                "mitre":     [t["id"] for t in d.get("mitre", [])],
                "ioc_count": len(d.get("ioc", {}).get("files_accessed", []))
            })
        except Exception:
            pass

    return jsonify({"count": len(reports), "reports": reports})


@api.route("/api/reports/<report_name>")
def get_report(report_name):
    """Retourne un rapport JSON complet."""
    safe = secure_filename(report_name)
    if not safe.endswith(".json"):
        safe += ".json"

    path = os.path.join(REPORTS_DIR, safe)
    if not os.path.exists(path):
        # Essai avec préfixe report_
        path2 = os.path.join(REPORTS_DIR, f"report_{safe}")
        if os.path.exists(path2):
            path = path2
        else:
            return jsonify({"error": "Rapport introuvable"}), 404

    with open(path) as f:
        return jsonify(json.load(f))
