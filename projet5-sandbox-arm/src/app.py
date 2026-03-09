from flask import Flask, render_template, jsonify
import json, os, sys

app = Flask(__name__, template_folder='templates')

SRC_DIR     = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR  = os.path.join(SRC_DIR, "reports")
SAMPLES_DIR = os.path.join(SRC_DIR, "samples")

# Enregistre l'API Blueprint
sys.path.insert(0, SRC_DIR)
from api import api as api_blueprint
app.register_blueprint(api_blueprint)

def normalize(data, filename):
    if "meta" in data and "risk" in data:
        da = data.get("dynamic_analysis", {})
        sa = data.get("static_analysis", {})
        if "risk_score" not in da: da["risk_score"] = data["risk"]["score"]
        if "risk_score" not in sa: sa["risk_score"] = 0
        if "verdict"    not in sa: sa["verdict"] = "Non packe"
        return data

    score = data.get("risk_score", 0)
    if   score == 0:    level, color = "LOW",      "#27ae60"
    elif score <= 50:   level, color = "MEDIUM",   "#f39c12"
    elif score <= 80:   level, color = "HIGH",     "#e67e22"
    else:               level, color = "CRITICAL", "#e74c3c"

    sa  = data.get("static_analysis",  {})
    da  = data.get("dynamic_analysis", {})

    import re
    files_accessed = []
    for alert in da.get("alerts", []):
        m = re.search(r'"(/[^"]+)"', alert)
        if m: files_accessed.append(m.group(1))

    mitre = []
    if files_accessed:
        mitre.append({"id": "T1083", "name": "File and Directory Discovery",
                      "reason": f"Acces a {', '.join(files_accessed)}"})
    if da.get("categories", {}).get("c2_network"):
        mitre.append({"id": "T1071", "name": "Application Layer Protocol",
                      "reason": "Tentatives connexion reseau"})

    return {
        "meta": {
            "target":            data.get("target", filename.replace("report_","").replace(".json","")),
            "timestamp":         "2026-01-01T00:00:00",
            "analyzer_version":  "2.0.0",
            "sandbox":           "ARM/MIPS/PPC QEMU Sandbox — UBO M1 LSE"
        },
        "risk":  {"score": score, "level": level, "color": color},
        "static_analysis": {
            "entropy":    sa.get("entropy", 0),
            "is_packed":  sa.get("is_packed", False),
            "packer":     sa.get("packer"),
            "arch":       sa.get("arch", "ARM"),
            "risk_score": 0,
            "verdict":    sa.get("verdict", "Non packe")
        },
        "dynamic_analysis": {
            "syscalls_count": da.get("syscalls_count", 0),
            "alerts":         da.get("alerts", []),
            "categories":     da.get("categories", {}),
            "risk_score":     score
        },
        "network_analysis": {
            "syscalls_count": 0, "connection_attempts": [],
            "suspicious_ports": [], "dns_lookups": [], "risk_score": 0
        },
        "ioc":   {"files_accessed": files_accessed, "ips": [], "ports": [], "hostnames": []},
        "mitre": mitre
    }

@app.route('/')
def index():
    reports = []
    if os.path.exists(REPORT_DIR):
        for filename in sorted(os.listdir(REPORT_DIR), reverse=True):
            if filename.endswith(".json"):
                try:
                    with open(os.path.join(REPORT_DIR, filename)) as f:
                        reports.append(normalize(json.load(f), filename))
                except Exception as e:
                    print(f"[!] {filename}: {e}")

    # Liste des samples disponibles pour le batch
    samples = []
    if os.path.exists(SAMPLES_DIR):
        samples = [f for f in os.listdir(SAMPLES_DIR)
                   if os.path.isfile(os.path.join(SAMPLES_DIR, f))
                   and not f.endswith(".c")]

    return render_template('index.html', reports=reports, samples=samples)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
