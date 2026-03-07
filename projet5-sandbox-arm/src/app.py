from flask import Flask, render_template
import json
import os

app = Flask(__name__, template_folder='templates')
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

def normalize(data, filename):
    """Convertit ancien et nouveau format en format unifié."""
    # Déjà nouveau format
    if "meta" in data and "risk" in data:
        # S'assure que dynamic_analysis a risk_score
        if "risk_score" not in data.get("dynamic_analysis", {}):
            data["dynamic_analysis"]["risk_score"] = data["risk"]["score"]
        if "risk_score" not in data.get("static_analysis", {}):
            data["static_analysis"]["risk_score"] = 0
        if "verdict" not in data.get("static_analysis", {}):
            data["static_analysis"]["verdict"] = "Non packé"
        return data

    # Ancien format (généré par analyzer.py dans Docker)
    score = data.get("risk_score", 0)
    if   score == 0:              level, color = "LOW",      "#27ae60"
    elif score <= 50:             level, color = "MEDIUM",   "#f39c12"
    elif score <= 80:             level, color = "HIGH",     "#e67e22"
    else:                         level, color = "CRITICAL", "#e74c3c"

    static_raw  = data.get("static_analysis", {})
    dynamic_raw = data.get("dynamic_analysis", {})

    # IOC : extrait /etc/shadow etc depuis les alertes
    import re
    files_accessed = []
    for alert in dynamic_raw.get("alerts", []):
        m = re.search(r'"(/[^"]+)"', alert)
        if m:
            files_accessed.append(m.group(1))

    # MITRE mapping basique
    mitre = []
    if files_accessed:
        mitre.append({"id": "T1083", "name": "File and Directory Discovery",
                      "reason": f"Acces a {', '.join(files_accessed)}"})

    return {
        "meta": {
            "target": data.get("target", filename.replace("report_","").replace(".json","")),
            "timestamp": "2026-03-07T00:00:00",
            "analyzer_version": "1.0.0",
            "sandbox": "ARM QEMU Sandbox -- UBO M1 LSE"
        },
        "risk": {"score": score, "level": level, "color": color},
        "static_analysis": {
            "entropy":    static_raw.get("entropy", 0),
            "is_packed":  static_raw.get("is_packed", False),
            "risk_score": 0,
            "verdict":    "Packed/chiffre" if static_raw.get("is_packed") else "Non packe"
        },
        "dynamic_analysis": {
            "syscalls_count": dynamic_raw.get("syscalls_count", 0),
            "alerts":         dynamic_raw.get("alerts", []),
            "risk_score":     score
        },
        "network_analysis": {
            "syscalls_count":      0,
            "connection_attempts": [],
            "suspicious_ports":    [],
            "dns_lookups":         [],
            "risk_score":          0
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
                    print(f"[!] Erreur {filename}: {e}")
    return render_template('index.html', reports=reports)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
