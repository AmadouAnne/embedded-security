#!/usr/bin/env python3
"""
launch.py -- Orchestrateur complet ARM Malware Analysis Sandbox
Gere Docker + pipeline d'analyse + dashboard Flask en une commande.

Usage :
  python3 launch.py                        # build + analyse + dashboard
  python3 launch.py --binary mon_binaire   # analyse un binaire specifique
  python3 launch.py --no-server            # analyse sans Flask
  python3 launch.py --server-only          # Flask sans analyser
  python3 launch.py --docker-only          # build + run Docker uniquement
  python3 launch.py --local                # analyse locale sans Docker
  python3 launch.py --rebuild              # force rebuild image Docker
  python3 launch.py --clean                # supprime conteneurs et images
"""

import argparse
import os
import sys
import subprocess
import json

ROOT    = os.path.dirname(os.path.abspath(__file__))
SRC     = os.path.join(ROOT, "src")
ENGINE  = os.path.join(SRC, "engine")
SAMPLES = os.path.join(SRC, "samples")
REPORTS = os.path.join(SRC, "reports")
DEFAULT = os.path.join(SAMPLES, "malware_arm_bin")
IMAGE   = "projet5-sandbox-arm-arm-sandbox"

R   = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C   = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"; RS = "\033[0m"

def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════╗
║        ARM Malware Analysis Sandbox  v1.0.0          ║
║        UBO M1 LSE -- Embedded Security Project 5     ║
╚══════════════════════════════════════════════════════╝{RS}
""")

def step(n, total, label):
    print(f"\n{DIM}[{n}/{total}]{RS} {W}{label}{RS}")
    print(f"  {'─'*50}")

def ok(msg):   print(f"  {G}✓{RS}  {msg}")
def warn(msg): print(f"  {Y}⚠{RS}  {msg}")
def err(msg):  print(f"  {R}✗{RS}  {msg}")
def info(msg): print(f"  {C}→{RS}  {msg}")

def run_cmd(cmd, capture=True):
    return subprocess.run(
        cmd, capture_output=capture,
        text=True, cwd=ROOT
    )

# ── VÉRIFICATIONS ────────────────────────────────────────────────────────────

def check_deps():
    print(f"{C}── Environnement ──{RS}")

    r = run_cmd(["docker", "--version"])
    if r.returncode == 0:
        ok(r.stdout.strip())
    else:
        err("Docker non trouvé")
        sys.exit(1)

    r = run_cmd(["docker", "compose", "version"])
    if r.returncode == 0:
        ok(r.stdout.strip())
    else:
        warn("docker compose v2 absent -- utilisation docker-compose")

    r = run_cmd(["which", "qemu-arm-static"])
    if r.returncode == 0:
        ok("qemu-arm-static disponible sur l'hôte")
    else:
        warn("qemu-arm-static absent -- analyse via Docker uniquement")

    try:
        import flask
        ok(f"Flask {flask.__version__}")
    except ImportError:
        warn("Flask absent -- pip install flask")

    for d in [SAMPLES, REPORTS]:
        os.makedirs(d, exist_ok=True)
    ok("Dossiers samples/ et reports/ prets")

# ── DOCKER BUILD ─────────────────────────────────────────────────────────────

def docker_build(force=False):
    step(1, 5, "Docker -- Build de l'image sandbox")

    if not force:
        r = run_cmd(["docker", "images", "-q", IMAGE])
        if r.returncode == 0 and r.stdout.strip():
            warn("Image deja buildee (utilisez --rebuild pour forcer)")
            ok(f"Image : {IMAGE}")
            return True

    info("Construction de l'image (premiere fois ~2 min)...")
    info("Base : debian:bookworm-slim + qemu-user-static + strace")

    # Essai docker compose
    r = subprocess.run(
        ["docker", "compose", "build"] + (["--no-cache"] if force else []),
        cwd=ROOT
    )
    if r.returncode == 0:
        ok("Image buildee avec succes")
        return True

    # Fallback docker-compose
    r = subprocess.run(
        ["docker-compose", "build"] + (["--no-cache"] if force else []),
        cwd=ROOT
    )
    if r.returncode == 0:
        ok("Image buildee avec succes (legacy)")
        return True

    err("Echec du build -- verifiez le Dockerfile")
    return False

# ── SAMPLE ───────────────────────────────────────────────────────────────────

def prepare_sample(binary_path):
    step(2, 5, f"Preparation du sample -- {os.path.basename(binary_path)}")

    if not os.path.exists(binary_path):
        err(f"Binaire introuvable : {binary_path}")
        err(f"Placez votre binaire ARM dans : {SAMPLES}/")
        return False

    os.chmod(binary_path, 0o755)
    size = os.path.getsize(binary_path)
    ok(f"Binaire : {binary_path}")
    ok(f"Taille  : {size} bytes ({size/1024:.1f} KB)")

    r = run_cmd(["file", binary_path])
    if r.returncode == 0:
        ok(f"Type    : {r.stdout.split(':',1)[-1].strip()}")

    return True

# ── ANALYSE DOCKER ───────────────────────────────────────────────────────────

def docker_analyze(binary_path):
    step(3, 5, "Analyse dans le conteneur Docker isole")
    info("Isolation : network_mode=none -- le malware ne peut pas sortir")

    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "-v", f"{SAMPLES}:/home/sandbox/src/samples:ro",
        "-v", f"{REPORTS}:/home/sandbox/src/reports",
        IMAGE,
        "python3", "src/engine/analyzer.py"
    ]
    info("Lancement du conteneur...")
    r = subprocess.run(cmd, cwd=ROOT)

    if r.returncode == 0:
        ok("Analyse Docker terminee")
        return True
    else:
        warn("Analyse Docker echouee -- fallback analyse locale")
        return run_local_analysis(binary_path)

# ── ANALYSE LOCALE ───────────────────────────────────────────────────────────

def run_local_analysis(binary_path):
    info("Analyse locale sur l'hote...")
    sys.path.insert(0, ENGINE)
    target_name = os.path.basename(binary_path)

    try:
        from analyzer import ARMAnalyzer
        from network import NetworkAnalyzer
        from report_gen import ReportGenerator

        a = ARMAnalyzer(binary_path)
        a.calculate_entropy()
        a.run_dynamic()

        static  = {**a.report["static_analysis"],  "risk_score": a.report["risk_score"]}
        dynamic = {**a.report["dynamic_analysis"],  "risk_score": a.report["risk_score"]}
        ok(f"Entropie : {static['entropy']}  Syscalls : {dynamic['syscalls_count']}")

        n = NetworkAnalyzer(binary_path)
        network = n.run()

        gen = ReportGenerator(output_dir=REPORTS)
        report = gen.generate(static, dynamic, network, target_name)
        ok(f"Risk Score : {report['risk']['score']}/100 -- {report['risk']['level']}")
        return True

    except Exception as e:
        err(f"Analyse locale echouee : {e}")
        return False

# ── RÉSUMÉ RAPPORTS ──────────────────────────────────────────────────────────

def show_summary():
    step(4, 5, "Rapports generes")

    files = [f for f in os.listdir(REPORTS) if f.endswith(".json")] if os.path.exists(REPORTS) else []
    if not files:
        warn("Aucun rapport JSON trouve")
        return

    for filename in sorted(files, reverse=True):
        try:
            with open(os.path.join(REPORTS, filename)) as f:
                d = json.load(f)
            target = d.get("meta", {}).get("target", filename)
            score  = d.get("risk", {}).get("score", "?")
            level  = d.get("risk", {}).get("level", "?")
            mitre  = [t["id"] for t in d.get("mitre", [])]
            ioc    = d.get("ioc", {}).get("files_accessed", [])
            color  = G if level == "LOW" else Y if level == "MEDIUM" else R
            ok(f"{W}{target}{RS}  {color}{score}/100 {level}{RS}")
            if mitre: info(f"MITRE : {', '.join(mitre)}")
            if ioc:   info(f"IOC   : {', '.join(ioc)}")
        except Exception as e:
            warn(f"Erreur {filename} : {e}")

# ── FLASK ─────────────────────────────────────────────────────────────────────

def run_server():
    step(5, 5, "Dashboard Flask")
    info(f"URL : {W}http://127.0.0.1:5000{RS}")
    info("CTRL+C pour arreter\n")

    os.chdir(ROOT)
    sys.path.insert(0, SRC)

    try:
        from app import app
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except ImportError:
        err("Flask absent -- pip install flask")
    except OSError as e:
        err(f"Port 5000 occupe : {e}")
        info("Liberer : kill $(lsof -t -i:5000)")

# ── CLEAN ─────────────────────────────────────────────────────────────────────

def docker_clean():
    print(f"\n{C}── Nettoyage Docker ──{RS}")
    subprocess.run(["docker", "compose", "down", "--rmi", "all"], cwd=ROOT)
    ok("Conteneurs et images supprimes")

# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="ARM Malware Sandbox -- Orchestrateur")
    p.add_argument("--binary",      default=DEFAULT, help="Binaire ARM a analyser")
    p.add_argument("--no-server",   action="store_true", help="Sans Flask")
    p.add_argument("--server-only", action="store_true", help="Flask uniquement")
    p.add_argument("--docker-only", action="store_true", help="Docker sans Flask")
    p.add_argument("--local",       action="store_true", help="Analyse locale sans Docker")
    p.add_argument("--rebuild",     action="store_true", help="Force rebuild image Docker")
    p.add_argument("--clean",       action="store_true", help="Supprime conteneurs et images")
    args = p.parse_args()

    banner()

    if args.clean:
        docker_clean()
        sys.exit(0)

    check_deps()

    if args.server_only:
        run_server()
        sys.exit(0)

    # Build Docker
    if not args.local:
        if not docker_build(force=args.rebuild):
            warn("Build echoue -- passage en mode local")
            args.local = True

    # Sample
    if not prepare_sample(args.binary):
        sys.exit(1)

    # Analyse
    if args.local:
        step(3, 5, "Analyse locale (sans Docker)")
        run_local_analysis(args.binary)
    else:
        docker_analyze(args.binary)

    # Résumé
    show_summary()

    if args.docker_only:
        print(f"\n{G}Pipeline termine.{RS} Dashboard : {C}python3 launch.py --server-only{RS}\n")
        sys.exit(0)

    # Flask
    if not args.no_server:
        run_server()
    else:
        print(f"\n{G}Analyse terminee.{RS} Dashboard : {C}python3 launch.py --server-only{RS}\n")

if __name__ == "__main__":
    main()
