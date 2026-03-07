#!/usr/bin/env python3
"""
report_gen.py -- Générateur de rapport JSON unifié
Fusionne les résultats de analyzer.py et network.py
en un rapport final structuré avec scoring global.
"""
import json
import os
import datetime


# Seuils de dangerosité
RISK_LEVELS = {
    (0, 20):  ("LOW",      "#27ae60"),   # vert
    (21, 50): ("MEDIUM",   "#f39c12"),   # orange
    (51, 80): ("HIGH",     "#e67e22"),   # orange foncé
    (81, 999):("CRITICAL", "#e74c3c"),   # rouge
}


def get_risk_level(score):
    for (low, high), (label, color) in RISK_LEVELS.items():
        if low <= score <= high:
            return label, color
    return "CRITICAL", "#e74c3c"


class ReportGenerator:
    def __init__(self, output_dir="src/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, static_results, dynamic_results, network_results, target_name):
        """
        Fusionne les 3 analyses en un rapport JSON unifié.

        Args:
            static_results  : dict de analyzer.py (entropie, packed)
            dynamic_results : dict de analyzer.py (syscalls, alertes)
            network_results : dict de network.py (connexions, ports)
            target_name     : nom du binaire analysé
        """
        # Score total = somme des 3 modules (cap à 100)
        total_score = min(100, (
            static_results.get("risk_score", 0) +
            dynamic_results.get("risk_score", 0) +
            network_results.get("risk_score", 0)
        ))

        risk_label, risk_color = get_risk_level(total_score)

        report = {
            "meta": {
                "target": target_name,
                "timestamp": datetime.datetime.now().isoformat(),
                "analyzer_version": "1.0.0",
                "sandbox": "ARM QEMU Sandbox -- UBO M1 LSE"
            },
            "risk": {
                "score": total_score,
                "level": risk_label,
                "color": risk_color
            },
            "static_analysis": {
                "entropy": static_results.get("entropy", 0),
                "is_packed": static_results.get("is_packed", False),
                "risk_score": static_results.get("risk_score", 0),
                "verdict": "Packed/chiffré -- analyse difficile" if static_results.get("is_packed") else "Non packé"
            },
            "dynamic_analysis": {
                "syscalls_count": dynamic_results.get("syscalls_count", 0),
                "alerts": dynamic_results.get("alerts", []),
                "risk_score": dynamic_results.get("risk_score", 0)
            },
            "network_analysis": {
                "syscalls_count": len(network_results.get("network_syscalls", [])),
                "connection_attempts": network_results.get("connection_attempts", []),
                "suspicious_ports": network_results.get("suspicious_ports", []),
                "dns_lookups": network_results.get("dns_lookups", []),
                "risk_score": network_results.get("risk_score", 0)
            },
            "ioc": self._extract_ioc(dynamic_results, network_results),
            "mitre": self._map_mitre(dynamic_results, network_results)
        }

        # Sauvegarde JSON
        filename = f"report_{target_name}.json"
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print(f"[+] Rapport généré : {output_path}")
        print(f"[+] Risk Score : {total_score}/100 -- {risk_label}")
        return report

    def _extract_ioc(self, dynamic_results, network_results):
        """Extrait les Indicators of Compromise (IOC)."""
        ioc = {
            "files_accessed": [],
            "ips": [],
            "ports": [],
            "hostnames": []
        }

        # Fichiers suspects depuis les alertes
        for alert in dynamic_results.get("alerts", []):
            if "/etc/" in alert or "/proc/" in alert or "/sys/" in alert:
                # Extrait le chemin
                import re
                match = re.search(r'"(/[^"]+)"', alert)
                if match:
                    ioc["files_accessed"].append(match.group(1))

        # IPs et ports depuis les tentatives réseau
        for attempt in network_results.get("connection_attempts", []):
            if attempt["ip"] not in ioc["ips"]:
                ioc["ips"].append(attempt["ip"])
            if attempt["port"] not in ioc["ports"]:
                ioc["ports"].append(attempt["port"])

        # Hostnames depuis DNS
        ioc["hostnames"] = network_results.get("dns_lookups", [])

        return ioc

    def _map_mitre(self, dynamic_results, network_results):
        """Mappe les comportements détectés aux techniques MITRE ATT&CK."""
        techniques = []

        alerts = dynamic_results.get("alerts", [])
        connections = network_results.get("connection_attempts", [])
        dns = network_results.get("dns_lookups", [])

        # T1083 -- File and Directory Discovery
        if any("/etc/" in a for a in alerts):
            techniques.append({
                "id": "T1083",
                "name": "File and Directory Discovery",
                "reason": "Accès à /etc/ (shadow, passwd...)"
            })

        # T1071 -- Application Layer Protocol (C2)
        if connections:
            techniques.append({
                "id": "T1071",
                "name": "Application Layer Protocol",
                "reason": f"{len(connections)} tentative(s) de connexion réseau"
            })

        # T1071.004 -- DNS
        if dns:
            techniques.append({
                "id": "T1071.004",
                "name": "DNS C2",
                "reason": f"Résolution DNS : {', '.join(dns)}"
            })

        # T1059 -- Command and Scripting Interpreter
        syscalls = dynamic_results.get("syscalls_count", 0)
        if syscalls > 50:
            techniques.append({
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "reason": f"{syscalls} syscalls détectés"
            })

        return techniques


if __name__ == "__main__":
    # Test standalone avec le rapport existant
    existing = json.load(open("src/reports/report_malware_arm_bin.json"))

    static = {
        "entropy": existing["static_analysis"]["entropy"],
        "is_packed": existing["static_analysis"]["is_packed"],
        "risk_score": 0
    }
    dynamic = {
        "syscalls_count": existing["dynamic_analysis"]["syscalls_count"],
        "alerts": existing["dynamic_analysis"]["alerts"],
        "risk_score": existing["risk_score"]
    }
    network = {
        "network_syscalls": [],
        "connection_attempts": [],
        "suspicious_ports": [],
        "dns_lookups": [],
        "risk_score": 0
    }

    gen = ReportGenerator()
    gen.generate(static, dynamic, network, "malware_arm_bin")
