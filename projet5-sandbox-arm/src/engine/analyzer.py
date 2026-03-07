import subprocess
import os
import json
import math

class ARMAnalyzer:
    def __init__(self, binary_path):
        self.binary = os.path.abspath(binary_path)
        self.report = {
            "target": os.path.basename(binary_path),
            "static_analysis": {"entropy": 0, "is_packed": False},
            "dynamic_analysis": {"alerts": [], "syscalls_count": 0},
            "risk_score": 0
        }

    def calculate_entropy(self):
        if not os.path.exists(self.binary): return
        with open(self.binary, "rb") as f:
            data = f.read()
        entropy = 0
        if len(data) > 0:
            for i in range(256):
                p_i = data.count(i) / len(data)
                if p_i > 0: entropy -= p_i * math.log2(p_i)
        self.report["static_analysis"]["entropy"] = round(entropy, 2)
        if entropy > 7.0: 
            self.report["static_analysis"]["is_packed"] = True
            self.report["risk_score"] += 30

    def run_dynamic(self):
        print(f"[*] Analyse QEMU de {self.binary}...")
        cmd = ["qemu-arm-static", "-strace", self.binary]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            lines = proc.stderr.splitlines()
            self.report["dynamic_analysis"]["syscalls_count"] = len(lines)
            for line in lines:
                if "openat" in line and "/etc/" in line:
                    self.report["risk_score"] += 20
                    self.report["dynamic_analysis"]["alerts"].append(f"Fichier suspect: {line.strip()}")
        except Exception as e:
            print(f"[-] Erreur: {e}")

    def finalize(self):
        output_path = os.path.join("src/reports", f"report_{self.report['target']}.json")
        with open(output_path, "w") as f:
            json.dump(self.report, f, indent=4)
        print(f"[+] Rapport généré : {output_path} | Score: {self.report['risk_score']}")

if __name__ == "__main__":
    target = "/home/sandbox/src/samples/malware_arm_bin"
    scanner = ARMAnalyzer(target)
    scanner.calculate_entropy()
    scanner.run_dynamic()
    scanner.finalize()
