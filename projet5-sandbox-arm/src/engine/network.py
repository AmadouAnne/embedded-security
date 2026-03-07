#!/usr/bin/env python3
"""
network.py -- Analyse des tentatives réseau d'un binaire ARM
Capture les syscalls réseau (socket, connect, bind) via strace
et les parse pour extraire IPs, ports, et protocoles tentés.

Dans le sandbox Docker (network_mode: none), toutes les connexions
échouent -- mais les tentatives sont visibles dans strace.
"""
import subprocess
import re
import os


# Syscalls réseau à surveiller
NETWORK_SYSCALLS = [
    "socket", "connect", "bind", "listen",
    "accept", "sendto", "recvfrom", "getaddrinfo"
]

# Patterns de détection
SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 25: "SMTP",
    443: "HTTPS/C2", 1337: "C2 classique",
    4444: "Metasploit", 6666: "C2", 8080: "HTTP alternatif",
    31337: "Elite/Backdoor"
}


class NetworkAnalyzer:
    def __init__(self, binary_path, timeout=5):
        self.binary = os.path.abspath(binary_path)
        self.timeout = timeout
        self.results = {
            "network_syscalls": [],
            "connection_attempts": [],
            "suspicious_ports": [],
            "dns_lookups": [],
            "risk_score": 0
        }

    def parse_strace_network(self, strace_output):
        """Parse la sortie strace et extrait les événements réseau."""
        for line in strace_output.splitlines():
            line = line.strip()

            # Détecte les syscalls réseau
            for syscall in NETWORK_SYSCALLS:
                if syscall + "(" in line:
                    self.results["network_syscalls"].append({
                        "syscall": syscall,
                        "raw": line
                    })

            # Détecte les tentatives de connexion TCP/UDP
            # Pattern: connect(fd, {sa_family=AF_INET, sin_port=htons(PORT), sin_addr=inet_addr("IP")}, ...)
            conn_match = re.search(
                r'connect\(.*?sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)',
                line
            )
            if conn_match:
                port = int(conn_match.group(1))
                ip = conn_match.group(2)
                entry = {"ip": ip, "port": port, "raw": line}
                self.results["connection_attempts"].append(entry)
                self.results["risk_score"] += 25

                if port in SUSPICIOUS_PORTS:
                    self.results["suspicious_ports"].append({
                        "port": port,
                        "service": SUSPICIOUS_PORTS[port],
                        "ip": ip
                    })
                    self.results["risk_score"] += 25

            # Détecte les lookups DNS (getaddrinfo / gethostbyname)
            dns_match = re.search(r'getaddrinfo\("([^"]+)"', line)
            if dns_match:
                hostname = dns_match.group(1)
                self.results["dns_lookups"].append(hostname)
                self.results["risk_score"] += 15

    def run(self):
        """Lance le binaire via QEMU + strace et analyse le trafic réseau."""
        print(f"[*] Analyse réseau de {os.path.basename(self.binary)}...")

        cmd = ["qemu-arm-static", "-strace", self.binary]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            self.parse_strace_network(proc.stderr)

        except subprocess.TimeoutExpired:
            print("[!] Timeout -- binaire potentiellement en attente réseau (C2?)")
            self.results["risk_score"] += 20
            self.results["network_syscalls"].append({
                "syscall": "TIMEOUT",
                "raw": "Binaire bloque sur une operation reseau"
            })

        except FileNotFoundError:
            print("[-] qemu-arm-static non trouve -- lancer depuis le conteneur Docker")

        except Exception as e:
            print(f"[-] Erreur: {e}")

        # Résumé
        n_attempts = len(self.results["connection_attempts"])
        n_syscalls = len(self.results["network_syscalls"])
        print(f"[+] Syscalls réseau : {n_syscalls}")
        print(f"[+] Tentatives connexion : {n_attempts}")
        print(f"[+] Ports suspects : {len(self.results['suspicious_ports'])}")
        print(f"[+] Risk score réseau : +{self.results['risk_score']}")

        return self.results


if __name__ == "__main__":
    import json
    target = "/home/sandbox/src/samples/malware_arm_bin"
    analyzer = NetworkAnalyzer(target)
    results = analyzer.run()
    print(json.dumps(results, indent=2))
