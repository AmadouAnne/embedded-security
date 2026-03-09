#!/usr/bin/env python3
"""
analyzer.py v2 -- Analyse statique + dynamique multi-architecture
Supporte : ARM, MIPS, MIPS64, PowerPC, x86 (ELF)
Détecte  : UPX, packing custom, sections suspectes, syscalls malveillants
"""

import subprocess
import os
import re
import math
import struct


# ── Architecture detection ───────────────────────────────────────────────────

ELF_ARCHS = {
    0x28: ("ARM",     "qemu-arm-static"),
    0x08: ("MIPS",    "qemu-mips-static"),
    0x15: ("PPC",     "qemu-ppc-static"),
    0x3E: ("x86_64",  "qemu-x86_64-static"),
    0x03: ("x86",     None),               # natif sur hôte x86
    0xB7: ("ARM64",   "qemu-aarch64-static"),
    0xF3: ("RISCV",   "qemu-riscv64-static"),
}

# Byte order par architecture
ELF_LE = {0x28, 0x08, 0x3E, 0x03, 0xB7, 0xF3}
ELF_BE = {0x15}  # PowerPC big-endian

# ── Syscalls dangereux par catégorie ────────────────────────────────────────

DANGEROUS_SYSCALLS = {
    "credential_theft": [
        "openat.*\"/etc/shadow\"",
        "openat.*\"/etc/passwd\"",
        "openat.*\"/etc/sudoers\"",
        r"openat.*\"\.ssh/",
    ],
    "persistence": [
        r"openat.*\"/etc/cron",
        r"openat.*\"/etc/init",
        r"openat.*\"/etc/rc\.",
        "openat.*\"/tmp/.*\\.sh\"",
        "symlink(",
    ],
    "c2_network": [
        "connect(",
        "socket(.*SOCK_STREAM",
        "sendto(",
        "bind(",
    ],
    "process_injection": [
        "ptrace(",
        "process_vm_writev(",
        "memfd_create(",
    ],
    "recon": [
        r"openat.*\"/proc/net/",
        r"openat.*\"/proc/\d+/",
        "uname(",
        "getuid(",
    ],
    "destruction": [
        "unlink(",
        "rename(.*\"/bin/",
        "chmod.*0777",
        "truncate(",
    ],
}

RISK_WEIGHTS = {
    "credential_theft":  30,
    "persistence":       25,
    "c2_network":        25,
    "process_injection": 35,
    "recon":             10,
    "destruction":       40,
}

# ── Packer signatures (magic bytes) ─────────────────────────────────────────

PACKER_SIGNATURES = {
    "UPX": [b"UPX!", b"UPX0", b"UPX1"],
    "MPRESS": [b"MPRESS1", b"MPRESS2"],
    "ASPack": [b"\x60\xe8\x03\x00\x00\x00\xe9\xeb"],
    "FSG": [b"\xeb\x02\xcd\x20"],
    "MEW": [b"\xe9\x00\x00\x00\x00\x60"],
}


class ARMAnalyzer:
    """
    Analyseur multi-architecture pour binaires ELF.
    Compatible ARM, MIPS, PowerPC, x86.
    """

    def __init__(self, binary_path, timeout=10):
        self.binary  = os.path.abspath(binary_path)
        self.timeout = timeout
        self.arch    = "UNKNOWN"
        self.qemu    = None

        self.report = {
            "target":  os.path.basename(binary_path),
            "static_analysis": {
                "entropy":    0,
                "is_packed":  False,
                "packer":     None,
                "arch":       "UNKNOWN",
                "endian":     "unknown",
                "sections":   [],
                "risk_score": 0,
                "verdict":    "Non packe"
            },
            "dynamic_analysis": {
                "alerts":         [],
                "syscalls_count": 0,
                "categories":     {},
                "risk_score":     0
            },
            "risk_score": 0
        }

    # ── ELF parsing ──────────────────────────────────────────────────────────

    def detect_arch(self):
        """Lit l'en-tête ELF et détecte l'architecture."""
        try:
            with open(self.binary, "rb") as f:
                magic = f.read(4)
                if magic != b'\x7fELF':
                    self.report["static_analysis"]["verdict"] = "Non-ELF binary"
                    return

                f.seek(4);  ei_class = ord(f.read(1))   # 1=32bit 2=64bit
                f.seek(5);  ei_data  = ord(f.read(1))   # 1=LE 2=BE
                f.seek(18); e_machine_bytes = f.read(2)

                endian = "<" if ei_data == 1 else ">"
                e_machine = struct.unpack(endian + "H", e_machine_bytes)[0]

                arch_info = ELF_ARCHS.get(e_machine)
                if arch_info:
                    self.arch, self.qemu = arch_info
                else:
                    self.arch = f"0x{e_machine:02x}"
                    self.qemu = None

                self.report["static_analysis"]["arch"]   = self.arch
                self.report["static_analysis"]["endian"] = "little" if ei_data == 1 else "big"

        except Exception as e:
            print(f"[-] ELF parse error: {e}")

    def parse_sections(self):
        """Extrait les sections ELF avec readelf si disponible."""
        try:
            r = subprocess.run(
                ["readelf", "-S", "--wide", self.binary],
                capture_output=True, text=True, timeout=5
            )
            sections = []
            for line in r.stdout.splitlines():
                # Ligne type: [ 1] .text PROGBITS ...
                m = re.search(r'\[\s*\d+\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
                if m:
                    name, stype, addr, off, size = m.groups()
                    try:
                        sz = int(size, 16)
                        if sz > 0:
                            sections.append({
                                "name": name, "type": stype,
                                "size": sz
                            })
                    except ValueError:
                        pass
            self.report["static_analysis"]["sections"] = sections[:10]
        except Exception:
            pass  # readelf optionnel

    # ── Packing detection ────────────────────────────────────────────────────

    def detect_packing(self):
        """
        Détecte le packing par :
        1. Signatures magic bytes (UPX, MPRESS...)
        2. Entropie élevée (> 7.0)
        3. Sections nommées UPX0/UPX1
        """
        if not os.path.exists(self.binary):
            return

        with open(self.binary, "rb") as f:
            data = f.read()

        # 1. Entropie
        entropy = self._calc_entropy(data)
        self.report["static_analysis"]["entropy"] = round(entropy, 2)

        # 2. Signatures packers
        detected_packer = None
        for packer_name, sigs in PACKER_SIGNATURES.items():
            for sig in sigs:
                if sig in data:
                    detected_packer = packer_name
                    break
            if detected_packer:
                break

        # 3. Sections UPX dans les noms
        sections = self.report["static_analysis"].get("sections", [])
        for s in sections:
            if "UPX" in s.get("name", "").upper():
                detected_packer = "UPX"
                break

        # Verdict
        is_packed = (entropy > 7.0) or (detected_packer is not None)
        self.report["static_analysis"]["is_packed"] = is_packed
        self.report["static_analysis"]["packer"]    = detected_packer

        if is_packed:
            packer_str = f" ({detected_packer})" if detected_packer else " (custom)"
            self.report["static_analysis"]["verdict"] = f"PACKE{packer_str}"
            self.report["static_analysis"]["risk_score"] += 30
            self.report["risk_score"] += 30
            print(f"[!] Packing détecté{packer_str} — entropie {entropy:.2f}")
        else:
            self.report["static_analysis"]["verdict"] = "Non packe"

    def _calc_entropy(self, data):
        """Shannon entropy."""
        if not data:
            return 0
        entropy = 0
        for i in range(256):
            p = data.count(i) / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # Alias pour compatibilité launch.py
    def calculate_entropy(self):
        self.detect_arch()
        self.parse_sections()
        self.detect_packing()

    # ── Dynamic analysis ─────────────────────────────────────────────────────

    def run_dynamic(self):
        """Lance le binaire via QEMU + strace et analyse les syscalls."""
        if not self.qemu:
            print(f"[*] Pas de QEMU pour {self.arch} — analyse dynamique ignorée")
            return

        # Vérifie que QEMU est dispo
        r = subprocess.run(["which", self.qemu], capture_output=True)
        if r.returncode != 0:
            print(f"[-] {self.qemu} non trouvé — analyse dynamique ignorée")
            return

        print(f"[*] Analyse QEMU ({self.arch}) de {os.path.basename(self.binary)}...")
        cmd = [self.qemu, "-strace", self.binary]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
            lines = proc.stderr.splitlines()
            self.report["dynamic_analysis"]["syscalls_count"] = len(lines)
            self._analyze_syscalls(lines)

        except subprocess.TimeoutExpired:
            print(f"[!] Timeout ({self.timeout}s) — binaire bloqué sur I/O ou réseau (C2?)")
            self.report["dynamic_analysis"]["risk_score"] += 20
            self.report["dynamic_analysis"]["alerts"].append(
                f"TIMEOUT: binaire bloque apres {self.timeout}s — potentiel C2 en attente"
            )
            self.report["risk_score"] += 20

        except Exception as e:
            print(f"[-] Erreur QEMU: {e}")

    def _analyze_syscalls(self, lines):
        """Catégorise les syscalls dangereux et calcule le risk score."""
        categories_found = {}

        for line in lines:
            line_s = line.strip()
            for category, patterns in DANGEROUS_SYSCALLS.items():
                for pattern in patterns:
                    if re.search(pattern, line_s):
                        # Ajoute l'alerte
                        self.report["dynamic_analysis"]["alerts"].append(
                            f"[{category.upper()}] {line_s}"
                        )
                        # Score par catégorie (une fois par catégorie)
                        if category not in categories_found:
                            categories_found[category] = 0
                            weight = RISK_WEIGHTS.get(category, 10)
                            self.report["dynamic_analysis"]["risk_score"] += weight
                            self.report["risk_score"] += weight
                        categories_found[category] += 1
                        break

        self.report["dynamic_analysis"]["categories"] = categories_found

        total = self.report["dynamic_analysis"]["risk_score"]
        n_alerts = len(self.report["dynamic_analysis"]["alerts"])
        print(f"[+] {n_alerts} alertes | risk +{total}")

    # ── Finalize ─────────────────────────────────────────────────────────────

    def finalize(self):
        """Sauvegarde le rapport JSON (ancien format pour compatibilité Docker)."""
        output_path = os.path.join("src/reports", f"report_{self.report['target']}.json")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        import json
        with open(output_path, "w") as f:
            json.dump(self.report, f, indent=4, ensure_ascii=False)
        print(f"[+] Rapport → {output_path} | Score: {self.report['risk_score']}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "/home/sandbox/src/samples/malware_arm_bin"
    a = ARMAnalyzer(target)
    a.calculate_entropy()
    a.run_dynamic()
    a.finalize()
