
# Embedded Security — Research & Engineering Projects

> Travaux pratiques en sécurité des systèmes embarqués, couvrant la sécurité hardware, l'analyse de firmware, les protocoles industriels et la cryptographie physique.

**Amadou Tidiane Anne** · Master Logiciels et Systèmes Embarqués · UBO Brest  
[![HAL](https://img.shields.io/badge/HAL-Prépublication-blue)](https://hal.science/hal-05486729v1)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Projects

### 🔒 [P1 — FreeRTOS Hardened on STM32](./freertos-stm32)
Multitask RTOS system with MPU memory isolation, hardware watchdog and authenticated UART communication on ARM Cortex-M.  
`C` `FreeRTOS` `STM32` `MPU` `mbedTLS` `OpenOCD`

---

### 🛡️ [P2 — Secure Boot & Chain of Trust](./secure-boot)
FIT image signing for a Raspberry Pi 4 boot chain — kernel and device tree hashed (SHA-256) and signed (RSA-2048), trusted public key embedded in U-Boot's control DTB. Independently re-verified with openssl/fdtget outside of U-Boot, including two attack scenarios (tampering, re-signing with a foreign key) confirmed rejected.  
`U-Boot FIT` `RSA-2048` `OpenSSL` `PKI` `Docker`

---

### 🔍 [P3 — IoT Firmware Patch Diffing](./patch-diffing)
Compares two OpenWRT firmware versions at the function level via Ghidra (headless, PyGhidra), pinpointing exactly which functions changed and why. One confirmed CVE (stored XSS in LuCI) plus an undocumented `libuclient` fix found and reverse-engineered from the binary diff alone.  
`Python` `Ghidra` `PyGhidra` `Binwalk` `MIPS`

---

### ⚡ [P4 — Modbus TCP Grammar Fuzzer](./fuzzer-modbus)
Grammar-based fuzzer targeting Modbus TCP against a physics-based digital-twin PLC (water tank). Mutation engine plus a targeted unauthenticated-write attack that reproduces a real ICS dataset's most severe attack class end-to-end (triggers a real low-level safety alarm on the simulated PLC).  
`Python` `Scapy` `pymodbus` `ICS/SCADA` `Modbus`

---

### 🤖 [P5 — ARM Malware Analysis Sandbox](./sandbox-arm)
Dynamic analysis sandbox for ARM/MIPS/PPC binaries running under instrumented QEMU in an isolated, network-disabled Docker container. Captures syscalls and network attempts, scores risk, and maps behavior to MITRE ATT&CK.  
`QEMU` `Python` `Flask` `Docker` `strace`

---

### 📡 [P6 — AES-128 Side-Channel Attack](./side-channel)
Correlation Power Analysis (CPA) against AES-128's first-round SubBytes — full key recovery via Pearson correlation, and a first-order boolean masking countermeasure shown to defeat it. Currently validated on a simulated Hamming-weight leakage model; real oscilloscope captures pending hardware access.  
`Python` `numpy` `CPA` `AES-128` `Power Analysis`

---

### 🧩 [P7 — RISC-V PMP Task Isolation](./riscv-pmp-isolation)
Comparative counterpart to P1: the same untrusted-task-isolation threat model, ported from ARM Cortex-M's MPU to RISC-V's structurally different Physical Memory Protection (PMP). A minimal M-mode round-robin scheduler reconfigures PMP on every context switch between two sibling U-mode tasks; one deliberately corrupts the other's memory once scheduled, the scheduler catches and kills only the offender, and the sibling keeps running untouched — verified against the linked ELF's own symbol table, not just observed. Validated in QEMU; real hardware validation is next, pending a RISC-V board.  
`RISC-V` `C` `QEMU` `PMP`

---

## Research

**Analyse de la pertinence des métriques système natives pour la détection d'anomalies sous Linux en environnements contraints**  
Prépublication HAL — Janvier 2026  
→ [hal.science/hal-05486729v1](https://hal.science/hal-05486729v1)

**Isolation de tâches non fiables en systèmes embarqués contraints : étude comparative MPU ARM Cortex-M4 / PMP RISC-V, avec validation matérielle réelle**  
Brouillon — à partir de [P1](./freertos-stm32) et [P7](./riscv-pmp-isolation)  
→ [papers/mpu-vs-pmp-isolation](./papers/mpu-vs-pmp-isolation/paper.md)

---

## Stack

```
Languages  : C · Python · Bash · Assembly (MIPS, RISC-V)
Hardware   : STM32 Nucleo-F411RE · Raspberry Pi 4 · RISC-V (QEMU virt, hardware pending)
Security   : Ghidra (PyGhidra) · Binwalk · OpenSSL · mbedTLS
Embedded   : FreeRTOS-MPU · U-Boot (FIT) · QEMU-user · QEMU-system-riscv · OpenOCD · RISC-V PMP
Protocols  : Modbus TCP
```
