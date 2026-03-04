
# Embedded Security — Research & Engineering Projects

> Travaux pratiques en sécurité des systèmes embarqués, couvrant la sécurité hardware, l'analyse de firmware, les protocoles industriels et la cryptographie physique.

**Amadou Tidiane Anne** · Master Logiciels et Systèmes Embarqués · UBO Brest  
[![HAL](https://img.shields.io/badge/HAL-Prépublication-blue)](https://hal.science/hal-05486729v1)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Projects

### 🔒 [P1 — FreeRTOS Hardened on STM32](./projet1-freertos-stm32)
Multitask RTOS system with MPU memory isolation, hardware watchdog and authenticated UART communication on ARM Cortex-M.  
`C` `FreeRTOS` `STM32` `MPU` `mbedTLS` `OpenOCD`

---

### 🛡️ [P2 — Secure Boot & Chain of Trust](./projet2-secure-boot)
Full chain of trust implementation on Raspberry Pi using U-Boot verified boot. RSA-2048 kernel signature — any unsigned binary is rejected at boot time.  
`U-Boot` `RSA-2048` `ARM TrustZone` `PKI` `Buildroot`

---

### 🔍 [P3 — IoT Firmware Patch Diffing](./projet3-patch-diffing)
Automated tool that compares two firmware versions, identifies modified functions via Ghidra scripting, and correlates changes with published CVEs through the NVD API.  
`Python` `Ghidra` `Binwalk` `CVE` `NVD API` `ASM ARM`

---

### ⚡ [P4 — Modbus TCP Grammar Fuzzer](./projet4-fuzzer-modbus)
Grammar-based fuzzer targeting Modbus TCP — the industrial protocol used in power plants, water treatment and factories. Intelligent mutation engine with crash reproduction.  
`Python` `Scapy` `ICS/SCADA` `Modbus` `Coverage-guided`

---

### 🤖 [P5 — ARM Malware Analysis Sandbox](./projet5-sandbox-arm)
Dynamic analysis sandbox for ARM binaries running under instrumented QEMU. Captures syscalls, network traffic and filesystem access — generates automated behavior reports.  
`QEMU` `Python` `Flask` `Docker` `strace` `ARM`

---

### 📡 [P6 — AES-128 Side-Channel Attack](./projet6-side-channel)
Correlation Power Analysis (CPA) attack on AES-128 running on STM32. Full key extraction via Pearson correlation on 1000+ power traces. Masking countermeasure implemented and validated.  
`Python` `numpy` `CPA` `STM32` `mbedTLS` `Power Analysis`

---

## Research

**Analyse de la pertinence des métriques système natives pour la détection d'anomalies sous Linux en environnements contraints**  
Prépublication HAL — Janvier 2026  
→ [hal.science/hal-05486729v1](https://hal.science/hal-05486729v1)

---

## Stack

\`\`\`
Languages  : C · C++ · Python · Bash · Assembly (ARM/x86)
Hardware   : STM32 Nucleo · Raspberry Pi · ESP32
Security   : Ghidra · Binwalk · Metasploit · Wazuh · OpenSSL
Embedded   : FreeRTOS · Buildroot · U-Boot · QEMU · OpenOCD
Protocols  : Modbus TCP · MQTT · TLS/mTLS · CAN · SPI · I2C
\`\`\`
