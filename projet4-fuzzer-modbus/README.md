# Modbus TCP Grammar-Based Fuzzer

[![Python](https://img.shields.io/badge/Python-3.14-blue)](https://python.org)
[![Pymodbus](https://img.shields.io/badge/pymodbus-3.12.1-green)](https://pymodbus.readthedocs.io)
[![Scapy](https://img.shields.io/badge/Scapy-2.x-orange)](https://scapy.net)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

Grammar-based fuzzer targeting Modbus TCP — the most deployed protocol in industrial control systems (ICS/SCADA). Built as part of a 6-project embedded security research roadmap.

## Context

Modbus TCP (port 502) powers critical infrastructure: power plants, water treatment facilities, gas pipelines, and industrial production lines. Designed in 1979 with no authentication, no encryption, and no input validation, it remains a prime target for security research.

This project implements a grammar-based fuzzer that generates structurally valid but semantically corrupt Modbus frames, detects anomalies, and correlates results with real-world attack patterns from the Morris ICS datasets.

## Architecture

```
src/
├── plc_sim.py        # Digital Twin — water tank PLC simulation + Modbus server
├── scada_monitor.py  # SCADA dashboard — reads registers in real time
├── parser.py         # ModbusTCP Scapy layer — full MBAP header
├── mutator.py        # MutationEngine — 4 mutation strategies
├── fuzzer.py         # Fuzzing pipeline — socket-level, logs to CSV
└── report.py         # Results analyzer

data/
├── morris_water_tank/water_final.arff    # 236,179 real ICS records (8 attack classes)
└── morris_gas_pipeline/gas_final.arff   # Gas pipeline dataset
```

## Pipeline

```
ModbusTCP (Scapy) --> MutationEngine --> raw bytes
                                             |
                                    TCP socket (port 5020)
                                             |
                                    plc_sim.py (Digital Twin)
                                             |
                               [timeout / exception / anomaly]
                                             |
                                    logs/fuzz_results.csv
```

## Modbus Frame Structure

```
+----------+----------+--------+---------+---------------+---------+
| Trans.ID | Proto.ID | Length | Unit ID | Function Code |  Data   |
|  2 bytes |  2 bytes | 2 bytes| 1 byte  |    1 byte     |  var.   |
+----------+----------+--------+---------+---------------+---------+
  0x0001     0x0000    0x0006    0x01        0x03          ...
```

**Attack surface per field:**
- `Length` — oversized value triggers buffer over-read (CVE-2021-22779 pattern)
- `Function Code` — undefined codes (0x00, 0x08, 0x64-0x7F) cause undefined behavior
- `Unit ID` — 0x00 (broadcast) and 0xFF have special meanings in some implementations
- `Data` — boundary values (0x0000, 0xFFFF) in setpoint registers corrupt PLC logic

## Digital Twin — Water Tank PLC

`plc_sim.py` simulates a real water treatment PLC with physical dynamics:

```
Holding Registers (Modbus addresses 1-5):
  [1] water_level  : current level 0-100%  (read only)
  [2] pump_state   : pump ON=1 / OFF=0     (read only)
  [3] alarm        : LL alarm 0=OK / 1=ALM (read only)
  [4] setpoint_H   : high threshold = 80   (writable — attack target)
  [5] setpoint_L   : low threshold  = 20   (writable — attack target)

Hardware safety limits (not in Modbus registers):
  HH = 90  (overflow danger)
  LL = 10  (cavitation danger)
```

Writing `0x0000` to registers 4 and 5 replicates **Class 7 attacks** from the Morris dataset — the most severe attack category (14.4% of 236,179 records).

## Mutation Strategies

| Strategy | Description | Target CVE pattern |
|----------|-------------|-------------------|
| `bit_flip` | Random bit inversion in PDU | General corruption |
| `overflow` | Appends 100-1000 bytes of `0x41` | Buffer overflow |
| `extreme` | Replaces data with 0x00/0xFF/0x7F | Boundary value |
| `header_lie` | Sets Length to 0, 1, 500, or 65535 | CVE-2021-22779 |

## Results — 1000 Iterations

| Status | Count | % |
|--------|-------|---|
| Success (server responded) | 755 | 75.5% |
| **Timeout — potential DoS** | **245** | **24.5%** |

**Key finding:** `header_lie` strategy (Length=0xFFFF or Length=0x0001) causes systematic timeouts — the server stops responding for 500ms per malformed frame. This replicates the DoS pattern of CVE-2021-22779 (Schneider Electric, CVSS 9.8).

## Real-World Dataset Correlation

The Morris ICS datasets (`water_final.arff`, `gas_final.arff`) provide ground truth:

| Class | Count | % | Description |
|-------|-------|---|-------------|
| 0 | 172,415 | 73.0% | Normal traffic |
| 7 | 34,002 | 14.4% | Severe attack — setpoint corruption |
| 2 | 12,460 | 5.3% | Moderate attack |
| 1 | 9,187 | 3.9% | Reconnaissance |

Our fuzzer reproduces Class 7 attacks by writing `HH=0, H=0` to setpoint registers — identical to the attack signature in the dataset.

## Setup

```bash
# Create virtual environment
python3 -m venv venv && source venv/bin/activate

# Install dependencies
pip install pymodbus scapy

# Terminal 1 — Start Digital Twin PLC
python3 src/plc_sim.py

# Terminal 2 — Start SCADA Monitor
python3 src/scada_monitor.py

# Terminal 3 — Run fuzzer
python3 src/fuzzer.py

# Analyze results
python3 src/report.py
```

## Known Issues

- `plc_sim.py` register offset bug: `setValues(0,...)` should be `setValues(1,...)` — fix in progress
- Port 502 requires root on Linux — using port 5020 for development
- Ghidra headless PyGhidra not available — Python scripts require GUI mode

## References

- [Modbus Application Protocol Specification v1.1b3](https://modbus.org/specs.php)
- [Morris ICS Datasets](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)
- [CVE-2021-22779 — Schneider Electric EcoStruxure](https://nvd.nist.gov/vuln/detail/CVE-2021-22779)
- [ICS-CERT Advisories](https://www.cisa.gov/ics-advisories)
- [pymodbus Documentation](https://pymodbus.readthedocs.io)
- A. T. Anne, *Analyse de la pertinence des métriques système natives pour la détection d'anomalies sous Linux en environnements contraints*, HAL Open Science, 2026. https://hal.science/hal-05486729v1
