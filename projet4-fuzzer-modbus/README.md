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
├── setpoint_attack.py # Targeted Class 7 write attack (Modbus FC16, no protocol fuzzing)
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

Measured against the fixed `plc_sim.py` (see Known Issues → Fixed):

```
$ python3 src/fuzzer.py            # (1000 iterations)
$ python3 src/report.py
--- Rapport d'Analyse du Fuzzing ---
Nombre total de tests : 1000
✅ Paquets acceptés (réponse normale) : 410
⚠️ Erreurs gérées (exception Modbus, bit haut du code fonction) : 355
❌ Crashs / erreurs de connexion détectés : 0
⏳ Timeouts (DoS potentiel) : 235
```

| Status | Count | % |
|--------|-------|---|
| Success (clean response) | 410 | 41.0% |
| Handled Modbus exception (high bit of function code set) | 355 | 35.5% |
| **Timeout — potential DoS** | **235** | **23.5%** |
| Crash / connection error | 0 | 0% |

**Key finding:** `header_lie` strategy (Length=0xFFFF or Length=0x0001) causes systematic timeouts — the server stops responding for 500ms per malformed frame. This replicates the DoS pattern of CVE-2021-22779 (Schneider Electric, CVSS 9.8). This 23.5% figure and the breakdown above are freshly re-measured after fixing `report.py`'s crash/exception detection (see Known Issues) — it previously miscounted exceptions as clean successes and could never detect a crash at all.

## Real-World Dataset Correlation

The Morris ICS datasets (`water_final.arff`, `gas_final.arff`) provide ground truth:

| Class | Count | % | Description |
|-------|-------|---|-------------|
| 0 | 172,415 | 73.0% | Normal traffic |
| 7 | 34,002 | 14.4% | Severe attack — setpoint corruption |
| 2 | 12,460 | 5.3% | Moderate attack |
| 1 | 9,187 | 3.9% | Reconnaissance |

`src/setpoint_attack.py` reproduces Class 7 attacks for real by writing `setpoint_H=0, setpoint_L=0` directly via Modbus function code 16 (Write Multiple Registers) — Modbus TCP has no authentication, so this is exactly what a legitimate SCADA client's write looks like on the wire. Run against the live PLC:

```
$ python3 src/setpoint_attack.py --watch-seconds 30
[*] Baseline : level=23% pump=OFF alarm=0 spH=80 spL=20
[!] Sending unauthenticated write: setpoint_H=0, setpoint_L=0 ...
[*] Polling for 30s to observe the consequence ...
    t+ 0.0s  level= 23%  pump=OFF  alarm=-    spH=0 spL=0
    ...
    t+24.0s  level=  9%  pump=OFF  alarm=LL!  spH=0 spL=0
[X] LL (low-level / cavitation) alarm triggered -- Class 7 setpoint corruption reproduced.
```

Setting `spH=0` forces the hysteresis logic's `water_level >= sp_H` branch permanently true, so the pump is latched OFF regardless of how low the tank runs — it drains straight through the hardware LL safety limit (10%) in well under a minute, matching the Morris dataset's Class 7 signature.

## Setup

```bash
# Create virtual environment
python3 -m venv venv && source venv/bin/activate

# Install dependencies (pymodbus is pinned -- see Known Issues)
pip install -r requirements.txt

# Terminal 1 — Start Digital Twin PLC
python3 src/plc_sim.py

# Terminal 2 — Start SCADA Monitor
python3 src/scada_monitor.py

# Terminal 3 — Run fuzzer, or the targeted Class 7 write attack
python3 src/fuzzer.py
python3 src/setpoint_attack.py

# Analyze results
python3 src/report.py
```

## Known Issues

### Fixed
- **`plc_sim.py` register addressing.** `ModbusSequentialDataBlock` takes a
  1-based starting address; constructing it with `0` silently shifted every
  wire-level read/write by one register (`scada_monitor.py` was displaying
  `pump_state` in the "level" column, `alarm` in the "pump" column, etc.).
  Confirmed empirically against a live server (`getValues`/`setValues` and
  the client-visible PDU addresses were compared side-by-side) and fixed
  throughout `plc_sim.py` and `scada_monitor.py` — see the addressing note
  in `plc_sim.py`.
- **`report.py` crash detection was dead code.** `fuzzer.py` records
  `f"Error: {type(e).__name__}"` but `report.py` was counting
  `stats['ConnectionRefusedError']` (no `"Error: "` prefix) — that counter
  could never be anything but 0, regardless of how many real connection
  errors occurred. Fixed to bucket by exception type properly.
- **`report.py` exception detection used a substring match.** `if '83' in
  row['Response_Hex']` false-positives on "83" appearing anywhere in the
  hex dump (transaction ID, register values, ...). Fixed to check the
  actual function-code byte (offset 7 in the MBAP+PDU frame) for the
  high bit Modbus sets on exception responses.
- **README claimed a Class 7 attack reproduction that didn't exist in
  code.** `fuzzer.py` only ever sent mutated *read* requests; nothing
  wrote to the setpoint registers. Added `src/setpoint_attack.py`, which
  does the actual write and was run against the live PLC to confirm it
  triggers the LL alarm (see Real-World Dataset Correlation above).

### Open
- Port 502 requires root on Linux — using port 5020 for development.
- pymodbus is pinned to `3.12.1` in `requirements.txt`: 3.15.x removes the
  `ModbusSequentialDataBlock.getValues()`/`.setValues()` API this project
  uses (confirmed by actually installing 3.15 and hitting the resulting
  `AttributeError` inside `plc_logic()`'s background thread), and migrating
  to the newer SimData/SimDevice API is future work, not silently assumed
  to be a drop-in replacement.

## References

- [Modbus Application Protocol Specification v1.1b3](https://modbus.org/specs.php)
- [Morris ICS Datasets](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)
- [CVE-2021-22779 — Schneider Electric EcoStruxure](https://nvd.nist.gov/vuln/detail/CVE-2021-22779)
- [ICS-CERT Advisories](https://www.cisa.gov/ics-advisories)
- [pymodbus Documentation](https://pymodbus.readthedocs.io)
- A. T. Anne, *Analyse de la pertinence des métriques système natives pour la détection d'anomalies sous Linux en environnements contraints*, HAL Open Science, 2026. https://hal.science/hal-05486729v1
