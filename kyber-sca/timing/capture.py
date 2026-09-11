#!/usr/bin/env python3
"""Capture dudect fixed-vs-random timing traces from the on-device harness.

Resets the Nucleo-F411RE via OpenOCD while already listening on the serial
port, so the campaign's very first trials aren't lost to a race between
"board starts sending" and "host starts listening". Writes one CSV row per
trial: class (0=fixed, 1=random), cycles (raw DWT->CYCCNT delta from
firmware/dudect/dudect_kem_dec, see its README for what each class means).

Usage:
    python3 capture.py --port /dev/ttyACM0 --out ../traces/timing/run1.csv
"""
import argparse
import subprocess
import sys
import threading
import time

import serial

DEFAULT_OPENOCD_CFG = "../firmware/openocd/nucleo-f411re.cfg"
BAUD = 38400  # must match common/hal-opencm3.c's SERIAL_BAUD


def reset_target(openocd_cfg: str) -> None:
    subprocess.run(
        ["openocd", "-f", openocd_cfg, "-c", "init; reset run; exit"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--openocd-cfg", default=DEFAULT_OPENOCD_CFG)
    ap.add_argument("--out", required=True, help="output CSV path")
    ap.add_argument("--n", type=int, default=100_000,
                     help="number of trials to capture (must match/be <= "
                          "the firmware's DUDECT_NUM_TRACES)")
    ap.add_argument("--timeout-s", type=float, default=900.0,
                     help="overall capture timeout, seconds")
    args = ap.parse_args()

    ser = serial.Serial(args.port, BAUD, timeout=5)
    time.sleep(0.3)
    ser.reset_input_buffer()

    t = threading.Thread(target=reset_target, args=(args.openocd_cfg,))
    t.start()

    rows = []
    saw_begin = False
    start = time.time()
    while len(rows) < args.n and (time.time() - start) < args.timeout_s:
        raw = ser.readline()
        if not raw:
            continue
        line = raw.decode(errors="replace").strip()
        if line == "BEGIN dudect_kem_dec":
            saw_begin = True
            continue
        if line in ("END dudect_kem_dec", "#"):
            break
        if not saw_begin or "," not in line:
            continue
        try:
            cls_s, cyc_s = line.split(",")
            cls, cyc = int(cls_s), int(cyc_s)
        except ValueError:
            continue
        if cls not in (0, 1):
            continue
        rows.append((cls, cyc))
        if len(rows) % 10_000 == 0:
            print(f"  ... {len(rows)}/{args.n}", file=sys.stderr)

    t.join()
    ser.close()

    with open(args.out, "w") as f:
        f.write("class,cycles\n")
        for cls, cyc in rows:
            f.write(f"{cls},{cyc}\n")

    n0 = sum(1 for c, _ in rows if c == 0)
    n1 = sum(1 for c, _ in rows if c == 1)
    print(f"Captured {len(rows)} trials (class0={n0}, class1={n1}) -> {args.out}")
    if len(rows) < args.n:
        print("WARNING: fewer trials than requested -- capture timed out or "
              "the board stopped early; inspect before analysis.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
