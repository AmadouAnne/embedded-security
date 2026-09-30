#!/usr/bin/env python3
"""Record the Raspberry Pi serial console through the STM32 UART bridge.

Diagnostic only. Flash firmware/build_bridge/uart_bridge.bin first, and
enable the Pi console with hil/sd_console.sh on the SD card. Every line is
timestamped and saved in data/bringup/pi_console_<date>.log.

  python3 hil/pi_console.py [--port /dev/ttyACM0] [--seconds 180]
"""
import argparse
import sys
import time
from pathlib import Path

import serial

ap = argparse.ArgumentParser()
ap.add_argument("--port", default="/dev/ttyACM0")
ap.add_argument("--seconds", type=float, default=180)
args = ap.parse_args()

out = Path(__file__).resolve().parents[1] / "data" / "bringup" / time.strftime("pi_console_%Y%m%d-%H%M%S.log")
out.parent.mkdir(parents=True, exist_ok=True)
ser = serial.Serial(args.port, 115200, timeout=0.2)
t0, line = time.monotonic(), b""
print(f"listening on {args.port} for {args.seconds:.0f} s -> {out}\n(power the Pi now)", flush=True)
with open(out, "w") as f:
    while time.monotonic() - t0 < args.seconds:
        for b in ser.read(4096):
            if b in (10, 13):
                if line:
                    txt = f"[{time.monotonic() - t0:7.2f}] {line.decode(errors='replace')}"
                    print(txt, flush=True)
                    f.write(txt + "\n")
                    line = b""
            else:
                line += bytes([b])
print(f"saved {out}")
