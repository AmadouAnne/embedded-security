#!/usr/bin/env python3
"""Safety check of the NRST wire BEFORE the orchestrator is allowed to drive it.

Run on the Pi. The GPIO stays an input the whole time (never driven). While it
runs, press the black RESET button (B2) on the NUCLEO a few times: if the level
goes 1 -> 0 -> 1, the wire is on NRST. If it stays 1, the wire may be on IOREF
(a 3.3 V supply pin): then do NOT use --reset-gpio.

  python3 hil/check_reset_line.py [--gpio 17] [--seconds 15]
"""
import argparse
import subprocess
import time

ap = argparse.ArgumentParser()
ap.add_argument("--gpio", type=int, default=17)
ap.add_argument("--seconds", type=float, default=15)
args = ap.parse_args()

subprocess.run(["pinctrl", "set", str(args.gpio), "ip", "pn"], check=True)   # input, no pull
level = lambda: subprocess.run(["pinctrl", "lev", str(args.gpio)], capture_output=True, text=True).stdout.strip()
print(f"GPIO{args.gpio} idle level = {level()}  (expected 1: NRST has a pull-up)")
print(f"press the NUCLEO RESET button (B2) now, several times, for {args.seconds:.0f} s ...")
lows, prev, t0 = 0, level(), time.monotonic()
while time.monotonic() - t0 < args.seconds:
    cur = level()
    if prev == "1" and cur == "0":
        lows += 1
        print(f"  {time.monotonic() - t0:5.1f} s: line pulled low by the button")
    prev = cur
    time.sleep(0.005)
if lows:
    print(f"OK: {lows} button presses seen, the wire is on NRST. Use --reset-gpio {args.gpio}.")
else:
    print("NOT CONFIRMED: no low level seen. Check the wire (NRST, not IOREF) before using --reset-gpio.")
