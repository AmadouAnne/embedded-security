#!/usr/bin/env python3
"""HIL orchestrator (runs on the host PC; the DUT link goes through the ESP32-S3 bridge).

For every run of every scenario in a campaign file:
  reset DUT -> wait HELLO -> CONFIG -> START -> stream sensor data (+ E3/E4
  injection) -> collect TRACE/STATS until END -> write CSV + metadata.

Usage:
  python3 orchestrator.py campaign.toml --port /dev/ttyACM0 --out ../data/raw
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import queue
import random
import subprocess
import sys
import threading
import time
import tomllib
from dataclasses import asdict
from pathlib import Path

import serial

import protocol as P
from provenance import FW, file_sha256, firmware_build_id, host_info
from flight_model import FlightModel, Perturbation, perturb

SENSOR_HZ = 200


class Link:
    """Serial link. A dedicated thread only drains the port into memory, so a
    stall in decoding or disk I/O cannot overflow the kernel tty buffer (4 KiB)
    and make the ST-LINK bridge drop DUT->host bytes."""

    def __init__(self, port: str, baud: int) -> None:
        self.ser = serial.Serial()
        self.ser.port, self.ser.baudrate, self.ser.timeout = port, baud, 0.02
        # DTR asserted = "host connected": the TinyUSB CDC of the ESP32-S3
        # bridge only transmits to the host while DTR is set. The bridge runs
        # with enableReboot(false), so DTR/RTS changes cannot reset it.
        self.ser.dtr = True
        self.ser.rts = False
        self.ser.open()
        self.tx_lock = threading.Lock()
        self.reader = P.FrameReader()
        self.rxq: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self.flush_rx = threading.Event()
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        while self.ser.is_open:
            try:
                chunk = self.ser.read(max(1, self.ser.in_waiting))
            except (serial.SerialException, TypeError, OSError):
                break                     # port closed or device gone: the run's checks will flag it
            if self.flush_rx.is_set():
                self.flush_rx.clear()
                while not self.rxq.empty():
                    self.rxq.get_nowait()
                continue
            if chunk:
                self.rxq.put(chunk)

    def reset_input(self) -> None:
        self.flush_rx.set()
        while self.flush_rx.is_set():
            time.sleep(0.005)

    def send(self, data: bytes) -> None:
        with self.tx_lock:
            self.ser.write(data)

    def frames(self):
        try:
            chunk = self.rxq.get(timeout=0.05)
        except queue.Empty:
            return
        while not self.rxq.empty():
            chunk += self.rxq.get_nowait()
        yield from self.reader.feed(chunk)

    def wait_for(self, msg_type: int, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for t, payload in self.frames():
                if t == msg_type:
                    return payload
        raise TimeoutError(f"no frame 0x{msg_type:02x} within {timeout}s")


class SensorStreamer(threading.Thread):
    """200 Hz sensor frames with optional E4 perturbation."""

    def __init__(self, link: Link, seed: int, pert: Perturbation) -> None:
        super().__init__(daemon=True)
        self.link, self.pert = link, pert
        self.model, self.rng = FlightModel(seed), random.Random(seed + 1)
        self.stop = threading.Event()
        self.sent = 0
        self.t_send: list[float] = []

    def stats(self, t_from: float, t_to: float) -> dict:
        """Achieved stimulus rate and interval jitter inside [t_from, t_to] (perf_counter)."""
        import numpy as np
        t = np.array([x for x in self.t_send if t_from <= x <= t_to])
        if len(t) < 3:
            return {}
        d = np.diff(t) * 1e3
        return {"rate_hz": (len(t) - 1) / (t[-1] - t[0]), "interval_ms_mean": d.mean(),
                "interval_ms_p99": float(np.percentile(d, 99)), "interval_ms_max": d.max()}

    def run(self) -> None:
        period = 1.0 / SENSOR_HZ
        nxt = time.perf_counter()
        while not self.stop.is_set():
            sample = perturb(self.model.step(period), self.pert, self.rng)
            self.link.send(P.encode_frame(P.MSG_SENSOR, P.SENSOR.pack(self.sent, *sample)))
            self.t_send.append(time.perf_counter())
            self.sent += 1
            nxt += period
            time.sleep(max(0.0, nxt - time.perf_counter()))


class Flooder(threading.Thread):
    """E3: malformed traffic on the shared link at a target byte rate.

    kinds: random   - random bytes with frame delimiters
           bad_crc  - well-formed COBS frames of sensor size with a wrong CRC
           oversize - frames longer than the DUT's maximum frame length
    """

    def __init__(self, link: Link, kind: str, rate_bps: int, seed: int) -> None:
        super().__init__(daemon=True)
        self.link, self.kind, self.rate = link, kind, rate_bps
        self.rng = random.Random(seed)
        self.stop = threading.Event()
        self.sent = 0

    def packet(self) -> bytes:
        r = self.rng
        if self.kind == "random":
            return bytes(r.randrange(1, 256) for _ in range(r.randrange(8, 64))) + b"\x00"
        if self.kind == "bad_crc":
            body = bytes([P.MSG_SENSOR]) + r.randbytes(P.SENSOR.size) + b"\xde\xad"
            return P.cobs_encode(body) + b"\x00"
        if self.kind == "oversize":
            return bytes(r.randrange(1, 256) for _ in range(300)) + b"\x00"
        raise ValueError(self.kind)

    def run(self) -> None:
        t0 = time.perf_counter()
        while not self.stop.is_set():
            pkt = self.packet()
            self.link.send(pkt)
            self.sent += len(pkt)
            ahead = self.sent / self.rate - (time.perf_counter() - t0)
            if ahead > 0:
                time.sleep(ahead)


def default_port() -> str:
    """Link port by stable name: the ESP32-S3 bridge if present (campaign
    setup), else the ST-LINK virtual COM port (bench bring-up only)."""
    import glob
    for pat in ("/dev/serial/by-id/*Espressif*", "/dev/serial/by-id/*STLink*", "/dev/ttyACM0"):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[0]
    return "/dev/ttyACM0"


def reset_dut(cmd: str | None) -> None:
    if cmd:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
        time.sleep(0.3)


def handshake(link: Link, reset_cmd: str | None, expect_build: str | None) -> tuple[tuple, str]:
    """Reset the DUT, wait for HELLO + INFO, check compatibility and build identity."""
    reset_dut(reset_cmd)
    link.reset_input()
    link.reader = P.FrameReader()
    hello, info = None, None
    deadline = time.monotonic() + 5.0
    while (hello is None or info is None) and time.monotonic() < deadline:
        for t, payload in link.frames():
            if t == P.MSG_HELLO:
                hello = P.HELLO.unpack(payload)
            elif t == P.MSG_INFO and hello is not None:
                info = payload.decode(errors="replace")
    if hello is None or info is None:
        raise TimeoutError("no HELLO/INFO from DUT (wiring, baud rate, firmware flashed?)")
    magic, fw, proto, cpu_hz, n_tasks, rec_size, cfg_size = hello
    if magic != 0x45524153 or proto != P.PROTO_VERSION or rec_size != P.TRACE_REC.size or cfg_size != P.RunConfig.FORMAT.size:
        raise RuntimeError(f"incompatible firmware: {hello}")
    if expect_build and f"build={expect_build}" not in info:
        raise RuntimeError(f"DUT runs '{info}', but the source tree is build={expect_build}: reflash or pass --allow-build-mismatch")
    return hello, info


def run_once(link: Link, cfg: P.RunConfig, sc: dict, seed: int, out: Path, reset_cmd: str | None,
             expect_build: str | None = None) -> dict:
    hello, info = handshake(link, reset_cmd, expect_build)
    magic, fw, proto, cpu_hz, n_tasks, rec_size, cfg_size = hello

    link.send(P.encode_frame(P.MSG_CONFIG, cfg.pack()))
    link.wait_for(P.MSG_ACK, 2.0)

    pert = Perturbation(**sc.get("perturbation", {}))
    streamer = SensorStreamer(link, seed, pert)
    streamer.start()
    flood = None
    if "flood" in sc:
        flood = Flooder(link, sc["flood"]["kind"], sc["flood"]["rate_bps"], seed + 2)

    link.reader.bad = 0   # link integrity is assessed on run traffic only
    link.send(P.encode_frame(P.MSG_START))
    t_start, pc_start = time.time(), time.perf_counter()
    if flood:
        flood.start()

    trace_path, stats_path = out.with_suffix(".trace.csv"), out.with_suffix(".stats.csv")
    n_rec, end_info, calib = 0, None, None
    deadline = time.monotonic() + cfg.duration_ms / 1000 + 15
    with open(trace_path, "w", newline="") as tf, open(stats_path, "w", newline="") as sf:
        tw, sw = csv.writer(tf), csv.writer(sf)
        tw.writerow(P.TRACE_COLUMNS)
        sw.writerow(["host_time"] + P.STATS_COLUMNS)
        while end_info is None and time.monotonic() < deadline:
            for t, payload in link.frames():
                if t == P.MSG_TRACE:
                    for rec in P.TRACE_REC.iter_unpack(payload):
                        tw.writerow(rec)
                        n_rec += 1
                elif t == P.MSG_STATS:
                    sw.writerow([f"{time.time():.3f}", *P.STATS.unpack(payload)])
                elif t == P.MSG_CALIB:
                    calib = dict(zip(P.CALIB_FIELDS, P.CALIB.unpack(payload)))
                elif t == P.MSG_END:
                    end_info = P.END.unpack(payload)

    stimulus = streamer.stats(pc_start + 0.1, pc_start + cfg.duration_ms / 1000)
    streamer.stop.set()
    if flood:
        flood.stop.set()

    meta = {
        "scenario": sc["name"], "scenario_id": cfg.scenario_id, "run_id": cfg.run_id, "seed": seed,
        "config": asdict(cfg), "scenario_spec": sc, "cpu_hz": cpu_hz, "fw_version": fw,
        "fw_info": info, "fw_bin_sha256": file_sha256(FW / "build" / "sare_fw.bin"),
        "host": host_info(), "t_start": t_start, "records": n_rec, "calibration": calib,
        "end": dict(zip(["tasks_done", "trace_drops", "alarms"], end_info)) if end_info else None,
        "sensor_frames_sent": streamer.sent, "stimulus": stimulus, "flood_bytes_sent": flood.sent if flood else 0,
        "host_bad_frames": link.reader.bad,
    }
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def build_config(defaults: dict, sc: dict, sid: int, run: int) -> P.RunConfig:
    params = {**defaults, **sc.get("config", {})}
    return P.RunConfig(scenario_id=sid, run_id=run, **params)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("campaign", type=Path)
    ap.add_argument("--port", default=None, help="link port (default: ESP32 bridge by stable name)")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--out", type=Path, default=Path("../data/raw"))
    ap.add_argument("--only", nargs="*", help="run only these scenario names")
    ap.add_argument("--skip", nargs="*", default=[], help="skip these scenario names")
    ap.add_argument("--reset-cmd", default=os.environ.get("SARE_RESET_CMD", "st-flash --connect-under-reset reset"))
    ap.add_argument("--dry-run", action="store_true", help="print the run plan and exit")
    ap.add_argument("--rerun-invalid", action="store_true",
                    help="re-run every run that fails validation; the invalid originals are kept in <out>/invalid/")
    ap.add_argument("--max-rerun", type=int, default=3, help="attempts per invalid run")
    ap.add_argument("--allow-build-mismatch", action="store_true",
                    help="accept a DUT whose firmware differs from the local source tree (not for paper data)")
    args = ap.parse_args()

    camp = tomllib.loads(args.campaign.read_text())
    defaults, reps = camp.get("defaults", {}), camp.get("repetitions", 1)
    plan = [(sid, sc) for sid, sc in enumerate(camp["scenario"])
            if (not args.only or sc["name"] in args.only) and sc["name"] not in args.skip]

    total_s = sum(sc.get("repetitions", reps) * build_config(defaults, sc, 0, 0).duration_ms / 1000 for _, sc in plan)
    print(f"{len(plan)} scenarios, ~{total_s / 3600:.1f} h of measurement")
    if args.dry_run:
        for sid, sc in plan:
            print(f"  [{sid:2d}] {sc['name']:<28} x{sc.get('repetitions', reps)}  {build_config(defaults, sc, sid, 0)}")
        return 0

    out_dir = args.out / camp.get("name", args.campaign.stem)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "campaign.toml").write_text(args.campaign.read_text())
    link = Link(args.port or default_port(), args.baud)

    expect = None if args.allow_build_mismatch else firmware_build_id()

    def battery_low() -> bool:
        """True when running on battery below 15 %: stop cleanly between runs."""
        import glob as g
        ac = [open(f).read().strip() for f in g.glob("/sys/class/power_supply/A*/online")]
        cap = [int(open(f).read()) for f in g.glob("/sys/class/power_supply/BAT*/capacity")]
        return bool(cap) and "1" not in ac and min(cap) < 15
    for sid, sc in plan:
        for run in range(sc.get("repetitions", reps)):
            prefix = out_dir / f"{sc['name']}_r{run:02d}"
            if args.rerun_invalid and prefix.with_suffix(".meta.json").exists() and run_is_valid(prefix):
                continue          # valid runs are never repeated; missing or partial runs are re-run
            if battery_low():
                print("on battery below 15 %: stopping cleanly; resume with --rerun-invalid", flush=True)
                return 2
            for attempt in range(args.max_rerun if args.rerun_invalid else 1):
                if args.rerun_invalid and prefix.with_suffix(".meta.json").exists():
                    archive_invalid(prefix, out_dir)       # complete but invalid: keep it for the report
                cfg = build_config(defaults, sc, sid, run)
                seed = camp.get("seed", 1) * 1000 + sid * 100 + run      # same seed: same stimulus
                meta = run_once(link, cfg, sc, seed, prefix, args.reset_cmd, expect)
                ok = run_is_valid(prefix)
                print(f"{sc['name']:<28} run {run}: {meta['records']} records, "
                      f"{'VALID' if ok else 'INVALID'}{' (rerun)' if args.rerun_invalid else ''}", flush=True)
                if ok:
                    break
                if meta["records"] == 0 or meta["end"] is None:
                    # No trace data at all is not a link glitch: it is deterministic
                    # (e.g. overload starving the Logging task). Retrying cannot help.
                    print(f"{sc['name']:<28} run {run}: no data received, not retried", flush=True)
                    break
    return 0


def run_is_valid(prefix: Path) -> bool:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis"))
    import sare
    import validate
    tr, st, meta = sare.load_run(prefix)
    return all(ok for _, ok, _ in validate.check_run(tr, st, meta))


def archive_invalid(prefix: Path, out_dir: Path) -> None:
    """Keep every invalid run (reported in the supplementary material)."""
    dest = out_dir / "invalid"
    dest.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for suffix in (".meta.json", ".trace.csv", ".stats.csv"):
        src = prefix.with_suffix(suffix)
        if src.exists():
            src.rename(dest / f"{prefix.name}.{stamp}{suffix}")


if __name__ == "__main__":
    sys.exit(main())
