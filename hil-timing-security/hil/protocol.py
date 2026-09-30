"""Host side of the DUT link protocol. Mirrors firmware/include/link.h and trace.h.

Frame on the wire: COBS(type | payload | crc16-ccitt LE) followed by 0x00.
"""
from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass, field, fields

PROTO_VERSION = 6

MSG_SENSOR, MSG_CONFIG, MSG_START = 0x01, 0x10, 0x11
MSG_HELLO, MSG_TRACE, MSG_STATS, MSG_END, MSG_ACK, MSG_CALIB, MSG_INFO = 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86

TASKS = ["sensor", "control", "nav", "health", "security", "logging", "attack", "idle"]
PERIOD_MS = {"sensor": 5, "control": 10, "nav": 20, "health": 50, "security": 100, "logging": 500}

MIT_DEMOTE, MIT_RX_THROTTLE = 1, 2
MON_OFF, MON_DETECT, MON_MITIGATE = 0, 1, 2

TF_DEADLINE_MISS, TF_ALARM, TF_MITIGATING, TF_DATA_REJECT, TF_SLOW_PATH = 1, 2, 4, 8, 16

TRACE_REC = struct.Struct("<BBHIIIII")
TRACE_COLUMNS = ["task", "flags", "mon_cost", "seq", "release", "start_lat", "response", "exec"]
SENSOR = struct.Struct("<I7f")
HELLO = struct.Struct("<IHHIBBH")
STATS = struct.Struct("<23I B3x")
STATS_COLUMNS = ["cyc", "window_cyc", "idle_cyc", "rx_bytes", "rx_frames_ok", "rx_frames_bad",
                 "rx_overflow", "rx_hw_errors", "rx_ore", "rx_fe", "rx_ne", "rx_bad_cobs", "rx_bad_crc", "rx_overlong",
                 "sensor_seq_lost", "rx_last_bad_cyc", "rx_last_bad_len", "trace_drops", "alarms", "mitigations", "sec_passes",
                 "sec_failures", "data_rejects", "mitigation_active"]
END = struct.Struct("<3I")
CALIB = struct.Struct("<7I")
CALIB_FIELDS = ["dwt_read_min", "dwt_read_max", "trace_push_min", "trace_push_max",
                "acct_hooks_min", "acct_hooks_max", "samples"]


@dataclass
class RunConfig:
    """Mirror of run_config_t. Field order is the wire order."""
    scenario_id: int = 0
    run_id: int = 0
    duration_ms: int = 60_000
    attack_enable: int = 0
    attack_prio: int = 1
    attack_period_ms: int = 10
    attack_load_permille: int = 0
    monitor_mode: int = MON_OFF
    monitor_frozen: int = 1
    monitor_task_mask: int = 0b000111      # sensor, control, nav
    mitigation_mask: int = 0
    alarm_consec: int = 3
    data_guard: int = 0
    warmup_jobs: int = 200
    cooldown_ms: int = 200
    ewma_alpha: float = 0.05
    k_sigma: float = 4.0
    guard_ratio: float = 0.8
    sigma_floor: float = 0.01
    sec_chunk_bytes: int = 65536
    work_units: list[int] = field(default_factory=lambda: [512, 362, 1334, 1500, 1, 0])

    FORMAT = struct.Struct("<HHIBBHHBBBBBBHHffffI6H")

    def pack(self) -> bytes:
        vals = []
        for f in fields(self):
            v = getattr(self, f.name)
            vals.extend(v if isinstance(v, list) else [v])
        return self.FORMAT.pack(*vals)


assert RunConfig.FORMAT.size == 56 and SENSOR.size == 32 and HELLO.size == 16 and STATS.size == 96


def crc16_ccitt(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF), same as firmware link.c."""
    return binascii.crc_hqx(data, crc)


def cobs_encode(data: bytes) -> bytes:
    out = bytearray()
    for part in data.split(b"\x00"):
        while len(part) >= 254:
            out += b"\xff" + part[:254]
            part = part[254:]
        out += bytes([len(part) + 1]) + part
    return bytes(out)


def cobs_decode(data: bytes) -> bytes:
    out, i, n = bytearray(), 0, len(data)
    while i < n:
        code = data[i]
        if code == 0 or i + code > n:
            raise ValueError("malformed COBS")
        out += data[i + 1:i + code]
        i += code
        if code != 0xFF and i < n:
            out.append(0)
    return bytes(out)


def encode_frame(msg_type: int, payload: bytes = b"") -> bytes:
    body = bytes([msg_type]) + payload
    return cobs_encode(body + struct.pack("<H", crc16_ccitt(body))) + b"\x00"


def decode_frame(raw: bytes) -> tuple[int, bytes] | None:
    """Decode one frame (without the 0x00 delimiter); None if invalid."""
    try:
        body = cobs_decode(raw)
    except ValueError:
        return None
    if len(body) < 3 or crc16_ccitt(body[:-2]) != struct.unpack("<H", body[-2:])[0]:
        return None
    return body[0], body[1:-2]


class FrameReader:
    """Incremental splitter: feed bytes, get (type, payload) tuples."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.bad = 0

    def feed(self, data: bytes):
        self.buf += data
        while (i := self.buf.find(0)) >= 0:
            raw = bytes(self.buf[:i])
            del self.buf[:i + 1]
            if not raw:
                continue
            frame = decode_frame(raw)
            if frame is None:
                self.bad += 1
            else:
                yield frame
