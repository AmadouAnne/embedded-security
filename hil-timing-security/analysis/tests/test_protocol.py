"""Cross-checks the firmware codec (compiled for the host) against hil/protocol.py."""
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "hil"))
import protocol as P  # noqa: E402

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "link.h"
void bsp_uart_send(const uint8_t *b, size_t n) { fwrite(b, 1, n, stdout); }
uint32_t link_timestamp(void) { return 0; }
static void on(uint8_t t, const uint8_t *p, size_t n, void *c) { printf("%02x:%zu;", t, n); }
int main(int argc, char **argv) {
    static uint8_t in[1 << 16], out[1 << 17];
    size_t n = fread(in, 1, sizeof in, stdin);
    if (argv[1][0] == 'e') {                 /* encode stdin as one MSG_TRACE payload */
        size_t w = link_encode(out, sizeof out, 0x81, in, n);
        fwrite(out, 1, w, stdout);
    } else {                                 /* decode stream, list frames */
        link_rx_t rx = {0};
        link_rx_feed(&rx, in, n, on, NULL);
        printf("ok=%u bad=%u", rx.frames_ok, rx.frames_bad);
    }
    return 0;
}
"""


@pytest.fixture(scope="module")
def codec(tmp_path_factory):
    d = tmp_path_factory.mktemp("codec")
    (d / "h.c").write_text(HARNESS)
    exe = d / "codec"
    subprocess.run(["gcc", "-O1", "-I", ROOT / "firmware/include", d / "h.c",
                    ROOT / "firmware/src/link.c", "-o", exe], check=True)
    return exe


def run(exe, mode, data):
    return subprocess.run([exe, mode], input=data, capture_output=True, check=True).stdout


@pytest.mark.parametrize("size", [0, 1, 24, 253, 254, 255, 768, 2000])
def test_firmware_encode_python_decode(codec, size):
    payload = random.Random(size).randbytes(size)
    wire = run(codec, "e", payload)
    frames = list(P.FrameReader().feed(wire))
    assert frames == [(P.MSG_TRACE, payload)]


def test_python_encode_firmware_decode(codec):
    rng = random.Random(1)
    good = [P.encode_frame(P.MSG_SENSOR, P.SENSOR.pack(i, *[rng.uniform(-9, 9) for _ in range(7)])) for i in range(20)]
    bad = [b"\x05\x01\x02\x00", bytes(range(1, 200)) + b"\x00"]   # truncated block, oversize
    out = run(codec, "d", b"".join(good[:10] + bad + good[10:])).decode()
    assert out.endswith("ok=20 bad=2")
    assert out.count("01:32;") == 20


def test_config_layout():
    assert len(P.RunConfig().pack()) == 56
