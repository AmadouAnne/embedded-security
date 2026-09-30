"""Provenance: tie every run to an exact firmware source tree and host setup."""
from __future__ import annotations

import hashlib
import platform
import sys
from pathlib import Path

FW = Path(__file__).resolve().parents[1] / "firmware"
HIL = Path(__file__).resolve().parent


def firmware_build_id(root: Path = FW) -> str:
    """Same algorithm as firmware/cmake/build_id.cmake."""
    pats = ["src/*.c", "include/*.h", "config/*.h", "ld/*.ld", "CMakeLists.txt", "fetch_deps.sh"]
    files = sorted({p.relative_to(root).as_posix() for pat in pats for p in root.glob(pat)})
    manifest = "".join(f"{f} {hashlib.sha256((root / f).read_bytes()).hexdigest()}\n" for f in files)
    return hashlib.sha256(manifest.encode()).hexdigest()[:16]


def host_info() -> dict:
    import serial
    hil_hash = hashlib.sha256(b"".join(p.read_bytes() for p in sorted(HIL.glob("*.py")))).hexdigest()[:16]
    return {"python": sys.version.split()[0], "pyserial": serial.__version__,
            "platform": platform.platform(), "node": platform.node(), "hil_sources": hil_hash}


def file_sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
