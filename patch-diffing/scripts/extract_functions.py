#!/usr/bin/env python3
import sys, json, hashlib
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import capstone

def get_code_bytes(elf, address, size):
    for seg in elf.iter_segments():
        s, e = seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"]
        if s <= address < e:
            elf.stream.seek(seg["p_offset"] + (address - s))
            return elf.stream.read(size)
    return None

def analyze(path, output):
    results = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        md = capstone.Cs(capstone.CS_ARCH_MIPS,
                         capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC": continue
                if sym["st_size"] == 0: continue
                code = get_code_bytes(elf, sym["st_value"], sym["st_size"])
                if not code: continue
                mnemonics = " ".join(i.mnemonic for i in
                                     md.disasm(code, sym["st_value"]))
                results.append({
                    "name": sym.name,
                    "address": hex(sym["st_value"]),
                    "size": sym["st_size"],
                    "opcode_hash": hashlib.sha256(mnemonics.encode()).hexdigest(),
                    "raw_hash": hashlib.sha256(code).hexdigest()
                })
    with open(output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] {len(results)} fonctions exportees -> {output}")

analyze(sys.argv[1], sys.argv[2])
