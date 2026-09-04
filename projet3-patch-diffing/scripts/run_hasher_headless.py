#!/usr/bin/env python3
"""
Headless replacement for GhidraFunctionHasher.py's manual GUI workflow.

The bug this fixes: running GhidraFunctionHasher.py from Ghidra's GUI
Script Manager requires opening a NEW project and importing each binary
separately, then running the script -- easy to get wrong by re-running it
against the same still-open program twice, which is exactly what produced
the identical libuclient_v33.json/libuclient_v35.json noted in earlier
analysis. This script does both imports + analyses + exports in one
non-interactive process, each into its own throwaway Ghidra project, so
there's no manual step left to get wrong.

Requires PyGhidra (`pip install pyghidra`) and a local Ghidra install
(GHIDRA_INSTALL_DIR environment variable, or pyghidra will try to find one).

Usage:
    python3 run_hasher_headless.py <binary_path> <output.json> [project_dir]
"""
import sys
import hashlib
import json
import tempfile
import warnings

import pyghidra


def hash_functions(binary_path: str, project_dir: str) -> list[dict]:
    # open_program() is deprecated in newer PyGhidra in favour of a
    # two-step open_project()/program_context() API; still fully functional
    # here and simpler for a one-shot script, so the warning is suppressed
    # rather than worked around.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pyghidra.open_program(binary_path, project_location=project_dir, analyze=True) as flat_api:
            program = flat_api.getCurrentProgram()
            fm = program.getFunctionManager()
            listing = program.getListing()

            results = []
            for func in fm.getFunctions(True):
                try:
                    opcodes = "".join(
                        cu.getMnemonicString()
                        for cu in listing.getCodeUnits(func.getBody(), True)
                        if hasattr(cu, "getMnemonicString")
                    )
                    calls = sorted(f.getName() for f in func.getCalledFunctions(flat_api.getMonitor()))
                    results.append({
                        "name": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "size": func.getBody().getNumAddresses(),
                        "opcode_hash": hashlib.sha256(opcodes.encode()).hexdigest(),
                        "calls": calls,
                    })
                except Exception:
                    results.append({
                        "name": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "size": 0,
                        "opcode_hash": "error",
                        "calls": [],
                    })
            return results


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    binary_path, output_path = sys.argv[1], sys.argv[2]
    project_dir = sys.argv[3] if len(sys.argv) > 3 else tempfile.mkdtemp(prefix="ghidra_proj_")

    results = hash_functions(binary_path, project_dir)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Exported {len(results)} functions to {output_path} (Ghidra project: {project_dir})")


if __name__ == "__main__":
    main()
