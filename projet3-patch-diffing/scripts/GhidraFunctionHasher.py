# @category: Vulnerability Analysis
import hashlib
import json
import os

def get_opcode_hash(func):
    opcodes = ""
    listing = currentProgram.getListing()
    for cu in listing.getCodeUnits(func.getBody(), True):
        if hasattr(cu, 'getMnemonicString'):
            opcodes += cu.getMnemonicString()
    return hashlib.sha256(opcodes.encode()).hexdigest()

def run():
    results = []
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        try:
            calls = [f.getName() for f in func.getCalledFunctions(monitor)]
            results.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "opcode_hash": get_opcode_hash(func),
                "calls": sorted(calls)
            })
        except Exception as e:
            results.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": 0,
                "opcode_hash": "error",
                "calls": []
            })

    # First script arg (analyzeHeadless ... -postScript GhidraFunctionHasher.py <path>)
    # lets this run non-interactively; falls back to the GUI prompt so it still
    # works from Script Manager. Using headless mode for both v33 and v35 is
    # what actually fixes the "identical JSON exports" bug documented in
    # README.md -- it removes the manual step (open project, run script, repeat)
    # where forgetting to re-import the second binary silently re-analyzes the
    # same currentProgram twice.
    args = getScriptArgs()
    output_path = args[0] if len(args) > 0 else askString("Output", "JSON output path:")
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print("[+] Exported {} functions to {}".format(len(results), output_path))

run()
