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

    output_path = askString("Output", "JSON output path:")
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print("[+] Exported {} functions to {}".format(len(results), output_path))

run()
