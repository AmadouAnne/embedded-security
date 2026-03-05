# @category: Vulnerability Analysis
# @author: Amadou Tidiane Anne
# @description: Extrait les fonctions, calcule le hash des opcodes et exporte en JSON.

import hashlib
import json
import os
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor

def get_opcode_hash(func):
    """
    Calcule le hash SHA-256 des mnemoniques d'une fonction.
    Cela permet de detecter un changement de logique meme si les adresses changent.
    """
    opcodes = ""
    listing = currentProgram.getListing()
    addr_set = func.getBody()
    code_units = listing.getCodeUnits(addr_set, True) # on fait un parcours en avant
    
    for cu in code_units:
    # On ne traite que les instructions (pas les donnees/bytes bruts)
        if isinstance(cu, ghidra.program.model.listing.Instruction):
        # getMnemonicString recupere l'instruction (ex: 'sw', 'jalr', 'save') et on ighore les  operandes pour eviter les faux positifs
            opcodes += cu.getMnemonicString()
            
    if not opcodes:
        return "Pas_Instruction_Trouver"
    
    return hashlib.sha256(opcodes.encode()).hexdigest()
    
def run_analysis():
    print("--- Debut de l'extraction des fonctions ---")
    results = []
    fm = currentProgram.getFunctionManager()
    
    # On recupere toutes les fonctions identifiees
    functions = fm.getFunctions(True) 
    
    count = 0
    for func in functions:
        count += 1
        # Extraction des metadata de la fonction
        func_data = {
            "name": func.getName(),
            "address": func.getEntryPoint().toString(),
            "size": func.getBody().getNumAddresses(),
            "opcode_hash": get_opcode_hash(func),
            "calls": [called.getName() for called in func.getCalledFunctions(ConsoleTaskMonitor())]
        }
        results.append(func_data)
    
    # Creation du nom de fichier de sortie base sur le nom du binaire charge
    binary_name = currentProgram.getName()
    output_filename = "{}_analysis.json".format(binary_name)
    
    output_path = os.path.join(os.path.expanduser("~"), output_filename)
    
    try:
        with open(output_path, "w") as f:
            json.dump(results, f, indent=4)
        print("SUCCES : {} fonctions analysees.".format(count))
        print("Fichier exporte ici : {}".format(output_path))
    except Exception as e:
        print("ERREUR lors de l'ecriture du fichier : {}".format(str(e)))

if __name__ == "__main__":
    run_analysis()
