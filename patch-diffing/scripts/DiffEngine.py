import json
import os

# Configuration des chemins vers tes fichiers dans le dossier analysis
V33_PATH = "../analysis/libuclient_v33.json"
V35_PATH = "../analysis/libuclient_v35.json"

def load_data(filename):
    if not os.path.exists(filename):
        print(f"[-] Erreur : {filename} introuvable.")
        return None
    with open(filename, 'r') as f:
        # On indexe par nom pour une recherche rapide
        return {item['name']: item for item in json.load(f)}

def compare():
    v33 = load_data(V33_PATH)
    v35 = load_data(V35_PATH)
    
    if not v33 or not v35:
        return

    print("\n" + "="*70)
    print("      RAPPORT DE DIFFING SÉMANTIQUE : libuclient v33 vs v35      ")
    print("="*70 + "\n")
    
    modified = []
    removed = []
    added = [name for name in v35 if name not in v33]

    for name, data_v33 in v33.items():
        if name in v35:
            data_v35 = v35[name]
            
            # Comparaison multi-critères : Hash des opcodes OU Taille
            # Si la taille change, le code a forcément bougé.
            if data_v33['opcode_hash'] != data_v35['opcode_hash'] or data_v33['size'] != data_v35['size']:
                modified.append((name, data_v33, data_v35))
        else:
            removed.append(name)

    # Affichage des résultats
    if modified:
        print(f"[!] {len(modified)} FONCTION(S) MODIFIÉE(S) TROUVÉE(S) :\n")
        for name, d33, d35 in modified:
            print(f"--> {name}")
            print(f"    [v33] Taille: {d33['size']} bytes | Hash: {d33['opcode_hash'][:12]}...")
            print(f"    [v35] Taille: {d35['size']} bytes | Hash: {d35['opcode_hash'][:12]}...")
            
            # Analyse spécifique pour les "no_instructions_found"
            if d33['opcode_hash'] == "no_instructions_found":
                print("    /!\\ Attention : Ghidra n'a pas pu désassembler cette fonction correctement.")
            print("-" * 50)
    else:
        print("[+] Aucune modification détectée dans le code des fonctions.")

    if added:
        print(f"\n[+] {len(added)} NOUVELLE(S) FONCTION(S) :")
        for name in added: print(f"    - {name}")

    if removed:
        print(f"\n[-] {len(removed)} FONCTION(S) SUPPRIMÉE(S) :")
        for name in removed: print(f"    - {name}")

    print("\n" + "="*70)

if __name__ == "__main__":
    compare()
