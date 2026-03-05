import json
from typing import Dict, List

# Chemins relatifs
V1_JSON = "../analysis/libuclient_v33.json"
V2_JSON = "../analysis/libuclient_v35.json"
OUTPUT_JSON = "../reports/libuclient_diff.json"

def load_json(filename: str) -> Dict[str, dict]:
    """Charge le JSON et retourne un dictionnaire {fonction_name: data}"""
    with open(filename, "r") as f:
        data = json.load(f)
    return {f["name"]: f for f in data}

def jaccard_similarity(opcodes1: List[str], opcodes2: List[str]) -> float:
    """Similitude Jaccard entre deux listes d'opcodes"""
    set1 = set(opcodes1)
    set2 = set(opcodes2)
    if not set1 and not set2:
        return 1.0
    return len(set1 & set2) / len(set1 | set2)

def analyze_diff(v1: Dict[str, dict], v2: Dict[str, dict], threshold: float = 0.8) -> dict:
    """Analyse les fonctions ajoutées, supprimées et modifiées"""
    result = {"added": [], "removed": [], "modified": []}

    all_funcs = set(v1.keys()) | set(v2.keys())

    for func in all_funcs:
        if func not in v1:
            result["added"].append(func)
        elif func not in v2:
            result["removed"].append(func)
        else:
            # Comparaison via Jaccard sur opcodes
            hash1 = v1[func].get("opcode_hash", "")
            hash2 = v2[func].get("opcode_hash", "")
            if hash1 != hash2:  # simple comparaison si pas d'opcodes détaillés
                result["modified"].append(func)
            # Si tu veux, tu peux utiliser jaccard_similarity avec une vraie liste d'opcodes

    return result

def main():
    v1 = load_json(V1_JSON)
    v2 = load_json(V2_JSON)

    diff_result = analyze_diff(v1, v2, threshold=0.8)

    # Sauvegarde dans reports/
    with open(OUTPUT_JSON, "w") as f:
        json.dump(diff_result, f, indent=2)

    print(f"Added: {len(diff_result['added'])}, Removed: {len(diff_result['removed'])}, Modified: {len(diff_result['modified'])}")

if __name__ == "__main__":
    main()
