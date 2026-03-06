#!/usr/bin/env python3
import random
import copy
from scapy.all import *

class MutationEngine:
    def __init__(self, base_pkt):
        """
        Le moteur prend un paquet Scapy 'propre' comme base 
        et va le cloner pour lui appliquer des corruptions.
        """
        self.base_pkt = base_pkt

    def bit_flip(self, data):
        """Inverse un bit au hasard dans les données (corruption binaire)."""
        if not data: return data
        list_data = list(data)
        idx = random.randint(0, len(list_data) - 1)
        # XOR avec un bit aléatoire (1 << 0-7)
        list_data[idx] = bytes([list_data[idx] ^ (1 << random.randint(0, 7))])[0]
        return bytes(list_data)

    def extreme_values(self):
        """Valeurs numériques limites souvent mal gérées par les buffers."""
        return [0x00, 0xFF, 0xFE, 0x01, 0x7F]

    def mutate(self):
        """Génère une mutation aléatoire en choisissant une stratégie."""
        # On travaille sur une copie pour ne pas détruire le paquet original
        mutated_pkt = copy.deepcopy(self.base_pkt)
        payload = bytes(mutated_pkt.payload)
        
        strategy = random.choice(["flip", "overflow", "extreme", "header_lie"])
        
        if strategy == "flip":
            # On corrompt un bit au hasard dans le PDU
            new_payload = self.bit_flip(payload)
            
        elif strategy == "overflow":
            # On envoie beaucoup plus de données que prévu (Buffer Overflow)
            new_payload = payload + b"A" * random.randint(100, 1000)
            
        elif strategy == "extreme":
            # On remplace les données par des valeurs limites (0, 255...)
            new_payload = bytes([random.choice(self.extreme_values())]) * len(payload)
            
        elif strategy == "header_lie":
            # STRATÉGIE AGRESSIVE : On ment sur le champ 'length' du header MBAP
            # On annonce une taille énorme (65535) ou minuscule (0)
            mutated_pkt.length = random.choice([0, 1, 500, 65535])
            new_payload = payload

        # On reconstruit le paquet avec la nouvelle charge utile
        mutated_pkt.remove_payload()
        return mutated_pkt / new_payload

# --- Section de Test ---
if __name__ == "__main__":
    # Import local du parser pour le test indépendant
    try:
        from parser import ModbusTCP
    except ImportError:
        # Si lancé depuis la racine du projet
        from src.parser import ModbusTCP

    # On forge un paquet standard : Lire 5 registres
    base = ModbusTCP(func_code=3) / b"\x00\x00\x00\x05"
    engine = MutationEngine(base)
    
    print("=== TEST DU MUTATION ENGINE ===")
    print("\n--- Paquet Original ---")
    base.show()
    
    print("\n--- Exemple de Paquet Muté ---")
    mutated = engine.mutate()
    mutated.show()
    print(f"\nHexadécimal : {bytes(mutated).hex()}")
