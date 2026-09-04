#!/usr/bin/env python3
from scapy.all import Packet, ShortField, ByteField, ConditionalField

class ModbusTCP(Packet):
    name = "ModbusTCP"
    fields_desc = [
        ShortField("trans_id", 1),     # Identifiant de transaction
        ShortField("proto_id", 0),     # Toujours 0 pour Modbus
        ShortField("length", 6),       # Longueur (UnitID + PDU)
        ByteField("unit_id", 1),       # ID de l'esclave (souvent 1 ou 0)
        
        # PDU Simple pour le fuzzing
        ByteField("func_code", 3),     # Code fonction (ex: 3 = Read Holding Reg)
        # On laisse le reste en "payload" brut pour pouvoir muter n'importe quoi
    ]

# Petit test rapide de forgeage
if __name__ == "__main__":
    packet = ModbusTCP(func_code=3) / b"\x00\x00\x00\x05" # Demande 5 registres à partir de 0
    packet.show()
