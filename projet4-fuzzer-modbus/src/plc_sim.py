#!/usr/bin/env python3
"""
plc_sim.py -- Digital Twin : simulation PLC + serveur Modbus TCP
Simule un systeme de controle de niveau d eau avec logique PLC reelle.

Registres Modbus (Holding Registers) :
  [0] water_level  : niveau eau en % (0-100)  -- lecture seule
  [1] pump_state   : etat pompe (0=OFF, 1=ON)  -- lecture seule
  [2] alarm        : alarme niveau bas (0=OK, 1=ALARME)
  [3] setpoint_H   : seuil haut (defaut 80)    -- ecriture possible
  [4] setpoint_L   : seuil bas  (defaut 20)    -- ecriture possible
"""

import threading
import time
import random
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusDeviceContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

# Seuils de securite
HH = 90   # Haut-Haut : danger debordement
LL = 10   # Bas-Bas   : danger cavitation pompe

class PLCSimulator:
    def __init__(self):
        # Etat initial du systeme
        self.water_level  = 50.0   # Niveau initial : 50%
        self.pump_state   = 0      # Pompe arretee au demarrage
        self.alarm        = 0      # Pas d alarme
        self.setpoint_H   = 80     # Seuil haut normal
        self.setpoint_L   = 20     # Seuil bas normal

        # Datastore Modbus -- 5 registres
        init_values = [
            int(self.water_level),   # [0] water_level
            self.pump_state,         # [1] pump_state
            self.alarm,              # [2] alarm
            self.setpoint_H,         # [3] setpoint_H
            self.setpoint_L,         # [4] setpoint_L
        ]

        self.data_block = ModbusSequentialDataBlock(0, init_values + [0]*95)
        self.slave = ModbusDeviceContext(hr=self.data_block)
        self.context = ModbusServerContext(devices=self.slave, single=True)

    def plc_logic(self):
        """
        Boucle principale du PLC -- tourne toutes les 500ms.
        Lit les setpoints depuis les registres (modifiables par SCADA ou fuzzer).
        Applique la logique de controle.
        Ecrit les resultats dans les registres.
        """
        while True:
            # Lit les setpoints depuis les registres Modbus
            # (le fuzzer peut les avoir modifies !)
            sp_H = self.data_block.getValues(3, 1)[0]
            sp_L = self.data_block.getValues(4, 1)[0]

            # Logique pompe : hysteresis simple
            # Si niveau depasse seuil haut -> pompe OFF
            # Si niveau descend sous seuil bas -> pompe ON
            if self.water_level >= sp_H:
                self.pump_state = 0   # Pompe OFF -- assez d eau
            elif self.water_level <= sp_L:
                self.pump_state = 1   # Pompe ON  -- besoin d eau

            # Simulation physique :
            # Pompe ON  -> niveau monte de 0.5% par cycle + bruit
            # Pompe OFF -> niveau descend de 0.3% par cycle + bruit
            if self.pump_state == 1:
                self.water_level += 0.5 + random.uniform(-0.1, 0.1)
            else:
                self.water_level -= 0.3 + random.uniform(-0.1, 0.1)

            # Clamp entre 0 et 100
            self.water_level = max(0.0, min(100.0, self.water_level))

            # Alarmes
            self.alarm = 1 if self.water_level <= LL else 0

            # Detection seuils critiques
            if self.water_level >= HH:
                print(f"[!!!] ALARME HH : niveau {self.water_level:.1f}% -- DEBORDEMENT")
            if self.water_level <= LL:
                print(f"[!!!] ALARME LL : niveau {self.water_level:.1f}% -- DANGER CAVITATION")

            # Ecrit les valeurs dans les registres Modbus
            self.data_block.setValues(0, [
                int(self.water_level),
                self.pump_state,
                self.alarm,
                sp_H,
                sp_L,
            ])

            # Affichage console
            pump_str = "ON " if self.pump_state else "OFF"
            bar = "#" * int(self.water_level / 5) + "." * (20 - int(self.water_level / 5))
            print(f"[PLC] Niveau: {self.water_level:5.1f}% [{bar}] Pompe:{pump_str} spH:{sp_H} spL:{sp_L} Alarme:{self.alarm}")

            time.sleep(0.5)

    def run(self):
        """Lance le PLC en thread + le serveur Modbus."""
        # Thread PLC -- tourne en arriere plan
        plc_thread = threading.Thread(target=self.plc_logic, daemon=True)
        plc_thread.start()

        print("[+] Digital Twin PLC demarre")
        print("[+] Serveur Modbus TCP sur 127.0.0.1:5020")
        print("[+] Registres : [0]=level [1]=pump [2]=alarm [3]=spH [4]=spL")
        print("[+] CTRL+C pour arreter")
        print("-" * 60)

        StartTcpServer(context=self.context, address=("127.0.0.1", 5020))

if __name__ == "__main__":
    sim = PLCSimulator()
    sim.run()
