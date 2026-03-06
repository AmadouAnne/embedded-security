#!/usr/bin/env python3
"""
scada_monitor.py -- Tableau de bord SCADA
Lit les registres du PLC en boucle et affiche l'etat du systeme.
Ne lance PAS de serveur -- se connecte au plc_sim.py existant.
"""
import time
from pymodbus.client import ModbusTcpClient

def monitor(host="127.0.0.1", port=5020, interval=1.0):
    client = ModbusTcpClient(host, port=port)

    if not client.connect():
        print("[!] Impossible de se connecter au PLC -- plc_sim.py est-il lance ?")
        return

    print("[+] SCADA Monitor connecte au PLC sur 127.0.0.1:5020")
    print("-" * 65)
    print(f"{'Temps':>7} {'Niveau':>8} {'Barre':<22} {'Pompe':>6} {'Alarme':>7}  Seuils")
    print("-" * 65)

    start = time.time()
    try:
        while True:
            regs = client.read_holding_registers(1, count=5)

            if regs.isError():
                print("[!] Erreur lecture -- PLC ne repond plus !")
                time.sleep(interval)
                continue

            level  = regs.registers[0]
            pump   = regs.registers[1]
            alarm  = regs.registers[2]
            sp_H   = regs.registers[3]
            sp_L   = regs.registers[4]

            elapsed   = time.time() - start
            bar       = "#" * (level // 5) + "." * (20 - level // 5)
            pump_str  = "ON " if pump  else "OFF"
            alarm_str = "ALARME" if alarm else "OK    "

            print(f"{elapsed:7.1f}s {level:7}% [{bar}] {pump_str:>6} {alarm_str}  spH={sp_H} spL={sp_L}")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[+] Monitor arrete")
        client.close()

if __name__ == "__main__":
    monitor()
