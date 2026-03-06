import socket
import time
import csv
import os
from parser import ModbusTCP
from mutator import MutationEngine

def run_fuzzer(target_ip="127.0.0.1", target_port=5020, iterations=100):
    if not os.path.exists('logs'): os.makedirs('logs')
    
    base_pkt = ModbusTCP(func_code=3) / b"\x00\x00\x00\x05"
    engine = MutationEngine(base_pkt)
    
    # Préparation du fichier de log
    log_file = open('logs/fuzz_results.csv', 'w', newline='')
    logger = csv.writer(log_file)
    logger.writerow(['Iteration', 'Payload_Hex', 'Status', 'Response_Hex'])

    print(f"[*] Fuzzing en cours... Check logs/fuzz_results.csv")

    for i in range(iterations):
        mutated_pkt = engine.mutate()
        payload = bytes(mutated_pkt)
        status = "Success"
        res_hex = ""

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, target_port))
            s.send(payload)
            
            response = s.recv(1024)
            res_hex = response.hex()
            s.close()
        except socket.timeout:
            status = "Timeout (Potential DoS)"
        except Exception as e:
            status = f"Error: {type(e).__name__}"
        
        # On logue tout
        logger.writerow([i, payload.hex(), status, res_hex])

    log_file.close()
    print("[*] Terminé. Analyse les logs pour voir comment le serveur a réagi !")

if __name__ == "__main__":
    run_fuzzer()
