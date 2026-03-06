import csv
from collections import Counter

def generate_report(logfile='logs/fuzz_results.csv'):
    stats = Counter()
    exceptions = 0
    success_clean = 0
    
    print("--- Rapport d'Analyse du Fuzzing ---")
    
    with open(logfile, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            stats[row['Status']] += 1
            if '83' in row['Response_Hex']: # Code d'erreur Modbus
                exceptions += 1
            elif row['Status'] == 'Success':
                success_clean += 1

    print(f"Nombre total de tests : {sum(stats.values())}")
    print(f"✅ Paquets acceptés : {success_clean}")
    print(f"⚠️ Erreurs gérées (Exceptions) : {exceptions}")
    print(f"❌ Crashs détectés : {stats['ConnectionRefusedError']}")
    print(f"⏳ Timeouts (DoS potentiel) : {stats['Timeout (Potential DoS)']}")
    print("------------------------------------")

if __name__ == "__main__":
    generate_report()
