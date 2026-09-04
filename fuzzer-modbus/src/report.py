import csv
from collections import Counter

def _is_modbus_exception(response_hex: str) -> bool:
    """A Modbus exception response sets the high bit of the function code
    byte, which sits at byte offset 7 of the MBAP+PDU frame (2 trans_id +
    2 proto_id + 2 length + 1 unit_id). Checking that specific byte avoids
    false positives from '83' appearing anywhere else in the hex dump."""
    if len(response_hex) < 16:
        return False
    func_code_byte = response_hex[14:16]
    return int(func_code_byte, 16) & 0x80 != 0


def generate_report(logfile='logs/fuzz_results.csv'):
    stats = Counter()
    error_types = Counter()
    exceptions = 0
    success_clean = 0

    print("--- Rapport d'Analyse du Fuzzing ---")

    with open(logfile, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            stats[row['Status']] += 1

            if row['Status'].startswith('Error:'):
                error_types[row['Status'].removeprefix('Error: ')] += 1
            elif _is_modbus_exception(row['Response_Hex']):
                exceptions += 1
            elif row['Status'] == 'Success':
                success_clean += 1

    total_crashes = sum(error_types.values())

    print(f"Nombre total de tests : {sum(stats.values())}")
    print(f"✅ Paquets acceptés (réponse normale) : {success_clean}")
    print(f"⚠️ Erreurs gérées (exception Modbus, bit haut du code fonction) : {exceptions}")
    print(f"❌ Crashs / erreurs de connexion détectés : {total_crashes}")
    for err_name, count in error_types.most_common():
        print(f"    - {err_name}: {count}")
    print(f"⏳ Timeouts (DoS potentiel) : {stats['Timeout (Potential DoS)']}")
    print("------------------------------------")

if __name__ == "__main__":
    generate_report()
