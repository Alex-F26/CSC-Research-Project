import csv

capec_attack = 'csv/CAPEC_ATTACK.csv'

def get_capec_attack_mapping(capec_ids):
    taxonomy = []

    with open(capec_attack, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        for row in reader:
            if row[0] in capec_ids and row[18]:
                entries = row[18].strip(':').split('::::')

                for entry in entries:
                    parts = entry.split(':')

                    if 'ATTACK' in parts:
                        taxonomy.append({
                            "capec_id": row[0],
                            "type": "ATT&CK",
                            "id": parts[3],
                            "name": parts[5]
                        })

                    elif 'OWASP Attacks' in parts:
                        taxonomy.append({
                            "capec_id": row[0],
                            "type": "OWASP",
                            "name": parts[3]
                        })

                    elif 'WASC' in parts:
                        taxonomy.append({
                            "capec_id": row[0],
                            "type": "WASC",
                            "id": parts[3],
                            "name": parts[5]
                        })

    return taxonomy
