import csv

attack_defend = 'csv/ATTACK_DEFEND.csv'

def get_attack_defend_mapping(attack_ids):
    results = []

    attack_ids = list(set(attack_ids))

    with open(attack_defend, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if row[0] in attack_ids and row[2]:
                entries = row[2].strip(':').split('::::')
                for entry in entries:
                    parts = entry.split(':')
                    results.append({
                        "attack_id": row[0],
                        "d3fend_id": parts[0],
                        "d3fend_name": parts[1]
                    })
    return results
