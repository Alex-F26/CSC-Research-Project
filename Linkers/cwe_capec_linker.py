import csv

cwe_capec = 'csv/CWE_CAPEC.csv'

def get_cwe_capec_mapping(cwe_ids):
    capec_results = []

    with open(cwe_capec, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            for cwe in cwe_ids:
                cwe_num = ''.join(filter(str.isdigit, cwe))
                if row[0] == cwe_num and row[21]:
                    capecs = row[21].strip('::').split('::')
                    for capec in capecs:
                        capec_results.append({
                            "cwe_id": cwe,
                            "capec_id": capec
                        })
    return capec_results
