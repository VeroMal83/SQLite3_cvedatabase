import sqlite3
import csv
import os as ops

# Updated database location
DB_FILE = ops.path.join(user_home, ".local", "path", "to", "database")

RELEVANT_COLUMNS = {
    'CWE-ID': 'cwe_id',
    'Name': 'name',
    'Description': 'description',
    'Extended Description': 'extended_description',
    'Likelihood of Exploit': 'likelihood_of_exploit',
    'Common Consequences': 'common_consequences',
    'Potential Mitigations': 'potential_mitigations',
    'Observed Examples': 'observed_examples',
    'Exploitation Factors': 'exploitation_factors',
    'Modes Of Introduction': 'modes_of_introduction',
    'Related Weaknesses': 'related_weaknesses',
    'Applicable Platforms': 'applicable_platforms',
    'Related Attack Patterns': 'related_attack_patterns',
    'Taxonomy Mappings': 'taxonomy_mappings',
}

def create_database():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cwe_weaknesses (
            cwe_id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            extended_description TEXT,
            likelihood_of_exploit TEXT,
            common_consequences TEXT,
            potential_mitigations TEXT,
            observed_examples TEXT,
            exploitation_factors TEXT,
            modes_of_introduction TEXT,
            related_weaknesses TEXT,
            applicable_platforms TEXT,
            related_attack_patterns TEXT,
            taxonomy_mappings TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_data(csv_path):
    if not os.path.isfile(csv_path):
        print(f"[!] File not found: {csv_path}")
        return

    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        count = 0
        for row in reader:
            data = {}
            for csv_field, db_field in RELEVANT_COLUMNS.items():
                value = row.get(csv_field, "").strip()
                if value:
                    if db_field == 'cwe_id' and not value.startswith("CWE-"):
                        value = f"CWE-{value}"
                    data[db_field] = value

            if not data.get('cwe_id'):
                continue

            columns = ', '.join(data.keys())
            placeholders = ', '.join(['?'] * len(data))
            values = list(data.values())

            try:
                c.execute(f"INSERT OR REPLACE INTO cwe_weaknesses ({columns}) VALUES ({placeholders})", values)
                count += 1
            except Exception as e:
                print(f"[!] Failed to insert {data.get('cwe_id', '[unknown]')}: {e}")

        conn.commit()
        conn.close()
        print(f"[+] Inserted {count} records.")

def query_cwe(cwe_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM cwe_weaknesses WHERE cwe_id = ?", (cwe_id,))
    result = c.fetchone()
    conn.close()
    if not result:
        print(f"[-] CWE-ID {cwe_id} not found.")
        return

    print(f"\n[+] CWE Entry for {cwe_id}:\n")
    for i, col in enumerate(RELEVANT_COLUMNS.values()):
        val = result[i]
        if val:
            print(f"{col.upper()}:")
            print(val)
            print("-" * 144)

def main_menu():
    create_database()

    while True:
        print("\n=== CWE Database CLI ===")
        print("1. Load data from CSV")
        print("2. Query CWE-ID")
        print("3. Exit")

        choice = input("Select an option [1-3]: ").strip()

        if choice == '1':
            path = input("Enter path to CSV file: ").strip()
            insert_data(path)
        elif choice == '2':
            cwe = input("Enter CWE-ID (e.g. CWE-79): ").strip().upper()
            if not cwe.startswith("CWE-"):
                cwe = f"CWE-{cwe}"
            query_cwe(cwe)
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print("Invalid option. Try again.")

if __name__ == '__main__':
    main_menu()

