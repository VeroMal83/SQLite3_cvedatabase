import json
import sqlite3
import sys
import os

def create_table(cursor):
    # Create the table if it doesn't exist.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve TEXT,
            description TEXT,
            os TEXT,
            server TEXT,
            version TEXT,
            risk_level TEXT
        )
    ''')

def insert_cve(cursor, cve_id, description):
    # Insert a record with empty placeholders for os, server, version, and risk_level.
    cursor.execute('''
        INSERT INTO cves (cve, description, os, server, version, risk_level)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (cve_id, description, "", "", "", ""))

def parse_and_upload(json_file, db_file):
    # Connect to the SQLite database (or create it if it doesn't exist).
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    create_table(cursor)
    conn.commit()

    # Load the JSON data
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        sys.exit(1)

    # Iterate through the CVE items
    cve_items = data.get("CVE_Items", [])
    for item in cve_items:
        cve_data = item.get("cve", {})
        cve_meta = cve_data.get("CVE_data_meta", {})
        cve_id = cve_meta.get("ID", "UNKNOWN")

        # Get the English description from the JSON structure.
        description = ""
        for desc in cve_data.get("description", {}).get("description_data", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        insert_cve(cursor, cve_id, description)

    conn.commit()
    conn.close()
    print(f"Uploaded {len(cve_items)} CVE records to the database.")

def main():
    print("=== CVE JSON to Database Uploader ===")
    json_file = input("Enter the path to the CVE JSON file: ").strip()
    db_file = input("Enter the path to your SQLite database file: ").strip()

    # Check if the JSON file exists
    if not os.path.isfile(json_file):
        print(f"Error: The JSON file '{json_file}' does not exist.")
        sys.exit(1)

    print(f"Using JSON file: {json_file}")
    print(f"Using database file: {db_file}")
    
    parse_and_upload(json_file, db_file)

if __name__ == "__main__":
    main()

