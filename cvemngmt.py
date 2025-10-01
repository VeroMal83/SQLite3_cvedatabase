# cvemngmt.py
import sqlite3
import os as ops
import getpass
import logging
import re
from logging.handlers import RotatingFileHandler
import bcrypt

# ---------------- Paths ----------------
user_home = ops.path.expanduser("~")
DB_DIR = ops.path.join(user_home, ".local", "path", "to", "database")
DB_FILE = ops.path.join(DB_DIR, "cve.db")

log_directory = ops.path.join(user_home, ".local", "path", "to", "logs")
ops.makedirs(log_directory, exist_ok=True)

log_file = ops.path.join(log_directory, "cve.log")

# ---------------- Logging ----------------
logger = logging.getLogger("cvemngmt")
logger.setLevel(logging.INFO)

if not logger.handlers:
    log_handler = RotatingFileHandler(log_file, maxBytes=100000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

# ---------------- Utility Functions ----------------
def sanitize_input(input_str):
    return re.sub(r"[^\w\s-.:/]", "", input_str).strip()

def get_stored_password_hash():
    file_path = ops.path.join(user_home, ".local", "path", "to", "password", "file")
    if ops.path.exists(file_path):
        with open(file_path, "r") as file:
            return file.read().strip()
    return None

def check_password():
    password = getpass.getpass("Enter password: ")
    stored_hash = get_stored_password_hash()
    if stored_hash:
        if bcrypt.checkpw(password.encode(), stored_hash.encode()):
            print("ACCESS GRANTED.")
            return True
        else:
            print("ACCESS DENIED.")
    else:
        print("No password set. ACCESS DENIED.")
    return False

# ---------------- Database ----------------
def initialize_database():
    ops.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY,
        cve TEXT,
        description TEXT,
        os TEXT,
        server TEXT,
        version TEXT,
        assigner TEXT,
        cwe_id TEXT,
        vector_string TEXT,
        cvss_score REAL,
        severity TEXT,
        exploitability_score REAL,
        impact_score REAL,
        user_interaction TEXT,
        privilege_escalation TEXT,
        cpe TEXT,
        published_date TEXT,
        last_modified_date TEXT,
        references_json TEXT
    )
    """)
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_FILE}\n")

def insert_cve(conn, user, **fields):
    cursor = conn.cursor()
    keys = ", ".join(fields.keys())
    placeholders = ", ".join("?" for _ in fields)
    query = f"INSERT INTO cves ({keys}) VALUES ({placeholders})"
    cursor.execute(query, tuple(fields.values()))
    conn.commit()
    logger.info(f"User {user} inserted CVE {fields.get('cve')}")
    print(f"CVE {fields.get('cve')} added successfully.")

def update_cve(conn, user, cve, **kwargs):
    cursor = conn.cursor()
    update_fields = [f"{field} = ?" for field, val in kwargs.items() if val is not None]
    update_values = [val for val in kwargs.values() if val is not None]

    if update_fields:
        update_values.append(cve)
        query = f"UPDATE cves SET {', '.join(update_fields)} WHERE cve = ?"
        cursor.execute(query, update_values)
        conn.commit()
        logger.info(f"User {user} updated CVE '{cve}' with {update_fields}")
        print(f"CVE '{cve}' updated successfully.")
    else:
        print("No fields provided for update.")

def query_database(conn, table_name="cves", column_name=None, value=None):
    cursor = conn.cursor()
    query = f"SELECT * FROM {table_name}"
    if column_name and value:
        query += f" WHERE {column_name} = ?"
        cursor.execute(query, (value,))
    else:
        cursor.execute(query)
    rows = cursor.fetchall()
    column_names = [desc[0] for desc in cursor.description]
    return rows, column_names

# ---------------- Main ----------------
def main():
    if not check_password():
        logger.warning("Access denied for CVE management.")
        return

    initialize_database()
    conn = sqlite3.connect(DB_FILE)
    user = getpass.getuser()

    while True:
        print("\nOptions:")
        print("1. Add CVE")
        print("2. Query Database")
        print("3. Update CVE")
        print("4. CWE Query")
        print("5. Exit")

        choice = input("Choose an option (1-5): ")

        if choice == "1":
            fields = {
                "id": input("ID (UUID or string): "),
                "cve": input("CVE: "),
                "description": input("Description: "),
                "os": input("OS: ") or None,
                "server": input("Server: ") or None,
                "version": input("Version: ") or None,
                "assigner": input("Assigner: ") or None,
                "cwe_id": input("CWE ID: ") or None,
                "vector_string": input("Vector string: ") or None,
                "cvss_score": input("CVSS score: ") or None,
                "severity": input("Severity: ") or None,
                "exploitability_score": input("Exploitability score: ") or None,
                "impact_score": input("Impact score: ") or None,
                "user_interaction": input("User interaction: ") or None,
                "privilege_escalation": input("Privilege escalation: ") or None,
                "cpe": input("CPE: ") or None,
                "published_date": input("Published date: ") or None,
                "last_modified_date": input("Last modified date: ") or None,
                "references_json": input("References (JSON): ") or None,
            }
            # Convert floats safely
            for key in ["cvss_score", "exploitability_score", "impact_score"]:
                if fields[key]:
                    try:
                        fields[key] = float(fields[key])
                    except ValueError:
                        fields[key] = None
            insert_cve(conn, user, **fields)

        elif choice == "2":
            rows, cols = query_database(conn)
            print("-" * 144)
            for row in rows:
                for col, val in zip(cols, row):
                    print(f"{col}: {val}")
                print("-" * 144)

        elif choice == "3":
            cve = input("Enter CVE to update: ")
            updates = {
                "description": input("New description (or blank): ") or None,
                "os": input("New OS (or blank): ") or None,
                "server": input("New server (or blank): ") or None,
                "version": input("New version (or blank): ") or None,
                "assigner": input("New assigner (or blank): ") or None,
                "cwe_id": input("New CWE ID (or blank): ") or None,
                "vector_string": input("New vector string (or blank): ") or None,
                "cvss_score": input("New CVSS score (or blank): ") or None,
                "severity": input("New severity (or blank): ") or None,
                "exploitability_score": input("New exploitability score (or blank): ") or None,
                "impact_score": input("New impact score (or blank): ") or None,
                "user_interaction": input("New user interaction (or blank): ") or None,
                "privilege_escalation": input("New privilege escalation (or blank): ") or None,
                "cpe": input("New CPE (or blank): ") or None,
                "published_date": input("New published date (or blank): ") or None,
                "last_modified_date": input("New last modified date (or blank): ") or None,
                "references_json": input("New references JSON (or blank): ") or None,
            }
            # Cast floats
            for key in ["cvss_score", "exploitability_score", "impact_score"]:
                if updates[key]:
                    try:
                        updates[key] = float(updates[key])
                    except ValueError:
                        updates[key] = None
            update_cve(conn, user, cve, **updates)

        elif choice == "4":
            import cwedbupload
            cwedbupload.main_menu()

        elif choice == "5":
            conn.close()
            break

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()

