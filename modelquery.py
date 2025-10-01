import sqlite3
import pandas as pd
import joblib
import os

# Define paths
user_home = os.path.expanduser("~")
DB_PATH = os.path.join(user_home, ".local", "path", "to", "database", "cve.db")
MODEL_PATH = os.path.join(user_home, ".local", "path", "to", "model", "cve_model.pkl")
VECTORIZER_PATH = os.path.join(user_home, ".local", "path", "to", "model", "cve_vectorizer.pkl")
LABEL_ENCODER_PATH = os.path.join(user_home, ".local", "path", "to", "model", "cve_encoder.pkl")

# Load model, vectorizer, and label encoder
def load_model_and_components():
    classifier = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    return classifier, vectorizer, label_encoder

# Use the model for prediction
def generate_report(cve_ids):
    classifier, vectorizer, label_encoder = load_model_and_components()

    with sqlite3.connect(DB_PATH) as conn:
        query = f"SELECT * FROM cves WHERE cve IN ({','.join(['?']*len(cve_ids))})"
        cve_data = pd.read_sql_query(query, conn, params=cve_ids)
    
    if cve_data.empty:
        print("No data found for this entry.")
        return

    # Vectorize the description for prediction
    X = vectorizer.transform(cve_data['description'].fillna(''))
    risk_levels = classifier.predict(X)
    
    # Transform predicted risk levels back to original labels
    cve_data['predicted_risk_level'] = label_encoder.inverse_transform(risk_levels)

    print("Report Generated for CVEs:")
    
    # Print results with 130 dashes between each entry
    print("-" * 144)
    for _, row in cve_data.iterrows():
        print(f"CVE: {row['cve']}")
        print(f"Description: {row['description']}")
        print(f"Predicted Risk Level: {row['predicted_risk_level']}")
        print("-" * 144)

# Main menu function
def main():
    while True:
        print("\nMenu:")
        print("1. Enter CVE numbers")
        print("2. Exit")
        
        choice = input("Enter your choice: ").strip()
        
        if choice == '1':
            cve_input = input("Enter CVE numbers separated by commas: ")
            cve_ids = [i.strip() for i in cve_input.split(',') if i.strip()]
            generate_report(cve_ids)
        
        elif choice == '2':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()

