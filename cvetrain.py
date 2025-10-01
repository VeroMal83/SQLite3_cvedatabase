import sqlite3
import pandas as pd
import numpy as np
import os
import joblib
import time
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report
from scipy.sparse import save_npz, load_npz

# Paths
user_home = os.path.expanduser("~")
DB_PATH = os.path.join(user_home, ".local", "path", "to", "database", "cve.db")
MODEL_PATH = os.path.join(user_home, ".local", "path", "to", "model", "cve_model.pkl")
VECTORIZER_PATH = os.path.join(user_home, ".local", "path", "to", "model", "cve_vectorizer.pkl")
LABEL_ENCODER_PATH = os.path.join(user_home, ".local", "path", "to", "model", "cve_encoder.pkl")
TFIDF_CACHE = os.path.join(user_home, ".local", "path", "to", "model", "model_matrix.npz")
TRAINING_LOG = os.path.join(user_home, ".local", "path", "to", "log", "model_log.txt")

# Load data
def load_data():
    with sqlite3.connect(DB_PATH) as conn:
        cves_df = pd.read_sql_query("SELECT * FROM cves", conn)
    return cves_df

# Preprocess data
def preprocess_data(df):
    df = df[df['description'].notna()]  # Remove rows with NaN in 'description'
    df = df[df['description'] != 'None']  # Remove rows with 'None' in 'description'
    df = df[df['description'] != '']  # Remove rows with empty descriptions
    return df

# Handle CPE data - Normalize and extract useful features
def process_cpe(cpe):
    if pd.isna(cpe) or cpe == 'None':
        return 'unknown', 'unknown', 'unknown'
    # Replace wildcards with 'any_' for uniformity
    cpe = cpe.replace('*', 'any')
    cpe_parts = cpe.split(":")
    
    if len(cpe_parts) < 5:
        return 'unknown', 'unknown', 'unknown'
    
    software_name = cpe_parts[2] if len(cpe_parts) > 2 else 'unknown'
    product_version = cpe_parts[3] if len(cpe_parts) > 3 else 'unknown'
    os_name = cpe_parts[4] if len(cpe_parts) > 4 else 'unknown'

    return software_name, product_version, os_name

# Combine textual data
def combine_textual_features(df):
    # Combine the 'description' and 'references_json' columns into one textual feature for vectorization
    df['references_combined'] = df['references_json'].apply(lambda x: ' '.join(eval(x)) if isinstance(x, str) else '')
    df['combined_text'] = df['description'] + ' ' + df['references_combined']
    
    # Process CPE data and create new columns for software name, version, and OS
    df[['software_name', 'product_version', 'os_name']] = df['cpe'].apply(lambda x: pd.Series(process_cpe(x)))
    
    return df

# Train the model
def train_model():
    cves_df = load_data()
    print(f"Loaded cves_df: {cves_df.shape}")

    # Preprocess data
    cves_df = preprocess_data(cves_df)

    # Combine text data and process CPE columns
    cves_df = combine_textual_features(cves_df)

    # Debug: Check if 'combined_text' column is populated
    print(f"Combined text column length: {len(cves_df['combined_text'])}")

    # Load or initialize vectorizer
    vectorizer = TfidfVectorizer(max_features=10000)
    X = vectorizer.fit_transform(cves_df['combined_text'])
    print(f"TF-IDF Matrix shape: {X.shape}")

    # Save vectorizer for future use
    joblib.dump(vectorizer, VECTORIZER_PATH)

    # Construct the labels for the combined data
    combined_labels = cves_df['severity'].fillna('UNKNOWN').values  # Handle missing severity data
    label_encoder = LabelEncoder()
    label_encoder.fit(combined_labels)
    y = label_encoder.transform(combined_labels)
    
    # Save label encoder for future use
    joblib.dump(label_encoder, LABEL_ENCODER_PATH)

    # Debug: Check the shape of X and y before training
    print(f"Features shape: {X.shape}")
    print(f"Labels shape: {len(y)}")

    # Initialize and train the model from scratch
    model = MLPClassifier(hidden_layer_sizes=(100,), max_iter=100, random_state=42)
    model.fit(X, y)

    # Save the trained model
    joblib.dump(model, MODEL_PATH)

    print("Training completed from scratch!")

# Evaluate model
def evaluate_model():
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)

    # Load combined data again and preprocess it
    cves_df = load_data()
    cves_df = preprocess_data(cves_df)

    # Combine text data and process CPE columns
    cves_df = combine_textual_features(cves_df)

    # Prepare the features (X) and labels (y)
    X = vectorizer.transform(cves_df['combined_text'])
    y = label_encoder.transform(cves_df['severity'].fillna('UNKNOWN'))  # Handle missing severity data

    # Debug: Check the shape of X and y before evaluation
    print(f"Features shape: {X.shape}")
    print(f"Labels shape: {len(y)}")

    y_pred = model.predict(X)
    print("Model Evaluation:")
    print(classification_report(y, y_pred))

# Log training time
def log_training_time():
    with open(TRAINING_LOG, "w") as f:
        f.write(str(time.time()))

# Get last training time
def get_last_training_time():
    if os.path.exists(TRAINING_LOG):
        with open(TRAINING_LOG, "r") as f:
            return float(f.read().strip())
    return None

# Main execution
def main():
    start_time = time.time()
    
    train_model()
    evaluate_model()
    log_training_time()

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Training completed in {elapsed_time:.2f} seconds.")

if __name__ == "__main__":
    main()

