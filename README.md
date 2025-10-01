SecurityRecon: CVE & CWE Management + ML Risk Prediction
📘 Overview

⚠️ Note: SecurityRecon is designed as an educational tool. Users must modify scripts and paths to match their own system configuration.

SecurityRecon is a beginner-friendly Python project designed to manage CVE (Common Vulnerabilities and Exposures) and CWE (Common Weakness Enumeration) data using SQLite. It offers a hands-on approach to learning database interactions, data preprocessing, and machine learning model training.

Key Features

CVE & CWE Management: Add, query, and update CVE and CWE records in a SQLite database.

Data Import: Load vulnerability and weakness data from JSON files.

Machine Learning Integration: Train and utilize models to predict CVE risk levels.

Command-Line Interface (CLI): Interact with the system via a user-friendly CLI.

⚙ Installation

git clone https://github.com/VeroMal83/SQLite3_cvedatabase.git

cd SQLite3_cvedatabase
pip install -r requirements.txt

▶ Quickstart

Run the main application:

python SecurityRecon.py

This will launch the CLI interface where you can manage CVE and CWE records and interact with the machine learning models.

📂 Project Structure

SecurityRecon.py: Main CLI launcher for the application.

cvemngmt.py: Manage CVE records in the SQLite database.

cwedbupload.py: Upload CWE records from JSON files.

cvedbupload.py: Upload CVE records from JSON files.

cvetrain.py: Train a machine learning model to predict CVE risk levels.

modelquery.py: Query the pre-trained CVE risk prediction model.

requirements.txt: Python dependencies for the project.

README.md: Project documentation.

📦 Dependencies

numpy

pandas

scikit-learn

joblib

pyinstaller (optional)

matplotlib (optional)

⚠️ Usage Notes

Educational Purpose: This project is for learning and demonstration only. It is not a ready-to-run production program. Users must review, understand, and adjust the scripts to suit their own system paths, configurations, and Python environments.

Machine Learning Training: Training models can be resource-intensive. GPU-equipped systems are strongly recommended.

Not for Production Security Auditing: The project demonstrates concepts in CVE/CWE handling, database management, and ML integration. It is not intended for operational deployment.
