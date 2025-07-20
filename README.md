phishing-triage-lab
SOC Alert Lifecycle simulation: phishing email analysis, threat triage, and IR documentation.

🔍 Features

Regex-based detection for phishing emails

Color-coded, human-friendly terminal output

Dynamically resolves log file path (no hardcoded paths)

Detects common obfuscations (e.g., netfl1x, amaz0n, secure-check, dropbox-login)

Tags MITRE ATT&CK techniques based on matched patterns

Exports findings to JSON for downstream analysis

Insight script reveals phishing trends and target patterns

Supports both CSV and JSON email log formats

🧠 Log Parser Scripts
This lab now supports both CSV and JSON log formats, with separate parsers for each.

📂 CSV Parser – csv_sslp.py
Parses phishing email records from a CSV-formatted mail log. Detects suspicious patterns, maps MITRE techniques, and exports alerts.

File: scripts/csv_sslp.py
To Run: python scripts/csv_sslp.py
Input: artifacts/mail_logs.csv
Output: artifacts/suspicious_emails.json

📂 JSON Parser – json_sslp.py (stubbed)
Parses structured phishing records in JSON format. Currently a placeholder for enhanced metadata-aware detection.

File: scripts/json_sslp.py
To Run: python scripts/json_sslp.py
Input: artifacts/mail_logs.json
Status: 🚧 Parser logic to be implemented

📊 Analyzer Script
This script ingests the exported suspicious email dataset and reveals threat trends by:

Identifying top sender domains

Sorting attack volume by MITRE technique

Ranking most-targeted users in your environment

File: scripts/analyzer.py
To Run: python scripts/analyzer.py
Output: Structured insight from suspicious_emails.json

🧪 Mail Log Generator
Interactive CLI script to generate realistic phishing and benign emails at scale. Supports custom MITRE tags and output format selection.

File: scripts/generate_mail_logs.py
To Run: python scripts/generate_mail_logs.py

User can specify:

Email volume (10–1000)

% phishing (1–5%)

MITRE techniques used

Output format: CSV or JSON

Difficulty level (stubbed)
