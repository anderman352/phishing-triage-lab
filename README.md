# phishing-triage-lab
SOC Alert Lifecycle simulation: phishing email analysis, threat triage, and IR documentation.

---

## 🔍 Features

- Regex-based detection for phishing emails  
- Color-coded, human-friendly terminal output  
- Dynamically resolves log file path (no hardcoded paths)  
- Detects common obfuscations (e.g., `netfl1x`, `amaz0n`, `secure-check`, `dropbox-login`)  
- Tags MITRE ATT&CK techniques based on matched patterns  
- Exports findings to JSON for downstream analysis  
- Insight script reveals phishing trends and target patterns

---

## 🧠 Log Parser Scripts

This lab now supports both CSV and JSON log formats, with separate parsers for each.

---

### 📂 CSV Parser – `csv_sslp.py`

Parses phishing email records from a CSV-formatted mail log. Detects suspicious patterns, maps MITRE techniques, and exports alerts.

📁 File:
scripts/csv_sslp.py

bash
Copy
Edit

🧪 To Run:
```bash
python scripts/csv_sslp.py
Input:

bash
Copy
Edit
artifacts/mail_logs.csv
Output:

bash
Copy
Edit
artifacts/suspicious_emails.json
📂 JSON Parser – json_sslp.py (stubbed)
Parses structured phishing records in JSON format. Currently a placeholder for enhanced metadata-aware detection.

📁 File:

bash
Copy
Edit
scripts/json_sslp.py
🧪 To Run:

bash
Copy
Edit
python scripts/json_sslp.py
Input:

bash
Copy
Edit
artifacts/mail_logs.json
Status:

pgsql
Copy
Edit
🚧 Parser logic to be implemented
