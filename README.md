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

## 🧠 Log Parser Script

This Python script scans inbound email logs for phishing indicators using regular expressions and enriches each alert with MITRE ATT&CK tags.

### 📁 File
scripts/log_parser.py

shell
Copy
Edit

### ▶️ Example Output
🛑 Suspicious Emails Flagged by Regex Patterns:

Timestamp: 2025-07-17 08:12:00
Sender: admin@microsoft-support.co
To: david@company.com
Subject: Account Verification
URL: https://microsoft-security-check[.]com/login
MITRE: T1566.002 (Initial Access)
bash
Copy
Edit

### 🧪 To Run
From the root of the project folder:
```bash
python scripts/log_parser.py
Results are saved to:

bash
Copy
Edit
artifacts/suspicious_emails.json
📊 Analyzer Script
This script ingests the exported suspicious email dataset and reveals threat trends by:

Identifying top sender domains

Sorting attack volume by MITRE technique

Ranking most-targeted users in your environment

📁 File
scripts/analyzer.py
▶️ Example Output

Top 3 Sender Domains:
  microsoft-support.co: 4 emails
  hr-secureportal.com: 3 emails
  netfl1x-auth.io: 2 emails

Top 3 MITRE Techniques:
  T1566.002: 9 matches

Most Targeted Users:
  david@company.com: 5 phishing attempts

Analysis complete. Review the results above for insights into phishing trends.
Data source: artifacts/suspicious_emails.json
To Run
From the root of the project:
python scripts/analyzer.py
