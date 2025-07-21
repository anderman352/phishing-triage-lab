📁 phishing-triage-lab
Simulates a SOC alert lifecycle: generate realistic phishing emails, triage logs, flag threats, and document incident response.

🔍 Features
Realistic phishing logs w/ MITRE techniques & obfuscation

Cyrillic homoglyph support to simulate evasion tactics

Smart regex detection of sender, subject, and URLs

Unicode-safe parsing and formatted output

Summary reporting by domain and MITRE tactic

Colorized CLI alerts for quick triage

JSON export of flagged emails

🛠️ Scripts
Script	Purpose
generate_mail_logs.py	Create CSV logs (1–1000 emails, % phishing, MITRE-based)
csv_sslp.py	Parse CSV logs and flag suspicious patterns
inspect_phishing_csv.py	Inspect raw phishing ground truth (for testing)

🧪 Sample Workflow
bash
Copy
Edit
# 1. Generate phishing logs
python scripts/generate_mail_logs.py

# 2. Analyze for threats
python scripts/csv_sslp.py

# 3. Inspect expected phishing records
python scripts/inspect_phishing_csv.py
🔐 Detection Logic
The parser:

Normalizes Unicode text (NFKD)

Replaces Cyrillic homoglyphs (e.g. а → a)

Applies phishing regex patterns

Flags and exports suspicious entries to JSON

📦 Outputs
artifacts/mail_logs.csv: full dataset

artifacts/suspicious_emails.json: flagged records

Console summary of suspicious domains, MITRE techniques
