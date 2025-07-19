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
