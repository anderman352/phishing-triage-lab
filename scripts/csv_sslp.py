# Structured Smart Log Parser
# parse logs for phishing attempts and suspicious activities.
# shorten name to sslp for structured smart log parser

import csv
import json
import re
from pathlib import Path
from datetime import datetime
from collections import Counter
import unicodedata

def normalize_cyrillic(text):
    text = unicodedata.normalize("NFKD", text)  # Unicode normalization
    cyrillic_map = {
        "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x", "у": "y",
        "А": "A", "Е": "E", "О": "O", "С": "C", "Р": "P", "Х": "X", "У": "Y"
    }
    return ''.join(cyrillic_map.get(char, char) for char in text)



# File paths
base_dir = Path(__file__).resolve().parent.parent
csv_path = base_dir / 'artifacts' / 'mail_logs.csv'
json_path = base_dir / 'artifacts' / 'suspicious_emails.json'

# Flexible phishing patterns
phishing_patterns = [
    r"netfl[i1]x",
    r"amaz[o0]n",
    r"dropbox[-_.]?(login|support)",
    r"secure[-_.]?(check|account|microsoft)",
    r"(document|pdf)[-_.]?preview",
    r"invoice[-_.]?update",
    r"(cmd|powershell)[-_.]?(reset|helpdesk|auth)",
    r"paypal[-_.]?alert",
    r"coinbase[-_.]?(auth|alert)",
    r"click[-_.]?here[-_.]?(now|urgent|verify)",
    r"support[-_.]?ticket",
    r"login[-_.]?verify",
    r"account[-_.]?(locked|verify|access|suspended)",
    r"internal[-_.]?notify",
    r"download[-_.]?pdf",
]

# MITRE mapping
mitre_map = {
    "netfl[i1]x": "T1566.002",
    "amaz[o0]n": "T1566.002",
    "dropbox": "T1566.002",
    "secure": "T1584.001",
    "cmd": "T1059.003",
    "powershell": "T1059.001",
    "paypal": "T1566.002",
    "coinbase": "T1566.002",
    "click": "T1204.001",
    "document": "T1566.001",
    "login": "T1556.002",
    "account": "T1584.002",
    "notify": "T1585.001",
    "preview": "T1566.001",
}

# Parse mail logs
suspicious_emails = []

with csv_path.open(encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        combined_text = " ".join([row["sender"], row["subject"], row["url"]])
        combined_text = normalize_cyrillic(combined_text)  # Normalize Cyrillic characters
        for pattern in phishing_patterns:
            if re.search(pattern, combined_text, re.IGNORECASE):
                tag = None
                for key in mitre_map:
                    if re.search(key, combined_text, re.IGNORECASE):
                        tag = mitre_map[key]
                        break
                row["matched_pattern"] = pattern
                row["mitre_technique"] = tag or "TBD"
                suspicious_emails.append(row)
                break

# Output flagged results (limited to first 10)
print("\n🛑 Suspicious Emails Flagged by Regex Patterns:\n")
for i, email in enumerate(suspicious_emails[:10]):
    print(f"\033[1;31m[!] Sender:\033[0m {email['sender']}")
    print(f"    Subject: {email['subject']}")
    print(f"    URL:     {email['url']}")
    print(f"    Pattern: {email['matched_pattern']}")
    print(f"    MITRE:   {email['mitre_technique']}\n")

if len(suspicious_emails) > 10:
    print(f"...and {len(suspicious_emails) - 10} more suspicious emails not shown.\n")

# 🧠 Summary table by MITRE technique
tech_counts = Counter(email["mitre_technique"] for email in suspicious_emails)

print("📊 MITRE Technique Summary:\n")
print(f"{'Technique':<12} | {'Count'}")
print("-" * 22)
for tag, count in tech_counts.most_common():
    print(f"{tag:<12} | {count}")

# Save to JSON
json_path.parent.mkdir(parents=True, exist_ok=True)
with json_path.open("w") as f:
    json.dump(suspicious_emails, f, indent=4)

print(f"\n\033[1;32m✅ Saved {len(suspicious_emails)} suspicious emails → {json_path}\033[0m")

# Final messages
print("\nAnalysis complete. Review the results above for insights into phishing trends.")
print(f"\n\033[1;31mData source: {json_path}\033[0m")
