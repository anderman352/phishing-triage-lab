# Structured Smart Log Parser
# parse logs for phishing attempts and suspicious activities.
# shorten name to sslp for structured smart log parser

from pathlib import Path
import csv
import re
import json

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Define phishing detection patterns and MITRE mappings
pattern_to_mitre = {
    r".*microsoft.*support.*": ("T1566.002", "Initial Access"),
    r".*paypal.*(alert|check).*": ("T1566.002", "Initial Access"),
    r".*coinbase.*(alert|verify).*": ("T1566.002", "Initial Access"),
    r".*amaz[0o]n.*": ("T1566.002", "Initial Access"),
    r".*netfl[i1]x.*": ("T1566.002", "Initial Access"),
    r".*icloud.*check.*": ("T1566.002", "Initial Access"),
    r".*office.*secure.*": ("T1566.002", "Initial Access"),
    r".*venmo.*cashlink.*": ("T1566.002", "Initial Access"),
    r".*hr.*secure.*portal.*": ("T1566.002", "Initial Access"),
    r".*dropbox.*login.*": ("T1566.002", "Initial Access")
}

base_dir = Path(__file__).resolve().parent.parent
csv_path = base_dir / 'artifacts' / 'mail_logs.csv'
json_path = base_dir / 'artifacts' / 'suspicious_emails.json'

results = []

with csv_path.open('r') as f:
    reader = csv.DictReader(f)
    print(f"\n{BOLD}{RED}🛑 Suspicious Emails Flagged by Regex Patterns:{RESET}\n")

    for row in reader:
        for pattern, (technique, tactic) in pattern_to_mitre.items():
            if re.search(pattern, row['sender'], re.IGNORECASE) or re.search(pattern, row['url'], re.IGNORECASE):
                # Console output
                print(f"{CYAN}Timestamp:{RESET} {row['timestamp']}")
                print(f"{CYAN}Sender:   {RESET} {row['sender']}")
                print(f"{CYAN}To:       {RESET} {row['recipient']}")
                print(f"{CYAN}Subject:  {RESET} {row['subject']}")
                print(f"{YELLOW}URL:      {RESET} {row['url']}")
                print(f"{CYAN}MITRE:    {RESET} {technique} ({tactic})")
                print("-" * 60)

                # Save data for export
                results.append({
                    "timestamp": row['timestamp'],
                    "sender": row['sender'],
                    "recipient": row['recipient'],
                    "subject": row['subject'],
                    "url": row['url'],
                    "matched_pattern": pattern,
                    "mitre_technique": technique,
                    "mitre_tactic": tactic
                })
                break  # Stop checking once a match is found

# Export flagged results to JSON
with json_path.open('w') as json_file:
    json.dump(results, json_file, indent=4)

print(f"\n{BOLD}{YELLOW}✔️ Exported {len(results)} suspicious emails to:{RESET} {json_path}")
from pathlib import Path
import csv
import re
import json

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Define phishing detection patterns and MITRE mappings
pattern_to_mitre = {
    r".*microsoft.*support.*": ("T1566.002", "Initial Access"),
    r".*paypal.*(alert|check).*": ("T1566.002", "Initial Access"),
    r".*coinbase.*(alert|verify).*": ("T1566.002", "Initial Access"),
    r".*amaz[0o]n.*": ("T1566.002", "Initial Access"),
    r".*netfl[i1]x.*": ("T1566.002", "Initial Access"),
    r".*icloud.*check.*": ("T1566.002", "Initial Access"),
    r".*office.*secure.*": ("T1566.002", "Initial Access"),
    r".*venmo.*cashlink.*": ("T1566.002", "Initial Access"),
    r".*hr.*secure.*portal.*": ("T1566.002", "Initial Access"),
    r".*dropbox.*login.*": ("T1566.002", "Initial Access")
}

base_dir = Path(__file__).resolve().parent.parent
csv_path = base_dir / 'artifacts' / 'mail_logs.csv'
json_path = base_dir / 'artifacts' / 'suspicious_emails.json'

results = []

with csv_path.open('r') as f:
    reader = csv.DictReader(f)
    print(f"\n{BOLD}{RED}🛑 Suspicious Emails Flagged by Regex Patterns:{RESET}\n")

    for row in reader:
        for pattern, (technique, tactic) in pattern_to_mitre.items():
            if re.search(pattern, row['sender'], re.IGNORECASE) or re.search(pattern, row['url'], re.IGNORECASE):
                # Console output
                print(f"{CYAN}Timestamp:{RESET} {row['timestamp']}")
                print(f"{CYAN}Sender:   {RESET} {row['sender']}")
                print(f"{CYAN}To:       {RESET} {row['recipient']}")
                print(f"{CYAN}Subject:  {RESET} {row['subject']}")
                print(f"{YELLOW}URL:      {RESET} {row['url']}")
                print(f"{CYAN}MITRE:    {RESET} {technique} ({tactic})")
                print("-" * 60)

                # Save data for export
                results.append({
                    "timestamp": row['timestamp'],
                    "sender": row['sender'],
                    "recipient": row['recipient'],
                    "subject": row['subject'],
                    "url": row['url'],
                    "matched_pattern": pattern,
                    "mitre_technique": technique,
                    "mitre_tactic": tactic
                })
                break  # Stop checking once a match is found

# Export flagged results to JSON
with json_path.open('w') as json_file:
    json.dump(results, json_file, indent=4)

print(f"\n{BOLD}{YELLOW}✔️ Exported {len(results)} suspicious emails to:{RESET} {json_path}")
