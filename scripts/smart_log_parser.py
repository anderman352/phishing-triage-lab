from pathlib import Path
import csv
import re

# ANSI color codes (same as before)
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Define regex patterns for suspicious sender domains and URLs
phishing_patterns = [
    r".*microsoft.*support.*",
    r".*paypal.*(alert|check).*",
    r".*coinbase.*(alert|verify).*",
    r".*amaz[0o]n.*",
    r".*netfl[i1]x.*",
    r".*icloud.*check.*",
    r".*office.*secure.*",
    r".*venmo.*cashlink.*",
    r".*hr.*secure.*portal.*",
    r".*dropbox.*login.*"
]

# Dynamically locate the artifacts folder relative to this script
base_dir = Path(__file__).resolve().parent.parent  # one level up from /scripts
csv_path = base_dir / 'artifacts' / 'mail_logs.csv'

with csv_path.open('r') as f:
    reader = csv.DictReader(f)
    print(f"\n{BOLD}{RED}🛑 Suspicious Emails Flagged by Regex Patterns:{RESET}\n")

    for row in reader:
        match_found = False

        for pattern in phishing_patterns:
            if re.search(pattern, row['sender'], re.IGNORECASE) or re.search(pattern, row['url'], re.IGNORECASE):
                match_found = True
                break

        if match_found:
            print(f"{CYAN}Timestamp:{RESET} {row['timestamp']}")
            print(f"{CYAN}Sender:   {RESET} {row['sender']}")
            print(f"{CYAN}To:       {RESET} {row['recipient']}")
            print(f"{CYAN}Subject:  {RESET} {row['subject']}")
            print(f"{YELLOW}URL:      {RESET} {row['url']}\n")
            print("-" * 60)


            print(f"{BOLD}{RED}⚠️ Suspicious activity detected!{RESET}\n")
            print("-" * 60)
