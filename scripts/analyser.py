# (Phase 1):

# Count and sort:
# Suspicious emails by sender domain
# Tactics and techniques (MITRE)
# Recipients most frequently targeted

# Display:
# Top 3 sender domains
# Top 3 MITRE techniques
# Most targeted user(s)

import json
from collections import Counter
from pathlib import Path

# Locate the suspicious email data
base_dir = Path(__file__).resolve().parent.parent
json_path = base_dir / 'artifacts' / 'suspicious_emails.json'

# Load the JSON file
with json_path.open('r') as f:
    data = json.load(f)

# Counters
sender_domains = Counter()
techniques = Counter()
recipients = Counter()

# Analyze the data
for email in data:
    domain = email['sender'].split('@')[-1]
    sender_domains[domain] += 1
    techniques[email['mitre_technique']] += 1
    recipients[email['recipient']] += 1

# Output results
print("\n📊 Top 3 Sender Domains:")
for domain, count in sender_domains.most_common(3):
    print(f"  {domain}: {count} emails")

print("\n🧠 Top 3 MITRE Techniques:")
for tech, count in techniques.most_common(3):
    print(f"  {tech}: {count} matches")

print("\n🎯 Most Targeted Users:")
for user, count in recipients.most_common(3):
    print(f"  {user}: {count} phishing attempts")
print("\nAnalysis complete. Review the results above for insights into phishing trends.")
print(f"\n\033[1;31mData source: {json_path}\033[0m")
