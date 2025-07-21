import csv
from pathlib import Path
from collections import Counter

# Paths
csv_path = Path(__file__).resolve().parent.parent / 'artifacts' / 'mail_logs.csv'

# Detect phishing based on sender domain (contains dash = phishing)
def is_phishing_sender(sender):
    domain = sender.split('@')[-1]
    return '-' in domain or 'secure' in domain or 'login' in domain

# Read and filter
phishing_senders = []
with csv_path.open() as f:
    reader = csv.DictReader(f)
    for row in reader:
        if is_phishing_sender(row['sender']):
            phishing_senders.append(row['sender'])

# Display results
total = len(phishing_senders)
print(f"\n📌 Potential phishing senders: {total}")
for sender, count in Counter(phishing_senders).most_common():
    print(f"  {sender:40} | {count}")

print(f"\n🔢 Total suspected phishing emails: {total}")

