import csv

# Define your known bad indicators
ioc_list = ["microsoft-support.co", "microsoft-security-check"]

with open('../artifacts/mail_logs.csv', 'r') as f:
    reader = csv.DictReader(f)
    print("Flagged Emails:")
    for row in reader:
        if any(ioc in row['sender'] or ioc in row['url'] for ioc in ioc_list):
            print(f"{row['timestamp']} - {row['sender']} to {row['recipient']} | {row['subject']}")
