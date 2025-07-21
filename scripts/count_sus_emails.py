import json
with open('artifacts/suspicious_emails.json') as f:
    data = json.load(f)
print(f"⚠️  Detected: {len(data)} suspicious emails")
