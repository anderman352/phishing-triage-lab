import sys
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# ----- Step 1: Collect CLI Input -----

print("\n🛠️  Phishing Mail Log Generator\n")

# Total emails (10–1000)
while True:
    try:
        total = int(input("How many email records do you want to generate? (10–1000): "))
        if 10 <= total <= 1000:
            break
        else:
            print("❌ Please enter a number between 10 and 1000.")
    except ValueError:
        print("❌ Please enter a valid integer.")

# Phishing percentage (1–5%)
while True:
    try:
        phishing_pct = int(input("What percent should be phishing emails? (1–5): "))
        if 1 <= phishing_pct <= 5:
            break
        else:
            print("❌ Please enter a number between 1 and 5.")
    except ValueError:
        print("❌ Please enter a valid integer.")

# MITRE Technique Selection
print("\nSelect one or more MITRE techniques (comma-separated numbers):")
mitre_options = {
    1: ("T1566.002", "Phishing: Link"),
    2: ("T1566.001", "Phishing: Attachment"),
    3: ("T1598", "Spearphishing Service"),
    4: ("T1059", "Command & Scripting"),
    5: ("T1204", "User Execution")
}
for num, (tid, desc) in mitre_options.items():
    print(f"  {num}. {tid} – {desc}")

while True:
    try:
        selected = input("\nYour selection: ")
        selected_nums = [int(x.strip()) for x in selected.split(",")]
        if all(num in mitre_options for num in selected_nums):
            mitre_selected = [mitre_options[num] for num in selected_nums]
            break
        else:
            print("❌ Invalid selection. Please choose from the listed numbers.")
    except ValueError:
        print("❌ Please enter numbers only (comma-separated).")

# Difficulty (stub only)
print("\nChoose difficulty level (stubbed — future use only):")
print("  1. Easy\n  2. Medium\n  3. Hard")

while True:
    difficulty = input("Your choice: ")
    if difficulty in {"1", "2", "3"}:
        difficulty = {"1": "Easy", "2": "Medium", "3": "Hard"}[difficulty]
        break
    else:
        print("❌ Enter 1, 2, or 3.")

# Summary
print("\n📦 Configuration Summary:")
print(f"  • Total emails: {total}")
print(f"  • Phishing emails: ~{int(total * phishing_pct / 100)} ({phishing_pct}%)")
print(f"  • MITRE techniques: {[t[0] for t in mitre_selected]}")
print(f"  • Difficulty level: {difficulty} (placeholder)")

# Confirm next step
input("\n✅ Press ENTER to continue and generate data...\n")

# ----- Step 2: Generate Email Records -----

# Output file path
csv_path = Path(__file__).resolve().parent.parent / 'artifacts' / 'mail_logs.csv'

# Hardcoded recipients
recipients = [
    "alice@company.com", "bob@company.com", "carol@company.com",
    "dave@company.com", "eve@company.com", "frank@company.com",
    "grace@company.com", "heidi@company.com", "ivan@company.com",
    "judy@company.com"
]

# Clean domains (benign)
clean_domains = ["internal-notify.com", "support.company.com", "calendar.local", "news.company.io"]

# Phishing domains linked to MITRE techniques
phishing_patterns = {
    "T1566.002": ["secure-microsoft-check.com", "paypal-alert.net", "coinbase-auth.io"],
    "T1566.001": ["invoice-update.com", "document-preview.net"],
    "T1598": ["customerservice-netflix.com", "fake-support-dropbox.io"],
    "T1059": ["powershell-helpdesk.com", "cmd-reset-warning.net"],
    "T1204": ["click-here-urgent.com", "download-pdf-safely.org"]
}

# Subject samples
subjects_clean = ["Meeting Reminder", "Weekly Update", "Internal Newsletter", "Project Kickoff"]
subjects_phishing = ["Urgent Account Update", "Verify Now", "Download Invoice", "Suspicious Login", "Immediate Action Required"]

# Build records
records = []
now = datetime.now()

num_phishing = int(total * phishing_pct / 100)
num_clean = total - num_phishing

# Generate phishing records
for _ in range(num_phishing):
    mitre = random.choice(mitre_selected)[0]
    domain = random.choice(phishing_patterns.get(mitre, ["badsite.com"]))
    records.append({
        "timestamp": (now - timedelta(minutes=random.randint(1, 10000))).strftime("%Y-%m-%d %H:%M:%S"),
        "sender": f"alert@{domain}",
        "recipient": random.choice(recipients),
        "subject": random.choice(subjects_phishing),
        "url": f"https://{domain}/login"
    })

# Generate clean records
for _ in range(num_clean):
    domain = random.choice(clean_domains)
    records.append({
        "timestamp": (now - timedelta(minutes=random.randint(1, 10000))).strftime("%Y-%m-%d %H:%M:%S"),
        "sender": f"noreply@{domain}",
        "recipient": random.choice(recipients),
        "subject": random.choice(subjects_clean),
        "url": f"https://{domain}/notice"
    })

# Shuffle records
random.shuffle(records)

# Write to CSV
csv_path.parent.mkdir(parents=True, exist_ok=True)
with csv_path.open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp", "sender", "recipient", "subject", "url"])
    writer.writeheader()
    writer.writerows(records)

print(f"\n✅ Generated {total} emails → {csv_path}")
print("\n📂 You can now analyze the generated mail logs using the provided scripts.")

