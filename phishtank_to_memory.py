import csv
import json
from urllib.parse import urlparse
from datetime import datetime
import os

PHISHTANK_CSV = "data/phishtank_urls.csv"
MEMORY_FILE = "data/feedback_memory.json"

now = datetime.now().isoformat()

with open(MEMORY_FILE, "r", encoding="utf-8") as f:
    mem = json.load(f)

mem.setdefault("urls", {})
mem.setdefault("domains", {})
mem.setdefault("texts", {})
mem.setdefault("events", [])

added = 0

with open(PHISHTANK_CSV, newline="", encoding="utf-8", errors="ignore") as f:
    reader = csv.reader(f)
    for row in reader:
        if not row:
            continue
        url = row[0].strip().lower()
        try:
            domain = urlparse(url).netloc
            if domain and domain not in mem["domains"]:
                mem["domains"][domain] = now
                added += 1
        except:
            pass

mem["events"].append({
    "timestamp": now,
    "user": "system",
    "note": f"Imported {added} phishing domains from PhishTank"
})

with open(MEMORY_FILE, "w", encoding="utf-8") as f:
    json.dump(mem, f, indent=2)

print(f"✅ Added {added} phishing domains to feedback memory")
