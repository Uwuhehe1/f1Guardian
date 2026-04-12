import csv

INPUT = "data/phishtank.csv"
OUTPUT = "data/phishtank_urls.csv"

urls = set()

with open(INPUT, newline="", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    for row in reader:
        url = row.get("url") or row.get("phish_url")
        if url:
            urls.add(url.strip())

with open(OUTPUT, "w", newline="", encoding="utf-8") as out:
    writer = csv.writer(out)
    writer.writerow(["url", "label"])
    for u in urls:
        writer.writerow([u, 1])  # 1 = phishing

print(f"✅ Extracted {len(urls)} phishing URLs from PhishTank")
