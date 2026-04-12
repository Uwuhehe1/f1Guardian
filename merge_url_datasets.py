import csv

FILES = [
    "data/url_training.csv",
    "data/phishtank_urls.csv"
]

OUT = "data/url_training_merged.csv"
seen = set()

with open(OUT, "w", newline="", encoding="utf-8") as out:
    writer = csv.writer(out)
    writer.writerow(["url", "label"])

    for file in FILES:
        try:
            with open(file, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    key = (row["url"], row["label"])
                    if key not in seen:
                        seen.add(key)
                        writer.writerow(key)
        except FileNotFoundError:
            pass

print(f"✅ Merged dataset size: {len(seen)} URLs")
