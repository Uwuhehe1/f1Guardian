import csv
import os

INPUT = "data/training.csv"
OUTPUT = "data/url_training.csv"

os.makedirs("data", exist_ok=True)

with open(INPUT, newline="", encoding="utf-8") as f, \
     open(OUTPUT, "w", newline="", encoding="utf-8") as out:

    reader = csv.DictReader(f)
    writer = csv.writer(out)
    writer.writerow(["url", "label"])

    for row in reader:
        text = row.get("text", "")
        label = row.get("label", "0")

        if "http" in text or "." in text:
            writer.writerow([text.strip(), label])

print("✅ url_training.csv created")
