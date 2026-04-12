import pandas as pd
import re
import joblib
import os
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

DATASET = "data/phishtank.csv"
MODEL_OUT = "models/url_model.joblib"

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update",
    "account", "bank", "paypal", "gcash",
    "confirm", "reset", "signin"
]

def extract_features(url):
    url = str(url).lower().strip()
    parsed = urlparse(url if url.startswith("http") else "http://" + url)

    return [
        len(url),
        url.count("@"),
        url.count("-"),
        url.count("."),
        int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))),
        int(url.startswith("https")),
        sum(word in url for word in SUSPICIOUS_WORDS),
    ]

def load_data():
    df = pd.read_csv(DATASET)
    df.columns = df.columns.str.strip().str.lower()

    print("Detected columns:", list(df.columns))

    # Case 1: proper dataset already has url,label
    if "url" in df.columns and "label" in df.columns:
        urls = df["url"].astype(str).str.strip()
        labels = df["label"].astype(int)
        return urls, labels

    # Case 2: only one column exists -> assume all are phishing
    if len(df.columns) == 1:
        col = df.columns[0]
        urls = df[col].astype(str).str.strip()
        labels = [1] * len(urls)

        # add safe samples manually so model does not think everything is phishing
        safe_urls = [
            "https://google.com",
            "https://facebook.com",
            "https://github.com",
            "https://microsoft.com",
            "https://apple.com",
            "https://bdo.com.ph",
            "https://gcash.com",
            "https://youtube.com",
            "https://openai.com",
            "https://amazon.com"
        ]

        all_urls = list(urls) + safe_urls
        all_labels = list(labels) + [0] * len(safe_urls)

        return all_urls, all_labels

    # Case 3: has url but no label
    if "url" in df.columns and "label" not in df.columns:
        urls = df["url"].astype(str).str.strip()
        labels = [1] * len(urls)

        safe_urls = [
            "https://google.com",
            "https://facebook.com",
            "https://github.com",
            "https://microsoft.com",
            "https://apple.com",
            "https://bdo.com.ph",
            "https://gcash.com",
            "https://youtube.com",
            "https://openai.com",
            "https://amazon.com"
        ]

        all_urls = list(urls) + safe_urls
        all_labels = list(labels) + [0] * len(safe_urls)

        return all_urls, all_labels

    raise ValueError(
        f"Unsupported dataset format. Found columns: {list(df.columns)}. "
        f"Need either ['url','label'] or a single URL column."
    )

def main():
    print("Loading dataset...")
    urls, labels = load_data()

    print(f"Total samples: {len(urls)}")
    print(f"Phishing samples: {sum(1 for x in labels if x == 1)}")
    print(f"Safe samples: {sum(1 for x in labels if x == 0)}")

    print("Extracting features...")
    X = [extract_features(u) for u in urls]
    y = labels

    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    acc = model.score(X_test, y_test)
    print(f"Model accuracy: {acc:.2f}")

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_OUT)

    print(f"Model saved to {MODEL_OUT}")

if __name__ == "__main__":
    main()