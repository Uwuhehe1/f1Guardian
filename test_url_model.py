import joblib

model = joblib.load("models/url_model.joblib")

def extract_features(url):
    import re
    from urllib.parse import urlparse

    suspicious = ["login","verify","secure","account","update","paypal","gcash"]
    parsed = urlparse(url if url.startswith("http") else "http://" + url)

    return [[
        len(url),
        url.count("@"),
        url.count("-"),
        url.count("."),
        int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))),
        int(url.startswith("https")),
        sum(w in url.lower() for w in suspicious)
    ]]

# TEST
urls = [
    "https://secure-paypal-login.com/verify",
    "https://google.com"
]

for u in urls:
    pred = model.predict(extract_features(u))[0]
    print(u, "=>", "PHISHING 🚨" if pred == 1 else "SAFE ✅")
