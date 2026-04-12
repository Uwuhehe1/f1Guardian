import joblib

model = joblib.load('phishing_detector_model.pkl')


test_samples = [
    {
        "subject": "Account Suspended",
        "body": "Your account has been suspended. Click here to verify your information."
    },
    {
        "subject": "Team Meeting Reminder",
        "body": "Meeting scheduled at 10 AM tomorrow. Please confirm attendance."
    },
    {
        "subject": "Gift Card Winner",
        "body": "You won a gift card! Enter your credentials to claim it."
    },
    {
        "subject": "Community Survey",
        "body": "We value your feedback. Please take a moment to complete our community survey."
    },
    {
        "subject": "Security Alert",
        "body": "Security alert: unusual login detected. Login now to secure your account."
    },
    {
        "subject": "New Feature Release",
        "body": "Our platform has been updated with new reporting features. Check them out!"
    }
]

print("="*60)
for email in test_samples:
    combined = f"{email['subject']} {email['body']}"
    prob = model.predict_proba([combined])[0][1]
    pred = model.predict([combined])[0]
    label = "PHISHING" if pred else "SAFE"
    print(f"[{label:8} | Prob: {prob:.2f}] Subject: {email['subject']}")
    print(f"Body: {email['body']}")
    print("-"*60)
print("="*60)
