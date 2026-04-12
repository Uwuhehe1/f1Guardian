import joblib


model = joblib.load('phishing_detector_model.pkl')  


def is_phishing_ml(email_content):
    prediction = model.predict([email_content])[0]
    return prediction == 1


test_emails = [
    "Your account has been suspended. Click here to verify your information.",
    "Meeting scheduled at 10 AM tomorrow. Please confirm attendance.",
    "Urgent! Your PayPal account has been compromised. Reset your password immediately!",
    "Your invoice is attached. Let us know if you have questions.",
    'won', 'urgent', 'money', 'lotto', 'otp', 'gcash',
    'verify', 'account suspended', 'click here', 'login now',
    'free', 'iphone', 'confirm', 'reset password', 'secure it now','cash'
]


for email in test_emails:
    result = is_phishing_ml(email)
    print(f"[{'PHISHING' if result else 'SAFE'}] {email}") 
