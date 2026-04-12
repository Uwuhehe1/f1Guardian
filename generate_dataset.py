import random
import pandas as pd
from pathlib import Path  # <-- missing import added

# =========================
# SECTION A: YOUR LABELED DATA
# =========================
phishing_emails = [
    "Your account has been suspended. Click here to verify your information.",
    "Urgent: Confirm your bank details immediately!",
    "You won a gift card! Enter your credentials to claim it.",
    "Security alert: unusual login detected. Login now to secure your account.",
    "Reset your password now or your account will be locked.",
    "Your account has been compromised. Click to secure it now.",
    "Final warning: your account will be deactivated if you don’t act now!",
    "Verify your identity to avoid suspension of your account.",
    "Limited time offer! Get your free iPhone by clicking this link.",
    "Security breach detected in your account. Act fast to prevent damage.",
    "Your PayPal account will be suspended unless you verify now.",
    "Suspicious login detected from overseas. Click here to secure your account.",
    "Unusual withdrawal attempt detected. Verify to prevent account lockout.",
    "Your tax refund is ready. Fill out the form to receive payment.",
    "We couldn’t process your payment. Update your billing info.",
    "Apple ID login from a new device detected. Confirm if this was you.",
    "Your Microsoft account has been temporarily locked. Confirm your credentials.",
    "Claim your $1000 reward now! Just verify your details.",
    "Download the attached invoice to avoid late fees.",
    "Congratulations! You have been selected to win $10,000.",
    "FedEx: Your package is on hold due to missing information. Provide details to release it.",
    "Your email storage is full. Upgrade now to continue receiving messages.",
    "We detected suspicious activity on your Netflix account. Re-login to verify.",
    "Amazon order issue: Please update your payment method to complete your purchase.",
    "Your driver’s license has expired. Renew immediately to avoid penalties.",
    "You have pending funds in your account. Log in to claim before they expire.",
    "Unpaid electricity bill: Pay immediately to avoid disconnection.",
    "New voicemail received: Click here to listen to the message.",
    "Facebook: Your page is at risk of being deleted. Confirm your account now.",
    "Google Drive: Shared document requires you to login for access.",
    "Crypto wallet withdrawal request detected. Cancel it if this wasn’t you.",
    "IRS: You are eligible for a tax rebate. Submit your information to claim.",
    "Bank of America: We locked your card for unusual transactions. Verify to unlock.",
    "Your antivirus subscription has expired. Renew now to stay protected.",
    "Confirm your identity to prevent your account from permanent suspension.",
    "Lottery Alert: You’ve been selected as a winner! Claim your prize immediately.",
    "We noticed failed login attempts from a new device. Confirm if this was you.",
    "Your health insurance policy has lapsed. Reactivate your account now.",
    "QuickBooks: Payment error detected. Resolve issue by logging in here.",
    "Zoom: Meeting access suspended. Sign in to restore your account.",
    "Charity appeal: Donate now to help victims of natural disasters. Click to contribute.",
    "You have received a secure fax. View document by logging into your portal.",
    "DHL: Delivery attempt failed. Provide your address and payment to reschedule.",
    "Your Spotify Premium account has been downgraded. Re-enter payment info to restore.",
    "Government relief funds available. Submit your details to qualify.",
    "COVID-19 vaccine registration required. Fill out this form to confirm your appointment.",
    "eBay: Buyer has opened a dispute. Login to respond immediately.",
    "New job opportunity: Earn $500/day working from home. Apply now.",
    "CashApp: You’ve received $750. Click to claim instantly.",
    "We noticed unusual activity on your Gmail account. Re-verify your credentials.",
    "LinkedIn: Someone viewed your profile. Sign in to see who.",
    "Outlook: Your mailbox has exceeded its storage quota. Validate to avoid data loss.",
    "Delivery pending: Pay $2.99 shipping fee to release your package.",
    "Your bank account will be closed in 24 hours unless verified.",
    "Instagram: Your account is at risk of termination. Confirm login to keep it active.",
    "Bitcoin wallet: Immediate withdrawal detected. Verify before funds are lost.",
    "Hotmail: Update your account to maintain uninterrupted email service.",
    "COVID-19 relief grant: You are pre-approved. Claim your funds today.",
    "Wells Fargo: Temporary suspension due to suspicious activity. Login to restore.",
    "Chase Bank: Unusual transaction detected. Confirm your account to stop fraud.",
    "CitiBank: Your credit card has been temporarily disabled. Reactivate now.",
    "HSBC: Your online banking is locked. Log in to unlock access.",
    "Walmart: Your order cannot be shipped. Provide payment info to continue.",
    "Apple Music subscription renewal failed. Update billing info immediately.",
    "Hulu: Your subscription will be canceled unless you update your payment.",
    "IT Support: Mandatory security update required. Log in to apply the patch.",
    "Payroll: Your direct deposit was declined. Verify your bank info to receive salary.",
    "University notice: Your student portal account will be disabled unless verified.",
    "Parking ticket overdue: Pay now to avoid additional fines.",
    "Your mortgage account is past due. Make payment to avoid foreclosure.",
    "Fed relief loan available: Apply now for instant approval.",
    "Charity fund: Help children in need by sending your donation here.",
    "Crypto exchange: Withdrawal request pending. Approve or cancel immediately.",
    "Telegram: Your account will be restricted unless you confirm identity.",
    "Discord: Your account violates community rules. Log in to appeal.",
    "Steam: Unauthorized login attempt detected. Verify your credentials.",
    "Adobe: Your Creative Cloud subscription has expired. Update details to restore access.",
    "Dropbox: Shared folder requires you to login for access. Confirm credentials now.",
    "Gift card reward: Activate your $200 Amazon gift card by confirming your details.",
    "AT&T: Your mobile bill payment failed. Login now to avoid service suspension.",
    "Verizon: Unusual SIM card change request detected. Verify to secure your account.",
    "T-Mobile: Account upgrade required to continue using 5G services.",
    "Health Alert: Your medical records have been flagged. Verify identity to continue access.",
    "Pharmacy notice: Your prescription is ready for pickup. Confirm payment to release.",
    "Employee HR: Annual review documents require your signature. Log in here.",
    "Boss: Urgent wire transfer needed. Respond immediately with confirmation.",
    "Company IT: Password reset required within 24 hours. Failure to comply will lock account.",
    "Charity raffle: Confirm your ticket number to claim your prize.",
    "Uber: Your ride account is suspended. Update billing info to reactivate.",
    "Lyft: Payment failure detected. Please verify to continue rides.",
    "Airbnb: Reservation issue detected. Login to confirm your booking.",
    "Expedia: Your travel itinerary has been canceled. Re-login to restore.",
    "Southwest Airlines: Flight change requires confirmation. Click to proceed.",
    "United Airlines: Baggage fee payment pending. Pay to avoid cancellation.",
    "Payoneer: Your funds transfer has been blocked. Verify your identity.",
    "Venmo: You received a payment. Accept now to claim.",
    "Zelle: Incoming transaction requires verification. Confirm now.",
    "Western Union: Your transfer is pending. Login to confirm recipient."
]

legitimate_emails = [
    "Meeting scheduled at 10 AM tomorrow. Please confirm attendance.",
    "Your Amazon order has been shipped.",
    "Reminder: Submit your project by Friday.",
    "Monthly newsletter – September Edition",
    "Your subscription has been renewed successfully.",
    "Please find attached the report you requested.",
    "New blog post available – How to improve your coding skills.",
    "Monthly budget report is ready for review.",
    "Invitation: Join our annual company picnic this Sunday.",
    "Team meeting rescheduled to Monday at 2 PM.",
    "Your payment has been received successfully.",
    "Here is your e-ticket for the event next week.",
    "Weekly performance report attached for your review.",
    "System maintenance scheduled for this weekend.",
    "Workshop reminder: Advanced Python Programming at 3 PM.",
    "Your flight booking with Delta Airlines has been confirmed.",
    "New comment on your post: 'Great article, thanks for sharing!'",
    "Reminder: Dentist appointment scheduled for Thursday at 11 AM.",
    "Welcome to our service! Here are some tips to get started.",
    "Happy Birthday! Enjoy a special discount on us.",
    "Quarterly financial report is now available on the portal.",
    "Thank you for attending our webinar yesterday.",
    "Google Calendar reminder: Meeting with project team at 4 PM.",
    "Your order #12345 has been delivered successfully.",
    "Thank you for your donation to the local food bank.",
    "Class reminder: Data Science 101 starts at 9 AM tomorrow.",
    "Holiday greetings from our company to you and your family.",
    "Invoice for your recent purchase is attached.",
    "Here are the meeting notes from today’s discussion.",
    "Join our loyalty program and earn points on every purchase.",
    "Reminder: Company holiday party next Friday at 6 PM.",
    "Spotify: Your 2025 Wrapped is ready!",
    "LinkedIn: Your connection request has been accepted.",
    "GitHub: New pull request opened in your repository.",
    "Slack: You have 3 unread messages in #project-updates.",
    "Zoom: Your scheduled meeting link for tomorrow is ready.",
    "Your course certificate is now available for download.",
    "Apple: Your device warranty has been successfully registered.",
    "Dropbox: Your file 'report.pdf' has been shared with you.",
    "Microsoft Teams: Meeting invitation for Thursday at 9 AM.",
    "Coursera: Congratulations! You completed the Python course.",
    "Bank statement for your checking account is now available online.",
    "Reminder: Submit your health insurance claim before the deadline.",
    "Doctor appointment confirmed for Tuesday at 2 PM.",
    "Newsletter: Top 10 travel destinations for 2025.",
    "HR: Please complete your annual benefits enrollment form.",
    "Welcome aboard! Your employee account has been created.",
    "Event registration successful. See you at the Tech Expo next month.",
    "New assignment uploaded in your university portal.",
    "Payment receipt for your electricity bill is attached.",
    "Google Drive: You have been granted access to a shared folder.",
    "Reminder: Your library books are due back on Friday.",
    "Thank you for renewing your gym membership.",
    "Survey: Share your feedback and help us improve our service.",
    "Happy Anniversary! Here’s a special thank-you for being with us.",
    "Pinterest: Here are some fresh ideas for you this week.",
    "Twitter: You have a new follower waiting for you.",
    "Booking.com: Your hotel reservation is confirmed.",
    "Uber: Your ride with driver John is arriving in 5 minutes.",
    "Grubhub: Your food delivery is on its way!",
    "Starbucks Rewards: You earned 50 bonus stars this week.",
    "Netflix: New shows added that you might like.",
    "Welcome back! Your login to the university portal was successful.",
    "Reminder: Submit your timesheet before Friday noon.",
    "Lazada: Big Sale starts tomorrow – Don’t miss out!",
    "Shopee: Your parcel is out for delivery.",
    "Gmail: Security checkup completed successfully.",
    "Your car service appointment is confirmed for next Monday.",
    "Reminder: Parent-teacher meeting scheduled this Saturday.",
    "Thank you for updating your profile information.",
    "Your water bill has been paid successfully.",
    "Flight boarding pass attached for your upcoming trip.",
    "Amazon: Your return request has been processed.",
    "Outlook: New email filters applied successfully.",
    "Campus reminder: Midterm exams start next week.",
    "Your conference registration has been confirmed.",
    "Payment for your mobile plan has been received.",
    "New policy updates are now available on the company portal.",
    "Doctor: Lab test results are ready for download.",
    "Your gym class schedule for next week is confirmed.",
    "We received your support ticket. Our team will respond shortly.",
    "Google Photos: Your memories from last year are ready to view.",
    "PayPal: Your refund has been processed successfully.",
    "Welcome to our newsletter – thanks for subscribing!",
    "Coursera: New recommended course available for you.",
    "Medium: New stories from authors you follow.",
    "Thank you for renewing your magazine subscription.",
    "Library: Your reserved book is now available for pickup.",
    "LinkedIn: Weekly job alerts curated for you.",
    "GitHub: Workflow completed successfully.",
    "Slack: Reminder to update your status during vacation.",
    "Spotify: Your playlist has been successfully updated.",
    "Netflix: We’ve added new movies in your favorite genre.",
    "Eventbrite: Your tickets for the workshop are attached.",
    "Zoom: Recording from your last meeting is available.",
    "Trello: A new task has been assigned to you.",
    "Jira: Sprint planning starts tomorrow.",
    "Bank: Your credit card bill is ready for payment.",
    "Telegram: You have new unread messages.",
    "Discord: Your friend request has been accepted.",
    "Notion: A new page was shared with you.",
    "Dropbox: Backup completed successfully.",
    "Your electricity consumption report is available in the portal.",
    "Doctor reminder: Annual health checkup scheduled next week.",
    "Your child’s school newsletter for October is ready.",
    "Google Classroom: New assignment posted for your course.",
    "Congratulations! You’ve completed your fitness challenge this week.",
    "Your mobile app update is now available in the App Store.",
    "Tax receipt for your recent donation is attached.",
    "Conference reminder: Keynote session starts tomorrow at 9 AM.",
    "Thank you for confirming your RSVP to the wedding.",
    "Your community center membership has been renewed.",
    "Your photography order prints are ready for pickup.",
    "Thank you for joining our mentorship program.",
    "Car insurance renewal confirmation attached.",
    "Bank alert: Your savings interest report is now available.",
    "Google Docs: A new comment was added to your document.",
    "Zoom: Poll results from your meeting are available.",
    "Slack: Weekly digest of your workspace activity.",
    "Udemy: Course progress update – keep going!",
    "Airbnb: Your booking details for the trip are attached.",
    "TripAdvisor: Here are new travel recommendations for you."
]

phishing_keywords = [
    "urgent", "immediately", "act now", "final notice", "your account will be suspended",
    "account locked", "account suspended", "deactivation notice", "your account has been compromised",
    "unusual login attempt", "verify now", "confirm now", "security alert", "alert: suspicious activity",
    "immediate response required", "respond instantly", "failure to respond", "deadline approaching",
    "avoid termination", "within 12 hours", "login required immediately", "critical warning",
    "take immediate action", "high priority", "time sensitive", "final attempt",
    "last chance", "act before it’s too late", "account closure imminent",
    "verify your account", "confirm your credentials", "login now to secure your account",
    "validate your identity", "identity check required", "unlock account", "restricted access",
    "temporary hold", "login verification required", "two-step verification failure",
    "re-activate account", "account confirmation", "credentials required", "reactivation required",
    "reconfirm details", "password reset required", "login authentication required",
    "won", "winner", "lotto", "lottery", "claim prize", "reward", "bonus", "free gift", "cash", "money",
    "$1000 reward", "gift card", "exclusive offer", "special promotion", "free iPhone", "limited time offer",
    "congratulations, you’ve been selected", "exclusive deal", "instant reward", "lucky draw",
    "pre-approved prize", "redeem now", "reward points available", "earn money fast",
    "scratch and win", "lifetime prize", "guaranteed winnings",
    "verify payment method", "payment failed", "update billing info", "renew subscription", "otp", "gcash",
    "wire transfer", "fund transfer request", "tax refund", "irs refund", "government grant",
    "relief fund", "compensation fund", "inheritance", "fund release", "bank account update",
    "overdue payment", "unpaid bill", "credit card declined", "billing error", "suspicious transaction",
    "pending transaction", "payment required", "unauthorized withdrawal", "suspicious transfer",
    "atm withdrawal attempt", "paypal balance issue", "crypto wallet login", "loan approval",
    "mortgage relief", "get rich quick", "investment scheme",
    "debt forgiveness", "credit score update", "cash advance", "forex trading alert",
    "download attachment", "open the document", "secure it now", "invoice attached",
    "download secure file", "document shared with you", "scan to unlock", "open file urgently",
    "attachment required", "statement attached", "urgent pdf", "review invoice", "view document here",
    "download statement", "file requires password", "click to view report",
    "fedex delivery pending", "dhl shipment hold", "usps delivery failed",
    "package on hold", "delivery confirmation required", "shipping fee required",
    "your parcel is awaiting pickup", "reschedule delivery", "customs clearance fee",
    "tracking update required", "courier unable to deliver",
    "work from home offer", "earn $500 daily", "easy job available",
    "instant hiring", "job opportunity waiting", "apply now to start earning",
    "online work offer", "limited vacancies", "make money online fast",
    "career opportunity", "no experience required",
    "charity appeal", "donate now", "help victims", "emergency fund",
    "support our cause", "disaster relief fund", "donation request",
    "urgent fundraising", "sponsor a child", "aid campaign",
    "facebo0k.com", "y0utube.com", "tikt0k.com", "yah00.com", "paypal-login.com",
    "secure-google-account.com", "google.secure-login.net", "secure-facebook.com", "secure-instagram.com",
    "login-microsoft.net", "apple.verify.com", "amaz0n.com", "micros0ft.com", "paypa1.com", "app1e.com",
    "netfIix.com", "spot1fy.com", "linkedln.com", "instagrarn.com", "g00gle.com", "icloud-support.net",
    "cloudfIare.com", "secure-dropbox.com", "onedrive-verification.com", "bankofarnerica.com",
    "rnybank.com", "officiaIpaypal.com", "netfl1x-login.com",
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rebrand.ly", "shorte.st", "buff.ly",
    "adf.ly", "short.cm", "linktr.ee", "clk.sh", "ouo.io", "lnkd.in", "smarturl.it", "mcaf.ee", "t.ly",
    "qr.ae", "s.id", "trib.al", "rb.gy", "shorturl.at", "v.gd", "shrtco.de", "chilp.it",
    "%32%33", "xn--pple-43d.com", "xn--goog1e-qmc.com", "xn--facebok-8nf.com", "xn--youtub-4ve.com",
    "％65xample.com", "gοοgle.com", "paypaⅼ.com", "аpple.com", "secυre.com", "microsοft.com",
    "facebοok.secure-login.com", "instagrɑm-help.com", "xn--amazn-l2a.com", "xn--paypl-4ve.com",
    "legal action pending", "lawsuit notice", "court appearance required",
    "report to authorities", "final demand", "compliance violation",
    "account investigation", "criminal charges", "dispute notice",
    "tax violation", "official warning", "breach of policy",
    "court summons", "law enforcement notice", "confidential legal document",
    "vpn login required", "outlook password expired", "email quota exceeded",
    "mailbox full", "upgrade mailbox", "quota warning", "verify email settings",
    "service interruption", "it department notice", "mandatory update required",
    "microsoft exchange login", "secure email gateway alert",
    "remote access required", "system configuration alert", "admin credentials required",
    "free ethereum", "free eth", "btc free", "bitcoin giveaway", "crypto giveaway",
    "crypto airdrop", "ico presale", "wallet verification required", "blockchain alert",
    "exchange login required", "coinbase verify", "binance login issue",
    "ledger device unlock", "metamask security warning", "token unlock event",
    "nft giveaway", "crypto presale", "altcoin rewards",  # <-- fixed comma here
    "bpi otp", "bdo one-time pin", "unionbank verify", "metrobank secure", "rcbc verify",
    "security bank verify", "landbank iaccess", "gcash verification", "maya verification",
    "paymaya verify", "coins.ph login", "grabpay verify", "palawan express claim code",
    "western union mtcn", "remittance claim code",
    "kyc update", "revalidate kyc", "customer due diligence", "fatca update", "aml check",
    "sanctions screening", "source of funds verification",
    "dmca complaint", "copyright infringement notice", "community standards violation",
    "page will be unpublished", "policy breach detected", "terms of service violation",
    "2fa reset", "mfa reset", "otp required", "okta verify prompt", "duo push approval",
    "sso session expired", "id.me verification", "authenticator re-enroll",
    "docusign envelope", "adobe sign document", "sharepoint file shared",
    "onedrive secure message", "microsoft teams missed message", "servicenow ticket requires action",
    "workday payroll update", "sap invoice", "oracle expense report", "salesforce login verify",
    "intuit quickbooks invoice", "xero invoice awaiting payment",
    "lbc delivery pending", "j&t express shipment hold", "ninja van delivery failed",
    "best express parcel on hold", "customs duty required", "postal clearance fee",
    "windows defender auto-renewal", "mcafee renewal invoice", "norton subscription charged",
    "spotify premium renewal failed", "youtube premium payment declined", "applecare renewal",
    ".html attachment", ".htm attachment", ".zip attachment", ".rar attachment", ".7z attachment",
    ".exe file", ".scr file", ".iso file", ".img file", ".apk file", ".hta file",
    ".docm", ".xlsm", ".js attachment", ".vbs attachment", "enable macros", "enable content",
    "protected document click enable", "secure viewer required",
    "scan qr to login", "qr code verification", "scan to claim reward",
    "48 hours to respond", "account disabled in 24 hours", "final suspension",
    "non-compliance penalty", "immediate settlement required",
    "trust wallet verify", "phantom wallet login", "keystone seed phrase",
    "seed phrase verification", "private key required",
    "bit.do", "v.ht", "qrlnk.io", "ow.ly", "surl.li", "l.linklyhq.com", "tiny.cc",
    "db.tt", "box.com/s/", "dropbox.com/s/", "drive.google.com/uc?id=", "gg.gg",
    "rnicrosoft.com", "paypаl.com", "gοoglemail.com", "facebοok.com", "appⅼeid.apple.com",
    "micros0ftsupport.com", "secure-paypaI.com", "amaz0n-support.com",
    ".tk", ".top", ".xyz", ".buzz", ".icu", ".club", ".cn", ".ru",
    "http://", "https://", "://", "://@", "http://127.0.0.1", "http://0.0.0.0", "login via ip",
    "proforma invoice", "remittance advice", "payment advice", "swift copy attached",
    "bank confirmation letter", "vendor onboarding form",
    "salary adjustment form", "payroll discrepancy", "w-2 available", "2316 form download",
    "sss contribution update", "philhealth contribution update", "pag-ibig loan approval",
    "student portal verification", "scholarship approval form", "tuition fee settlement link",
    "tiktok creator fund verify", "facebook monetization appeal", "youtube copyright strike appeal",
    "instagram blue badge verify", "twitter/x blue verification appeal",
    "remote support session", "anydesk session id", "teamviewer code", "grant remote access",
    "i-verify ang account", "mag-login ngayon", "agad na aksyon", "i-update ang impormasyon",
    "i-reset ang password", "masususpinde ang iyong account", "na-hack ang account",
    "mag-click dito", "ipasa ang otp", "magpadala ng gcash ngayon",
    "transaction declined review", "chargeback notice", "card on hold", "cvv confirmation",
    "3d secure verification", "strong customer authentication",
    "secure portal login", "encrypted message portal", "confidential document portal",
    "security questionnaire", "risk assessment required"
]

# =========================
# SECTION B: CONFIG
# =========================
TARGET_SIZE = 1000
POS_RATIO   = 0.50
AUGMENT_PHISHING       = True
MAX_KEYWORDS_PER_EMAIL = 2
OUT_FIXED = "phishing_training_dataset_1000.csv"
OUT_FULL  = "phishing_training_dataset_full.csv"
RANDOM_STATE = 42

# =========================
# SECTION C: HELPERS
# =========================
def sanitize_lists():
    def cleaned(seq):
        seen = set()
        out = []
        for s in seq:
            s2 = (s or "").strip()
            if not s2:
                continue
            if s2 not in seen:
                seen.add(s2)
                out.append(s2)
        return out

    ph = cleaned(phishing_emails)
    lg = cleaned(legitimate_emails)
    kw = cleaned(phishing_keywords)

    if not ph:
        raise ValueError("phishing_emails must contain at least 1 item.")
    if not lg:
        raise ValueError("legitimate_emails must contain at least 1 item.")
    if not kw:
        print("⚠️  phishing_keywords is empty — augmentation will be skipped.")
    return ph, lg, kw

def augment_text(base, rng, keywords, max_k):
    if not keywords or max_k <= 0:
        return base
    k = rng.randint(0, max_k)
    if k == 0:
        return base
    k = min(k, len(keywords))
    kws = rng.sample(keywords, k=k)
    return base.rstrip(". ") + " " + " ".join(kws) + "."

def make_fixed_dataset(ph_list, lg_list, kw_list, size, pos_ratio,
                       augment=True, max_kw=2, random_state=42):
    rng = random.Random(random_state)
    n_pos = int(round(size * pos_ratio))
    n_neg = size - n_pos

    pos_samples = []
    for _ in range(n_pos):
        base = rng.choice(ph_list)
        txt = augment_text(base, rng, kw_list if augment else [], max_kw)
        pos_samples.append((txt, 1))

    neg_samples = []
    for _ in range(n_neg):
        base = rng.choice(lg_list)
        neg_samples.append((base, 0))

    data = pos_samples + neg_samples

    seen = set()
    deduped = []
    for row in data:
        if row not in seen:
            seen.add(row)
            deduped.append(row)
    while len(deduped) < size:
        if rng.random() < pos_ratio:
            base = rng.choice(ph_list)
            txt = augment_text(base, rng, kw_list if augment else [], max_kw)
            deduped.append((txt, 1))
        else:
            deduped.append((rng.choice(lg_list), 0))

    rng.shuffle(deduped)
    return pd.DataFrame(deduped[:size], columns=["text", "label"])

def make_full_labeled_dataset(ph_list, lg_list, random_state=42):
    rng = random.Random(random_state)
    data = [(t, 1) for t in ph_list] + [(t, 0) for t in lg_list]
    seen, out = set(), []
    for row in data:
        if row not in seen:
            seen.add(row)
            out.append(row)
    rng.shuffle(out)
    return pd.DataFrame(out, columns=["text", "label"])

def save_csv(df, path):
    df.to_csv(path, index=False, encoding="utf-8")
    print(f"💾 Saved: {path} ({len(df)} rows)")
    print(df['label'].value_counts(), "\n")

# =========================
# SECTION D: MAIN
# =========================
if __name__ == "__main__":
    ph_list, lg_list, kw_list = sanitize_lists()
    print("📊 Labeled counts:",
          f"phishing={len(ph_list)} | legit={len(lg_list)} | keywords={len(kw_list)}")

    df_fixed = make_fixed_dataset(
        ph_list, lg_list, kw_list,
        size=TARGET_SIZE,
        pos_ratio=POS_RATIO,
        augment=AUGMENT_PHISHING,
        max_kw=MAX_KEYWORDS_PER_EMAIL,
        random_state=RANDOM_STATE
    )
    save_csv(df_fixed, OUT_FIXED)

    df_full = make_full_labeled_dataset(
        ph_list, lg_list,
        random_state=RANDOM_STATE
    )
    save_csv(df_full, OUT_FULL)

    print("✅ Done. You can now load either CSV in your training code.")
