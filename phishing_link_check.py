import re
import ipaddress
from difflib import SequenceMatcher


SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'xyz.ru', 'abc123.com',
    'paypal-login.com', 'apple.verify.com', 'google.secure-login.net',
    'secure-facebook.com', 'secure-instagram.com', 'login-microsoft.net'
]


OFFICIAL_DOMAINS = [
    'paypal.com', 'google.com', 'facebook.com', 'microsoft.com', 'apple.com','youtube.com','x.com',
]

def extract_links(email_text):
    """Extract all URLs from text."""
    urls = re.findall(r'(https?://[^\s]+)', email_text)
    return urls

def is_ip_link(url):
    """Detect if link uses IP address."""
    try:
        host = re.findall(r'https?://([^/]+)', url)[0]
        ipaddress.ip_address(host)
        return True
    except:
        return False

def is_similar(a, b):
    """Detect lookalike domains using fuzzy matching."""
    return SequenceMatcher(None, a, b).ratio() > 0.85

def check_links(urls):
    """Check all links for suspicious patterns."""
    score = 0
    for url in urls:
        domain = extract_domain(url)

        
        for bad in SUSPICIOUS_DOMAINS:
            if bad.lower() in domain.lower():
                score += 1

        
        if is_ip_link(url):
            score += 1

        
        for safe in OFFICIAL_DOMAINS:
            if is_similar(domain, safe) and domain.lower() != safe.lower():
                score += 1

    return score

def extract_domain(url):
    """Extract domain from URL."""
    try:
        host = re.findall(r'https?://([^/]+)', url)[0]
        return host.lower()
    except:
        return ""
    