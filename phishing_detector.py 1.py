import re
import whois
from urllib.parse import urlparse
from datetime import datetime, timezone

# Suspicious keywords commonly used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "banking",
    "signin",
    "confirm",
    "password",
    "wallet"
]


def check_https(url):
    """Check if HTTPS is used"""
    return url.startswith("https://")


def check_keywords(url):
    """Check for suspicious keywords"""
    found = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in url.lower():
            found.append(keyword)

    return found


def check_url_structure(url):
    """
    Detect suspicious URL patterns
    """
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # Long URL
    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    # Too many subdomains
    if domain.count('.') > 3:
        score += 1
        reasons.append("Too many subdomains")

    # IP address instead of domain
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain):
        score += 2
        reasons.append("Uses IP address instead of domain name")

    # @ symbol trick
    if "@" in url:
        score += 2
        reasons.append("Contains '@' symbol")

    return score, reasons


def check_domain_age(url):
    """
    Check WHOIS record and calculate domain age
    """
    try:
        domain = urlparse(url).netloc

        if domain.startswith("www."):
            domain = domain[4:]

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        # Some WHOIS servers return a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None, "Domain creation date not found"

        # Fix timezone issue
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        current_time = datetime.now(timezone.utc)

        age_days = (current_time - creation_date).days

        if age_days < 180:
            return age_days, (
                f"Domain age: {age_days} days "
                "(New domain - Suspicious)"
            )

        return age_days, (
            f"Domain age: {age_days} days "
            "(Trusted domain)"
        )

    except Exception as e:
        return None, f"WHOIS Error: {str(e)}"


def analyze_url(url):
    score = 0
    reasons = []

    # HTTPS Check
    if not check_https(url):
        score += 2
        reasons.append("No HTTPS encryption")

    # Suspicious Keywords
    keywords = check_keywords(url)

    if keywords:
        score += len(keywords)
        reasons.append(
            f"Suspicious keywords found: {', '.join(keywords)}"
        )

    # URL Structure Analysis
    structure_score, structure_reasons = check_url_structure(url)

    score += structure_score
    reasons.extend(structure_reasons)

    # Domain Age Analysis
    age, age_message = check_domain_age(url)

    if age is not None and age < 180:
        score += 2

    reasons.append(age_message)

    # Final Classification
    if score <= 2:
        result = "SAFE"
    elif score <= 5:
        result = "WARNING"
    else:
        result = "DANGEROUS"

    return result, score, reasons


def main():
    print("=" * 50)
    print("      PHISHING URL DETECTOR")
    print("=" * 50)

    url = input("Enter URL: ").strip()

    if not url.startswith(("http://", "https://")):
        print("\nPlease enter a valid URL.")
        return

    result, score, reasons = analyze_url(url)

    print("\n" + "=" * 50)
    print("SCAN RESULT")
    print("=" * 50)

    print(f"Status     : {result}")
    print(f"Risk Score : {score}")

    print("\nReasons:")
    for reason in reasons:
        print(f"• {reason}")

    print("=" * 50)


if __name__ == "__main__":
    main()