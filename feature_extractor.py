"""
feature_extractor.py
---------------------
Extracts individual characteristics from a URL that are commonly
associated with phishing sites. Each function returns raw data
(numbers / booleans) — the actual "risk points" are assigned later
in risk_score.py, keeping detection logic and scoring separate.
"""

import re
from urllib.parse import urlparse
import tldextract

# ---------------------------------------------------------------
# Suspicious keywords commonly found in phishing URLs
# ---------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "password", "webscr", "ebayisapi",
    "paypal", "suspend", "limited", "urgent", "click", "billing",
    "recover", "unlock", "security", "authenticate",
]

# Suspicious / commonly abused free or cheap TLDs
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "loan", "download", "review", "country", "kim", "science",
]


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme so urlparse works correctly."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
    return url


def check_https(url: str) -> bool:
    """True if the URL uses HTTPS."""
    return urlparse(url).scheme == "https"


def get_url_length(url: str) -> int:
    """Total character length of the URL."""
    return len(url)


def count_special_chars(url: str) -> int:
    """Count of suspicious special characters (@, -, _, //, %, =)."""
    # Ignore the "//" that legitimately follows the scheme (http://)
    body = re.sub(r"^[a-zA-Z]+://", "", url)
    pattern = re.compile(r"[@\-_%=]|//")
    return len(pattern.findall(body))


def check_suspicious_keywords(url: str):
    """Returns list of suspicious keywords found (case-insensitive)."""
    url_lower = url.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]


def count_subdomains(url: str) -> int:
    """
    Counts subdomain segments. e.g.
    'secure.login.paypal.fake.com' -> subdomain part = 'secure.login'
    -> 2 subdomains (excludes the registered domain + suffix).
    """
    ext = tldextract.extract(url)
    if not ext.subdomain:
        return 0
    return len(ext.subdomain.split("."))


def is_ip_address(url: str) -> bool:
    """True if the host is a raw IP address instead of a domain name."""
    host = urlparse(url).netloc.split(":")[0]  # strip port if present
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    return bool(ip_pattern.match(host))


def get_tld(url: str) -> str:
    """Returns the top-level domain, e.g. 'com', 'tk'."""
    ext = tldextract.extract(url)
    return ext.suffix.lower()


def has_suspicious_tld(url: str) -> bool:
    return get_tld(url) in SUSPICIOUS_TLDS


def get_domain(url: str) -> str:
    """Returns registered domain, e.g. 'paypal.com'."""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def count_redirect_chars(url: str) -> int:
    """
    A crude, offline signal for redirect-style URLs:
    counts occurrences of 'http' appearing again after the first
    scheme (e.g. .../redirect?url=http://evil.com), which often
    signals an open-redirect / URL-in-URL trick.
    """
    return url.lower().count("http") - 1  # subtract the URL's own scheme


def extract_all_features(raw_url: str) -> dict:
    """Runs every check and returns a single dict of raw feature values."""
    url = normalize_url(raw_url)
    return {
        "url": url,
        "https": check_https(url),
        "length": get_url_length(url),
        "special_chars": count_special_chars(url),
        "keywords_found": check_suspicious_keywords(url),
        "subdomain_count": count_subdomains(url),
        "is_ip": is_ip_address(url),
        "tld": get_tld(url),
        "suspicious_tld": has_suspicious_tld(url),
        "domain": get_domain(url),
        "redirect_signals": max(count_redirect_chars(url), 0),
    }
