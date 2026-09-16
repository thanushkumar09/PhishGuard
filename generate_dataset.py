"""
generate_dataset.py
--------------------
Builds a synthetic labeled dataset (legit=0 / phishing=1) by
programmatically generating realistic-looking URLs of both kinds,
then extracting the SAME features used by the rule-based engine.

Why synthetic? Kaggle isn't reachable from this environment. This
still teaches you the full ML pipeline — and you can swap this file
out later for `pd.read_csv("your_kaggle_dataset.csv")` once you
download a real dataset on your own machine (see README).
"""

import random
import pandas as pd
from feature_extractor import extract_all_features

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "amazon.com",
    "microsoft.com", "nytimes.com", "bbc.com", "python.org",
    "stackoverflow.com", "linkedin.com", "apple.com", "reddit.com",
    "spotify.com", "netflix.com", "dropbox.com", "notion.so",
]

LEGIT_PATHS = [
    "", "/about", "/products", "/blog/2024/update", "/search?q=news",
    "/user/profile", "/docs/getting-started", "/contact", "/pricing",
]

BRAND_NAMES = ["paypal", "amazon", "apple", "netflix", "bankofamerica",
               "chase", "microsoft", "facebook", "instagram", "google"]

PHISH_KEYWORDS = ["secure", "verify", "login", "update", "account",
                   "confirm", "signin", "billing", "suspend", "recover"]

PHISH_TLDS = ["tk", "ml", "ga", "cf", "xyz", "top", "click", "loan"]


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    return f"https://www.{domain}{path}"


def make_phishing_url():
    brand = random.choice(BRAND_NAMES)
    kw1, kw2 = random.sample(PHISH_KEYWORDS, 2)
    style = random.choice(["ip", "subdomain", "tld", "long"])

    if style == "ip":
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        return f"http://{ip}/{kw1}/{kw2}/{brand}"

    if style == "subdomain":
        tld = random.choice(PHISH_TLDS)
        return f"http://{kw1}.{brand}-{kw2}.{tld}/account/update"

    if style == "tld":
        tld = random.choice(PHISH_TLDS)
        return f"http://{brand}-{kw1}-{kw2}.{tld}/login"

    # long, messy URL
    tld = random.choice(PHISH_TLDS)
    junk = "".join(random.choices("abcdefgh12345", k=20))
    return f"http://{brand}.{kw1}-{kw2}-{junk}.{tld}/secure/login?redirect=http://{brand}.com"


def build_dataset(n_per_class: int = 500) -> pd.DataFrame:
    rows = []

    for _ in range(n_per_class):
        url = make_legit_url()
        f = extract_all_features(url)
        rows.append(_to_row(f, label=0))

    for _ in range(n_per_class):
        url = make_phishing_url()
        f = extract_all_features(url)
        rows.append(_to_row(f, label=1))

    df = pd.DataFrame(rows)
    return df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle


def _to_row(f: dict, label: int) -> dict:
    return {
        "https": int(f["https"]),
        "length": f["length"],
        "special_chars": f["special_chars"],
        "keyword_count": len(f["keywords_found"]),
        "subdomain_count": f["subdomain_count"],
        "is_ip": int(f["is_ip"]),
        "suspicious_tld": int(f["suspicious_tld"]),
        "redirect_signals": f["redirect_signals"],
        "label": label,
    }


if __name__ == "__main__":
    df = build_dataset(n_per_class=500)
    df.to_csv("phishing_dataset.csv", index=False)
    print(f"Saved {len(df)} rows to phishing_dataset.csv")
    print(df["label"].value_counts())
