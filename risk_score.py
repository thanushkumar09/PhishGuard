"""
risk_score.py
-------------
Turns raw features (from feature_extractor.py) into a weighted
Risk Score out of 100, plus a human-readable breakdown — this is
the "brain" that decides HOW risky each signal is.
"""

from feature_extractor import extract_all_features

# ---------------------------------------------------------------
# Weight table — tune these numbers as you test more URLs.
# Keys must match the logic in calculate_risk_score() below.
# ---------------------------------------------------------------
WEIGHTS = {
    "no_https": 20,
    "long_url": 10,
    "many_special_chars": 10,
    "suspicious_keywords": 15,
    "many_subdomains": 15,
    "is_ip_address": 25,
    "suspicious_tld": 12,
    "redirect_signals": 10,
}

# Thresholds used to decide when a feature "triggers"
LENGTH_THRESHOLD = 75
SPECIAL_CHAR_THRESHOLD = 4
SUBDOMAIN_THRESHOLD = 2


def calculate_risk_score(raw_url: str) -> dict:
    f = extract_all_features(raw_url)
    breakdown = []
    score = 0

    if not f["https"]:
        score += WEIGHTS["no_https"]
        breakdown.append(("No HTTPS (unencrypted connection)", WEIGHTS["no_https"]))

    if f["length"] > LENGTH_THRESHOLD:
        score += WEIGHTS["long_url"]
        breakdown.append((f"Unusually long URL ({f['length']} chars)", WEIGHTS["long_url"]))

    if f["special_chars"] >= SPECIAL_CHAR_THRESHOLD:
        score += WEIGHTS["many_special_chars"]
        breakdown.append((f"Excessive special characters ({f['special_chars']})", WEIGHTS["many_special_chars"]))

    if f["keywords_found"]:
        score += WEIGHTS["suspicious_keywords"]
        kw_list = ", ".join(f["keywords_found"][:5])
        breakdown.append((f"Suspicious keywords found ({kw_list})", WEIGHTS["suspicious_keywords"]))

    if f["subdomain_count"] >= SUBDOMAIN_THRESHOLD:
        score += WEIGHTS["many_subdomains"]
        breakdown.append((f"Excessive subdomains ({f['subdomain_count']})", WEIGHTS["many_subdomains"]))

    if f["is_ip"]:
        score += WEIGHTS["is_ip_address"]
        breakdown.append(("IP address used instead of domain name", WEIGHTS["is_ip_address"]))

    if f["suspicious_tld"]:
        score += WEIGHTS["suspicious_tld"]
        breakdown.append((f"Suspicious top-level domain (.{f['tld']})", WEIGHTS["suspicious_tld"]))

    if f["redirect_signals"] > 0:
        score += WEIGHTS["redirect_signals"]
        breakdown.append((f"Possible embedded redirect URL detected", WEIGHTS["redirect_signals"]))

    score = min(score, 100)

    if score >= 70:
        level = "HIGH RISK"
        color = "red"
    elif score >= 40:
        level = "MEDIUM RISK"
        color = "orange"
    else:
        level = "LOW RISK"
        color = "green"

    return {
        "url": f["url"],
        "domain": f["domain"],
        "score": score,
        "level": level,
        "color": color,
        "breakdown": breakdown,
        "raw_features": f,
    }


if __name__ == "__main__":
    # Quick manual test from the command line
    test_urls = [
        "https://www.google.com",
        "http://paypa1-secure.verify-login.tk/account/update?redirect=http://evil.com",
        "http://192.168.1.1/login/secure/account",
    ]
    for u in test_urls:
        result = calculate_risk_score(u)
        print(f"\nURL: {result['url']}")
        print(f"Risk Score: {result['score']}/100 — {result['level']}")
        for reason, pts in result["breakdown"]:
            print(f"  - {reason} (+{pts})")
