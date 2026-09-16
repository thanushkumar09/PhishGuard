"""
ml_score.py
-----------
Loads the trained model (model.pkl) and produces an ML-based
phishing probability for a URL. Also provides a blended score that
combines the rule-based engine (risk_score.py) with the ML model —
this is the "impressive" part you can talk about in interviews:
two independent detection methods agreeing (or disagreeing) on risk.
"""

import os
import joblib
import pandas as pd

from feature_extractor import extract_all_features
from risk_score import calculate_risk_score

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

FEATURE_COLUMNS = [
    "https", "length", "special_chars", "keyword_count",
    "subdomain_count", "is_ip", "suspicious_tld", "redirect_signals",
]

_model = None


def _load_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "model.pkl not found. Run `python train_model.py` first."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def _features_to_row(raw_url: str) -> pd.DataFrame:
    f = extract_all_features(raw_url)
    row = {
        "https": int(f["https"]),
        "length": f["length"],
        "special_chars": f["special_chars"],
        "keyword_count": len(f["keywords_found"]),
        "subdomain_count": f["subdomain_count"],
        "is_ip": int(f["is_ip"]),
        "suspicious_tld": int(f["suspicious_tld"]),
        "redirect_signals": f["redirect_signals"],
    }
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)


def get_ml_probability(raw_url: str) -> float:
    """Returns the model's phishing probability, 0.0-1.0."""
    model = _load_model()
    X = _features_to_row(raw_url)
    proba = model.predict_proba(X)[0][1]  # probability of class "1" (phishing)
    return float(proba)


def calculate_blended_score(raw_url: str, rule_weight: float = 0.5) -> dict:
    """
    Combines the rule-based score and the ML probability into one
    final score. rule_weight=0.5 means a 50/50 blend; adjust to
    trust one method more than the other.
    """
    rule_result = calculate_risk_score(raw_url)
    ml_proba = get_ml_probability(raw_url)
    ml_score = round(ml_proba * 100)

    blended = round(rule_weight * rule_result["score"] + (1 - rule_weight) * ml_score)
    blended = min(blended, 100)

    if blended >= 70:
        level = "HIGH RISK"
        color = "red"
    elif blended >= 40:
        level = "MEDIUM RISK"
        color = "orange"
    else:
        level = "LOW RISK"
        color = "green"

    rule_result.update({
        "rule_score": rule_result["score"],
        "ml_score": ml_score,
        "ml_probability": ml_proba,
        "blended_score": blended,
        "score": blended,
        "level": level,
        "color": color,
    })
    return rule_result


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypa1-secure.verify-login.tk/account/update?redirect=http://evil.com",
        "http://192.168.1.1/login/secure/account",
    ]
    for u in test_urls:
        r = calculate_blended_score(u)
        print(f"\nURL: {r['url']}")
        print(f"Rule Score: {r['rule_score']}/100 | ML Score: {r['ml_score']}/100 "
              f"(prob={r['ml_probability']:.2f})")
        print(f"Blended Score: {r['blended_score']}/100 — {r['level']}")
