# 🛡️ PhishGuard — Phishing URL Detector

A Streamlit web app that analyzes a URL's structure and returns a
weighted **Risk Score (0–100)** with a HIGH / MEDIUM / LOW verdict
and a feature-by-feature breakdown.

## Features Analyzed
- HTTPS usage
- URL length
- Special character count
- Suspicious keywords (login, verify, secure, etc.)
- Subdomain count
- IP address instead of domain
- Suspicious TLD (.tk, .xyz, .top, etc.)
- Embedded redirect signals

## Setup

```bash
# 1. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
streamlit run app.py
```

The app opens at `http://localhost:8501`.

## Project Structure
```
phishguard/
├── app.py                 # Streamlit UI
├── feature_extractor.py   # Pulls raw features out of a URL
├── risk_score.py          # Weighs features into a 0-100 score (rule-based)
├── generate_dataset.py    # Builds a synthetic labeled dataset
├── train_model.py         # Trains a RandomForest and saves model.pkl
├── ml_score.py             # Loads model.pkl, blends ML + rule scores
├── requirements.txt
└── README.md
```

## ML Layer (Optional, included)

Run once before starting the app:
```bash
python train_model.py
```
This creates `model.pkl`. Once it exists, the Streamlit app shows a
**"Use ML-blended scoring"** toggle that combines the rule-based
score with the trained model's phishing probability (50/50 by
default — change `rule_weight` in `ml_score.py` to shift the
balance).

**Important honesty note for your report/demo:** the training data
in `generate_dataset.py` is **synthetically generated** (not a real
Kaggle dataset), because this environment can't reach kaggle.com.
The synthetic data is cleanly separable, so the model hits ~100%
test accuracy — that reflects the synthetic data being easy, not
real-world performance. For a stronger project:
1. Download a real dataset, e.g. search Kaggle for "Phishing
   Website Dataset" or use the UCI Phishing Websites dataset, on
   your own machine.
2. Replace the `build_dataset()` call in `train_model.py` with
   `pd.read_csv("your_real_dataset.csv")`, mapping its columns to
   the same 8 feature names used here.
3. Re-run `train_model.py` — expect accuracy in the 90-96% range,
   which is a much more credible number to quote.

## How Scoring Works
Each risky signal adds points (see `WEIGHTS` dict in `risk_score.py`):

| Signal | Points |
|---|---|
| No HTTPS | +20 |
| IP address instead of domain | +25 |
| Suspicious keywords found | +15 |
| Excessive subdomains | +15 |
| Suspicious TLD | +12 |
| Long URL (>75 chars) | +10 |
| Excessive special characters | +10 |
| Redirect signal detected | +10 |

**Score ≥ 70** → HIGH RISK · **40–69** → MEDIUM RISK · **< 40** → LOW RISK

## Next Steps / Extensions
- Add live domain-age lookup via WHOIS
- Add a trained ML classifier (scikit-learn) on a Kaggle phishing
  dataset, and blend its probability with the rule-based score
- Deploy free on Streamlit Community Cloud

## Disclaimer
Educational / portfolio project. Analyzes URL structure only — does
not guarantee a site is safe or malicious.
