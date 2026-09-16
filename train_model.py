"""
train_model.py
---------------
Trains a RandomForestClassifier on the (synthetic) feature dataset
and saves it as model.pkl for app.py to load at runtime.

Run: python train_model.py
"""

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from generate_dataset import build_dataset

FEATURE_COLUMNS = [
    "https", "length", "special_chars", "keyword_count",
    "subdomain_count", "is_ip", "suspicious_tld", "redirect_signals",
]


def train():
    df = build_dataset(n_per_class=800)  # more data = better generalization
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        random_state=42,
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Test Accuracy: {acc:.3f}\n")
    print(classification_report(y_test, preds, target_names=["Legit", "Phishing"]))

    # Feature importance — useful to explain your project in an interview
    importances = sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_),
        key=lambda x: x[1], reverse=True,
    )
    print("Feature importances:")
    for name, imp in importances:
        print(f"  {name:20s} {imp:.3f}")

    joblib.dump(model, "model.pkl")
    print("\nSaved trained model to model.pkl")


if __name__ == "__main__":
    train()
