"""
app.py
------
PhishGuard — Streamlit front-end.
Run with:  streamlit run app.py
"""

import os
import streamlit as st
from risk_score import calculate_risk_score

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
ML_AVAILABLE = os.path.exists(MODEL_PATH)
if ML_AVAILABLE:
    from ml_score import calculate_blended_score

st.set_page_config(
    page_title="PhishGuard | URL Risk Analyzer", page_icon="🛡️", layout="centered"
)

st.title("🛡️ PhishGuard")
st.caption("Paste a URL below and get an instant phishing-risk analysis.")

use_ml = False
if ML_AVAILABLE:
    use_ml = st.toggle("🤖 Use ML-blended scoring (rules + trained model)", value=True)
else:
    st.info(
        "ML model not found — run `python train_model.py` to enable ML-blended scoring."
    )

# --- Session state: keeps the URL box and last result until explicitly reset ---
if "url_input" not in st.session_state:
    st.session_state.url_input = ""
if "result" not in st.session_state:
    st.session_state.result = None


def reset_analysis():
    """Clears the input box and any previous result — runs before the
    widgets redraw, so it's safe to reset the text_input's own key here."""
    st.session_state.url_input = ""
    st.session_state.result = None


url_input = st.text_input(
    "Enter a URL to analyze",
    key="url_input",
    placeholder="e.g. http://paypa1-secure-login.tk/verify",
)

col1, col2 = st.columns([3, 1])
with col1:
    analyze_clicked = st.button(
        "🔍 Analyze URL", type="primary", use_container_width=True
    )
with col2:
    st.button("🔄 Reset", on_click=reset_analysis, use_container_width=True)

if analyze_clicked:
    if not url_input.strip():
        st.warning("Please enter a URL first.")
        st.session_state.result = None
    else:
        if use_ml and ML_AVAILABLE:
            st.session_state.result = calculate_blended_score(url_input)
        else:
            st.session_state.result = calculate_risk_score(url_input)

result = st.session_state.result

if result:
    st.markdown("---")
    st.subheader(f"Analyzed: `{result['url']}`")

    # --- Risk score + progress bar ---
    color_map = {"red": "🔴", "orange": "🟠", "green": "🟢"}
    st.markdown(
        f"### Risk Score: {result['score']}/100 — {color_map[result['color']]} **{result['level']}**"
    )
    st.progress(result["score"] / 100)

    if use_ml and ML_AVAILABLE:
        c1, c2 = st.columns(2)
        c1.metric("Rule-based score", f"{result['rule_score']}/100")
        c2.metric("ML model score", f"{result['ml_score']}/100")

    # --- Recommendation ---
    if result["level"] == "HIGH RISK":
        st.error("⚠️ Do NOT enter credentials or personal information on this site.")
    elif result["level"] == "MEDIUM RISK":
        st.warning(
            "⚠️ Proceed with caution — verify this site through official channels."
        )
    else:
        st.success("✅ No major red flags detected. Still stay alert online.")

    # --- Feature breakdown ---
    st.markdown("#### 📋 Breakdown")
    if result["breakdown"]:
        for reason, pts in result["breakdown"]:
            st.markdown(f"❌ {reason}  \u2003`+{pts} pts`")
    else:
        st.markdown("✅ No suspicious signals detected.")

    # --- Raw feature details (expandable) ---
    with st.expander("🔬 Full technical details"):
        f = result["raw_features"]
        st.json(
            {
                "domain": result["domain"],
                "https": f["https"],
                "url_length": f["length"],
                "special_char_count": f["special_chars"],
                "keywords_found": f["keywords_found"],
                "subdomain_count": f["subdomain_count"],
                "is_ip_address": f["is_ip"],
                "tld": f["tld"],
                "suspicious_tld": f["suspicious_tld"],
                "redirect_signals": f["redirect_signals"],
            }
        )

st.markdown("---")
st.caption(
    "PhishGuard analyzes URL structure only (no live browsing). Educational / portfolio project."
)
