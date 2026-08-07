# ============================================================
# app.py — Phishing URL Detection System Streamlit Web Application
# Phishing Short URL Detection & Prevention System
# ============================================================

import streamlit as st
import pandas as pd
import sys
import os
import time

# Add src/ to path so we can import our pipeline
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from url_pipeline import check_url, PHISHTANK_DB

# ── Page Configuration ────────────────────────────────────
st.set_page_config(
    page_title = "Phishing URL Detection System — Phishing URL Detector",
    page_icon  = "️",
    layout     = "centered"
)

# ── Custom CSS Styling ────────────────────────────────────
st.markdown("""
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        text-align: center;
        color: #1a1a2e;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1rem;
        text-align: center;
        color: #555;
        margin-bottom: 2rem;
    }
    .verdict-safe {
        background-color: #d4edda;
        border-left: 6px solid #28a745;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        font-size: 1.3rem;
        font-weight: bold;
        color: #155724;
    }
    .verdict-phishing {
        background-color: #f8d7da;
        border-left: 6px solid #dc3545;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        font-size: 1.3rem;
        font-weight: bold;
        color: #721c24;
    }
    .verdict-suspicious {
        background-color: #fff3cd;
        border-left: 6px solid #ffc107;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        font-size: 1.3rem;
        font-weight: bold;
        color: #856404;
    }
    .info-box {
        background-color: #f0f4ff;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .step-label {
        font-size: 0.85rem;
        color: #888;
        font-weight: 600;
        text-transform: uppercase;
    }
    </style>
""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────
st.markdown(
    '<div class="main-title">️ Phishing URL Detector</div>',
    unsafe_allow_html=True
)
st.markdown(
    '<div class="sub-title">Phishing Short URL Detection & Prevention System (Phishing URL Detection System)<br>'
    'Detects phishing attacks hidden behind short URLs using ML + Blacklist</div>',
    unsafe_allow_html=True
)

st.divider()


# ── Session State — Results History ──────────────────────
# Session state persists data across button clicks
if 'history' not in st.session_state:
    st.session_state.history = []


# ── Input Section ─────────────────────────────────────────
st.subheader(" Check a URL")

url_input = st.text_input(
    label       = "Enter a short URL or any URL to check:",
    placeholder = "e.g. https://bit.ly/example or https://tinyurl.com/abc",
    help        = "Paste any URL — short or full — and click Check URL"
)

col1, col2 = st.columns([1, 4])
with col1:
    check_btn = st.button("Check URL", type="primary", use_container_width=True)
with col2:
    clear_btn = st.button("Clear History", use_container_width=True)

if clear_btn:
    st.session_state.history = []
    st.success("History cleared!")


# ── Main Detection Logic ──────────────────────────────────
if check_btn:
    if not url_input.strip():
        st.warning("Please enter a URL first.")
    else:
        with st.spinner("Analysing URL... please wait"):

            # Run complete pipeline
            result = check_url(
                url_input.strip(),
                db_path = PHISHTANK_DB,
                verbose = False
            )

        st.divider()
        st.subheader(" Detection Results")

        # ── Verdict Banner ────────────────────────────────
        verdict = result['final_verdict']

        if verdict == 'PHISHING':
            st.markdown(
                '<div class="verdict-phishing">'
                ' PHISHING DETECTED — This URL is dangerous!'
                '</div>',
                unsafe_allow_html=True
            )
        elif verdict == 'SUSPICIOUS':
            st.markdown(
                '<div class="verdict-suspicious">'
                ' SUSPICIOUS — Proceed with extreme caution'
                '</div>',
                unsafe_allow_html=True
            )
        elif verdict == 'INVALID URL':
            st.error(f" Invalid URL: {result.get('error', 'Unknown error')}")
        else:
            st.markdown(
                '<div class="verdict-safe">'
                ' SAFE — This URL appears legitimate'
                '</div>',
                unsafe_allow_html=True
            )

        st.caption(f"Reason: {result.get('verdict_reason', 'N/A')}")
        st.write("")

        # ── Details Grid ──────────────────────────────────
        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown('<p class="step-label">Original URL</p>',
                       unsafe_allow_html=True)
            st.code(result['input_url'], language=None)

            st.markdown('<p class="step-label">Expanded URL</p>',
                       unsafe_allow_html=True)
            expanded = result.get('expanded_url') or 'Could not expand'
            st.code(expanded, language=None)

        with col_b:
            st.markdown('<p class="step-label">PhishTank Result</p>',
                       unsafe_allow_html=True)
            pt = result.get('phishtank_result', 'N/A')
            if pt == 'PHISHING':
                st.error(f" {pt}")
            elif pt == 'SAFE':
                st.success(f" {pt}")
            else:
                st.warning(f" {pt}")

            st.markdown('<p class="step-label">ML Model Result</p>',
                       unsafe_allow_html=True)
            if result.get('ml_result'):
                ml    = result['ml_result']
                prob  = ml['phishing_prob']
                conf  = ml['confidence']
                if ml['is_phishing'] and prob >= 70:
                    st.error(f" Phishing — {prob}% confidence")
                elif ml['is_phishing']:
                    st.warning(f" Uncertain — {prob}% phishing probability")
                else:
                    st.success(f" Legitimate — {ml['legitimate_prob']}% confidence")

        # ── Confidence Gauge ──────────────────────────────
        if result.get('ml_result'):
            st.write("")
            st.markdown('<p class="step-label">Phishing Probability Gauge</p>',
                       unsafe_allow_html=True)
            prob = result['ml_result']['phishing_prob']

            # Color changes based on risk level
            if prob >= 70:
                color = "red"
            elif prob >= 50:
                color = "orange"
            else:
                color = "green"

            st.markdown(f"""
                <div style="background:#eee; border-radius:10px; height:20px; width:100%">
                    <div style="background:{color}; width:{prob}%; height:20px;
                                border-radius:10px; text-align:center;
                                color:white; font-size:0.8rem; line-height:20px">
                        {prob}%
                    </div>
                </div>
                <p style="text-align:right; font-size:0.75rem; color:#888">
                    0% = Safe &nbsp;&nbsp; 70%+ = Phishing threshold &nbsp;&nbsp; 100% = Certain phishing
                </p>
            """, unsafe_allow_html=True)

        # ── Save to History ───────────────────────────────
        st.session_state.history.append({
            'URL'          : result['input_url'],
            'Expanded'     : str(result.get('expanded_url', 'N/A'))[:40] + '...'
                             if result.get('expanded_url') and
                             len(str(result.get('expanded_url', ''))) > 40
                             else result.get('expanded_url', 'N/A'),
            'PhishTank'    : result.get('phishtank_result', 'N/A'),
            'ML Prob'      : f"{result['ml_result']['phishing_prob']}%"
                             if result.get('ml_result') else 'N/A',
            'Verdict'      : verdict
        })


# ── History Table ─────────────────────────────────────────
if st.session_state.history:
    st.divider()
    st.subheader(f" Session History ({len(st.session_state.history)} URLs checked)")

    history_df = pd.DataFrame(st.session_state.history)

    # Color the verdict column
    def color_verdict(val):
        if val == 'PHISHING':
            return 'background-color: #f8d7da; color: #721c24; font-weight: bold'
        elif val == 'SUSPICIOUS':
            return 'background-color: #fff3cd; color: #856404; font-weight: bold'
        elif val == 'SAFE':
            return 'background-color: #d4edda; color: #155724; font-weight: bold'
        return ''

    styled_df = history_df.style.applymap(
        color_verdict, subset=['Verdict']
    )
    st.dataframe(styled_df, use_container_width=True)

    # Download button
    csv = history_df.to_csv(index=False)
    st.download_button(
        label     = "Download Results as CSV",
        data      = csv,
        file_name = "Phishing URL Detection System_results.csv",
        mime      = "text/csv"
    )


# ── Sidebar Info ──────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=80)
    st.title("About Phishing URL Detection System")
    st.markdown("""
    **Phishing Short URL Detection & Prevention System**

    Based on research paper:
    *"Detection and Prevention of Phishing Short URLs Using
    Machine Learning and Blacklist Approaches"*
    Odeh & Hijazi, 2025

    ---
    **How it works:**
    1. Validates the input URL
    2. Expands short URLs
    3. Checks PhishTank blacklist
    4. Extracts 30 features
    5. Runs Gradient Boosting ML model
    6. Returns final verdict

    ---
    **Best Model:**
    Gradient Boosting — 95%+ accuracy

    **Verdict Levels:**
    -  SAFE
    -  SUSPICIOUS
    -  PHISHING

    ---
    **Confidence Threshold:** 70%
    """)

    st.divider()
    st.caption("Built with Python, Scikit-learn & Streamlit")