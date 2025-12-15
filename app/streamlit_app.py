import sys
import os
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import plotly.graph_objects as go

# -----------------------------------------------------------
# FIX PYTHON PATH FOR IMPORTING src/
# -----------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))          # .../05Phishing/app
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))       # .../05Phishing
sys.path.append(ROOT_DIR)

from src.feature_extractor import extract_url_features

# -----------------------------------------------------------
# PAGE CONFIG
# -----------------------------------------------------------
st.set_page_config(page_title="Phishing URL Detector", layout="centered")
st.title("🔍 Phishing URL Detection Dashboard")
st.write("Paste any URL below. The model will extract 58 features → classify → visualize.")

# -----------------------------------------------------------
# LOAD MODEL & COLUMNS
# -----------------------------------------------------------
MODEL_PATH = os.path.join(ROOT_DIR, "models", "xgb_phish_model.joblib")
DATA_PATH = os.path.join(ROOT_DIR, "data", "phish_cleaned.csv")

# Sidebar debug
st.sidebar.write("**Model Path:**", MODEL_PATH)
st.sidebar.write("**Data Path:**", DATA_PATH)

# Load model
try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    st.error(f"❌ Failed to load model!\n{e}")
    st.stop()

# Load column order
try:
    cols = pd.read_csv(DATA_PATH).drop(columns=['label']).columns.tolist()
except Exception as e:
    st.error(f"❌ Failed to load cleaned dataset!\n{e}")
    st.stop()

# Precompute global feature importance
try:
    importances = model.named_steps["xgb"].feature_importances_
    importance_df = pd.DataFrame({
        "feature": cols,
        "importance": importances
    }).sort_values("importance", ascending=False)
except:
    importance_df = pd.DataFrame()

# -----------------------------------------------------------
# URL INPUT
# -----------------------------------------------------------
st.write("## 🌐 Enter URL")

url_input = st.text_input("Enter URL here:", "")

if st.button("Predict"):
    if url_input.strip() == "":
        st.warning("Please enter a URL.")
        st.stop()

    # Extract full URL features
    features = extract_url_features(url_input)

    # Convert to DataFrame with correct order
    df_feat = pd.DataFrame([features])
    df_feat = df_feat.reindex(columns=cols, fill_value=0)

    # Predict
    pred = model.predict(df_feat)[0]
    prob = model.predict_proba(df_feat)[0][1]

    # -----------------------------------------------------------
    # RESULT
    # -----------------------------------------------------------
    st.write("---")
    if pred == 1:
        st.error(f"🚨 **PHISHING DETECTED!** — Confidence: {prob:.4f}")
    else:
        st.success(f"🟢 **LEGITIMATE URL** — Confidence: {1 - prob:.4f}")
    st.write("---")

    # -----------------------------------------------------------
    # CONFIDENCE BAR GRAPH
    # -----------------------------------------------------------
    st.write("### 🔥 Prediction Confidence Chart")
    fig_conf, ax = plt.subplots(figsize=(6, 2))
    ax.barh(["Phishing", "Legitimate"], [prob, 1 - prob], color=["red", "green"])
    ax.set_xlim(0, 1)
    ax.set_xlabel("Probability")
    st.pyplot(fig_conf)

    # -----------------------------------------------------------
    # RADAR CHART (URL Feature Profile)
    # -----------------------------------------------------------
    st.write("### 🕸️ URL Feature Radar Profile")

    radar_feats = [
        "nb_dots", "nb_subdomains", "ratio_digits_url", "phish_hints",
        "suspecious_tld", "prefix_suffix", "random_domain", "http_in_path"
    ]

    radar_vals = [features[f] for f in radar_feats]

    fig_radar = go.Figure(
        data=go.Scatterpolar(
            r=radar_vals,
            theta=radar_feats,
            fill='toself',
            marker=dict(color="orange")
        )
    )
    fig_radar.update_layout(
        polar=dict(radialaxis=dict(visible=True)),
        showlegend=False
    )

    st.plotly_chart(fig_radar)

    # -----------------------------------------------------------
    # GLOBAL FEATURE IMPORTANCE
    # -----------------------------------------------------------
    st.write("### 📊 Global Feature Importance (XGBoost)")

    if not importance_df.empty:
        fig_imp, ax2 = plt.subplots(figsize=(8, 6))
        top20 = importance_df.head(20)
        ax2.barh(top20["feature"], top20["importance"], color="purple")
        ax2.set_title("Top 20 Most Important Features")
        plt.gca().invert_yaxis()
        st.pyplot(fig_imp)
    else:
        st.info("Feature importance not available for this model.")

    # -----------------------------------------------------------
    # SHOW RAW EXTRACTED FEATURES
    # -----------------------------------------------------------
    st.write("### 📜 Extracted Feature Values")
    st.json(features)
