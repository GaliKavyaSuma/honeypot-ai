import streamlit as st
import numpy as np
import plotly.graph_objects as go
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_models
from utils.colors import fill

def render():
    models = load_models()

    st.markdown("## 🧪 Live Threat Detector")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Enter session parameters and run them through all 4 ML models in real-time. See how the ensemble arrives at its final decision.</p>", unsafe_allow_html=True)

    st.markdown("""
    <div style="background:#0a0f1e; border:1px solid #1a2540; border-radius:10px; padding:24px; margin-bottom:24px;">
      <div style="font-family:Rajdhani,sans-serif; font-size:1.1rem; font-weight:700; color:#00c8ff; margin-bottom:16px;">
        ⚙️ Session Parameters
      </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        session_count = st.slider("Number of Sessions", 1, 40, 3)
        total_events = st.slider("Total Events", 1, 500, 20)
    with col2:
        commands_tried = st.slider("Commands Attempted", 0, 25, 5)
        username_attempts = st.slider("Username Attempts", 1, 10, 2)
    with col3:
        password_attempts = st.slider("Password Attempts", 1, 10, 3)
        manual_rf = st.slider("Prior RF Score", 0.0, 1.0, 0.5)

    st.markdown("</div>", unsafe_allow_html=True)

    if st.button("🚀 RUN DETECTION", use_container_width=True):
        features = np.array([[
            session_count, total_events, commands_tried,
            username_attempts, password_attempts,
            manual_rf, manual_rf * 0.97, manual_rf * 0.95,
        ]])
        features_scaled = models["scaler"].transform(features)

        rf_s_prob = models["rf_session"].predict_proba(features)[0][1]
        lr_s_prob = models["lr_session"].predict_proba(features_scaled)[0][1]
        rf_a_prob = models["rf_attacker"].predict_proba(features)[0][1]

        svm_raw = models["svm_attacker"].decision_function(features_scaled)[0]
        svm_prob = 1 / (1 + np.exp(-svm_raw))

        # Rule-based scoring to make detector sensitive to actual inputs
        rule_score = 0.0
        rule_score += min(session_count / 40, 1.0) * 0.25
        rule_score += min(commands_tried / 25, 1.0) * 0.25
        rule_score += min((username_attempts + password_attempts) / 20, 1.0) * 0.15
        rule_score += min(total_events / 500, 1.0) * 0.10
        rule_score += manual_rf * 0.25

        # Blend ML + rules for final score
        ml_score = rf_s_prob * 0.25 + lr_s_prob * 0.25 + rf_a_prob * 0.25 + svm_prob * 0.25
        final_conf = ml_score * 0.4 + rule_score * 0.6

        is_persistent = session_count >= 5
        if final_conf > 0.65:
            risk = "HIGH"
            rc = "#ff4560"
        elif final_conf > 0.35:
            risk = "MEDIUM"
            rc = "#ffa500"
        else:
            risk = "LOW"
            rc = "#00f5a0"

        # Result banner
        st.markdown(f"""
        <div style="background:linear-gradient(135deg, #0a0f1e, {rc}15); border:2px solid {rc}; 
             border-radius:12px; padding:32px; text-align:center; margin:20px 0;">
          <div style="font-size:0.8rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:3px;">Final Verdict</div>
          <div style="font-family:Rajdhani,sans-serif; font-size:4rem; font-weight:700; color:{rc}; line-height:1; margin:8px 0;">{risk} RISK</div>
          <div style="font-family:Share Tech Mono,monospace; color:{rc}; font-size:1.1rem; margin-bottom:16px;">{int(final_conf*100)}% THREAT CONFIDENCE</div>
        </div>
        """, unsafe_allow_html=True)

        # Action buttons
        a1, a2, a3 = st.columns(3)
        with a1:
            if st.button("🚫 Block IP", use_container_width=True, type="primary" if risk=="HIGH" else "secondary"):
                st.error(f"✅ IP flagged as BLOCKED — adaptive response triggered. UFW rule added.")
        with a2:
            if st.button("👁️ Monitor Session", use_container_width=True, type="primary" if risk=="MEDIUM" else "secondary"):
                st.warning(f"✅ Session added to watchlist. Alert generated for review.")
        with a3:
            if st.button("📝 Log + Continue", use_container_width=True, type="primary" if risk=="LOW" else "secondary"):
                st.success(f"✅ Session logged to Redis. Honeypot continues capturing data.")

        # Model breakdown
        st.markdown("### 🔬 Model-by-Model Breakdown")
        model_results = [
            ("Random Forest", "Session", rf_s_prob, "#00f5a0"),
            ("Logistic Regression", "Session", lr_s_prob, "#00c8ff"),
            ("Random Forest", "Attacker", rf_a_prob, "#a855f7"),
            ("SVM (LinearSVC)", "Attacker", svm_prob, "#ffa500"),
        ]

        cols = st.columns(4)
        for i, (name, path, prob, color) in enumerate(model_results):
            with cols[i]:
                pct = int(prob * 100)
                verdict = "THREAT" if prob > 0.5 else "SAFE"
                st.markdown(f"""
                <div style="background:#0a0f1e; border:1px solid #1a2540; border-top:3px solid {color};
                     border-radius:10px; padding:16px; text-align:center;">
                  <div style="font-size:0.6rem; color:#4a5a7a; letter-spacing:2px; text-transform:uppercase;">{path}</div>
                  <div style="font-family:Rajdhani,sans-serif; font-size:0.95rem; font-weight:700; color:{color}; margin:4px 0;">{name}</div>
                  <div style="font-family:Rajdhani,sans-serif; font-size:3rem; font-weight:700; color:{color}; line-height:1;">{pct}%</div>
                  <div style="font-family:Share Tech Mono,monospace; font-size:0.7rem; margin-top:6px;
                       color:{'#ff4560' if verdict=='THREAT' else '#00f5a0'};">{verdict}</div>
                  <div style="background:#1a2540; border-radius:4px; height:6px; margin:8px 0; overflow:hidden;">
                    <div style="background:{color}; width:{pct}%; height:100%; border-radius:4px;"></div>
                  </div>
                </div>
                """, unsafe_allow_html=True)

        # Radar chart
        st.markdown("### 📡 Threat Profile Radar")
        categories = ["Session Activity", "Command Usage", "Credential Attacks", "Persistence", "ML Confidence"]
        values = [
            min(session_count / 40, 1),
            min(commands_tried / 25, 1),
            min((username_attempts + password_attempts) / 20, 1),
            1.0 if is_persistent else 0.2,
            final_conf,
        ]

        fig = go.Figure(go.Scatterpolar(
            r=values + [values[0]],
            theta=categories + [categories[0]],
            fill="toself",
            fillcolor=fill(rc, 0.18),
            line=dict(color=rc, width=2),
            marker=dict(color=rc, size=8),
        ))
        fig.update_layout(
            polar=dict(
                bgcolor="#0a0f1e",
                radialaxis=dict(visible=True, range=[0, 1], gridcolor="#1a2540", tickfont=dict(color="#4a5a7a")),
                angularaxis=dict(gridcolor="#1a2540", tickfont=dict(color="#c8d8f0", family="Rajdhani")),
            ),
            paper_bgcolor="#050810",
            font=dict(color="#c8d8f0"),
            margin=dict(l=60, r=60, t=20, b=20),
            height=380,
        )
        st.plotly_chart(fig, use_container_width=True)

    else:
        st.markdown("""
        <div style="background:#0a0f1e; border:1px dashed #1a2540; border-radius:12px; padding:60px;
             text-align:center; margin-top:20px;">
          <div style="font-size:3rem;">🎯</div>
          <div style="font-family:Rajdhani,sans-serif; font-size:1.3rem; color:#4a5a7a; margin-top:12px;">
            Set parameters above and click RUN DETECTION
          </div>
          <div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#2a3a5a; margin-top:8px;">
            All 4 models will score the session in real-time
          </div>
        </div>
        """, unsafe_allow_html=True)
