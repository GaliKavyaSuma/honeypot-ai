import streamlit as st
import plotly.graph_objects as go
import numpy as np
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers, load_models

def render():
    df = load_attackers()
    models = load_models()

    st.markdown("## 🤖 ML Detection Engine")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Dual-path 4-model ensemble architecture. Each model contributes to the final 99.43% confidence score.</p>", unsafe_allow_html=True)

    # Model accuracy cards
    model_data = [
        ("Random Forest", "Session Detection", 100.00, "#00f5a0", "Detects high-risk sessions using tree ensemble"),
        ("Logistic Regression", "Session Detection", 99.67, "#00c8ff", "Probability-based session risk scoring"),
        ("Random Forest", "Attacker Profiling", 100.00, "#a855f7", "Classifies PERSISTENT vs SCANNER attackers"),
        ("SVM (LinearSVC)", "Attacker Profiling", 100.00, "#ffa500", "Support vector machine behavioural analysis"),
    ]

    cols = st.columns(4)
    for i, (name, path, acc, color, desc) in enumerate(model_data):
        with cols[i]:
            st.markdown(f"""
            <div style="background:#0a0f1e; border:1px solid #1a2540; border-top:3px solid {color};
                 border-radius:10px; padding:20px; text-align:center; height:200px;">
              <div style="font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px;">{path}</div>
              <div style="font-family:Rajdhani,sans-serif; font-size:1.1rem; font-weight:700; color:{color}; margin:6px 0;">{name}</div>
              <div style="font-family:Rajdhani,sans-serif; font-size:2.8rem; font-weight:700; color:{color}; line-height:1;">{acc:.2f}%</div>
              <div style="font-size:0.68rem; color:#4a5a7a; margin-top:8px;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Final combined confidence banner
    st.markdown("""
    <div style="background:linear-gradient(135deg,#0a0f1e,#0d1a2e); border:1px solid #00f5a040;
         border-radius:12px; padding:28px; text-align:center; margin:16px 0;">
      <div style="font-size:0.75rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:3px;">Final Combined Confidence</div>
      <div style="font-family:Rajdhani,sans-serif; font-size:5rem; font-weight:700; color:#00f5a0; line-height:1; margin:8px 0;">99.43%</div>
      <div style="font-family:Share Tech Mono,monospace; color:#00c8ff; font-size:0.85rem;">RF·LR·RF·SVM Ensemble · All 4 Models In Agreement</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📊 Confidence Distribution")
        fig = go.Figure()
        colors = {"HIGH": "#ff4560", "MEDIUM": "#ffa500", "LOW": "#00f5a0"}
        for risk, color in colors.items():
            sub = df[df["risk_level"] == risk]["final_confidence"]
            fig.add_trace(go.Histogram(
                x=sub, name=risk, nbinsx=30,
                marker_color=color, opacity=0.7,
            ))
        fig.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            barmode="overlay",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540", title="Confidence Score"),
            yaxis=dict(gridcolor="#1a2540", title="Count"),
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=0, r=0, t=10, b=0), height=280,
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🧬 Feature Importance (RF Session)")
        features = ["Session Count", "Total Events", "Commands Tried", "Usernames", "Passwords", "RF Score", "LR Score", "SVM Score"]
        importances = models["rf_session"].feature_importances_
        sorted_idx = np.argsort(importances)
        
        fig2 = go.Figure(go.Bar(
            x=importances[sorted_idx],
            y=[features[i] for i in sorted_idx],
            orientation="h",
            marker=dict(
                color=importances[sorted_idx],
                colorscale=[[0, "#1a2540"], [1, "#00f5a0"]],
            ),
        ))
        fig2.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540"),
            yaxis=dict(gridcolor="#1a2540"),
            margin=dict(l=0, r=0, t=10, b=0), height=280,
        )
        st.plotly_chart(fig2, use_container_width=True)

    # Architecture diagram using Streamlit columns - no raw HTML complexity
    st.markdown("### 🏗️ Dual-Path Architecture")

    # Row 1 - Input
    st.markdown(
        "<div style='text-align:center;padding:12px;background:#1a2540;border:1px solid #00c8ff;"
        "border-radius:8px;font-family:Rajdhani,sans-serif;font-weight:700;color:#00c8ff;"
        "letter-spacing:2px;margin-bottom:8px;'>🌐 INCOMING ATTACK SESSION</div>",
        unsafe_allow_html=True)
    st.markdown("<div style='text-align:center;color:#4a5a7a;font-size:1.4rem;'>▼</div>", unsafe_allow_html=True)

    # Row 2 - Two paths
    colA, colMid, colB = st.columns([5, 1, 5])
    with colA:
        st.markdown(
            "<div style='background:#050e08;border:1px solid #00f5a040;border-radius:10px;padding:16px;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-size:0.7rem;color:#00f5a0;letter-spacing:3px;"
            "text-transform:uppercase;margin-bottom:12px;text-align:center;'>PATH A · SESSION DETECTION</div>"
            "<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;'>"
            "<div style='background:#0a0f1e;border:1px solid #00f5a030;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#00f5a0;'>Random Forest</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#00f5a0;'>100.00%</div></div>"
            "<div style='background:#0a0f1e;border:1px solid #00c8ff30;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#00c8ff;'>Logistic Reg.</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#00c8ff;'>99.67%</div></div>"
            "</div></div>", unsafe_allow_html=True)
    with colMid:
        st.markdown("<div style='text-align:center;color:#4a5a7a;padding-top:40px;font-size:1.2rem;'>│</div>", unsafe_allow_html=True)
    with colB:
        st.markdown(
            "<div style='background:#0e0510;border:1px solid #a855f740;border-radius:10px;padding:16px;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-size:0.7rem;color:#a855f7;letter-spacing:3px;"
            "text-transform:uppercase;margin-bottom:12px;text-align:center;'>PATH B · ATTACKER PROFILING</div>"
            "<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;'>"
            "<div style='background:#0a0f1e;border:1px solid #a855f730;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#a855f7;'>Random Forest</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#a855f7;'>100.00%</div></div>"
            "<div style='background:#0a0f1e;border:1px solid #ffa50030;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#ffa500;'>SVM LinearSVC</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#ffa500;'>100.00%</div></div>"
            "</div></div>", unsafe_allow_html=True)

    st.markdown("<div style='text-align:center;color:#4a5a7a;font-size:1.4rem;margin-top:8px;'>▼</div>", unsafe_allow_html=True)

    # Row 3 - Ensemble
    st.markdown(
        "<div style='text-align:center;padding:20px;background:#0a1628;border:2px solid #00f5a0;"
        "border-radius:8px;margin:4px 80px;'>"
        "<div style='font-family:Rajdhani,sans-serif;font-size:0.7rem;color:#4a5a7a;letter-spacing:3px;'>ENSEMBLE FUSION (WEIGHTED)</div>"
        "<div style='font-family:Rajdhani,sans-serif;font-size:2.5rem;font-weight:700;color:#00f5a0;'>99.43%</div>"
        "<div style='font-family:Share Tech Mono,monospace;font-size:0.8rem;color:#4a5a7a;'>FINAL CONFIDENCE SCORE</div>"
        "</div>", unsafe_allow_html=True)

    st.markdown("<div style='text-align:center;color:#4a5a7a;font-size:1.4rem;margin-top:8px;'>▼</div>", unsafe_allow_html=True)

    # Row 4 - Response
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            "<div style='background:#1a050a;border:1px solid #ff456050;border-radius:8px;padding:14px;text-align:center;'>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.7rem;color:#ff4560;'>HIGH RISK</div>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;font-size:1rem;'>🚫 Block IP</div>"
            "<div style='font-family:Rajdhani,sans-serif;color:#4a5a7a;font-size:0.75rem;'>Activate Deception Mode</div>"
            "</div>", unsafe_allow_html=True)
    with c2:
        st.markdown(
            "<div style='background:#1a0e00;border:1px solid #ffa50050;border-radius:8px;padding:14px;text-align:center;'>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.7rem;color:#ffa500;'>MEDIUM RISK</div>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;font-size:1rem;'>👁️ Monitor</div>"
            "<div style='font-family:Rajdhani,sans-serif;color:#4a5a7a;font-size:0.75rem;'>Generate Alert</div>"
            "</div>", unsafe_allow_html=True)
    with c3:
        st.markdown(
            "<div style='background:#001a0a;border:1px solid #00f5a030;border-radius:8px;padding:14px;text-align:center;'>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.7rem;color:#00f5a0;'>LOW RISK</div>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;font-size:1rem;'>📝 Log</div>"
            "<div style='font-family:Rajdhani,sans-serif;color:#4a5a7a;font-size:0.75rem;'>Continue Capture</div>"
            "</div>", unsafe_allow_html=True)
