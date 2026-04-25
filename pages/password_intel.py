import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from collections import Counter
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers

def render():
    df = load_attackers()

    st.markdown("## 🔐 Password Intelligence")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Analyse attacker password strategies. Sophisticated passwords indicate targeted attacks. Common passwords indicate automated bots.</p>", unsafe_allow_html=True)

    st.markdown("""
    <div style='background:#0a0f1e; border:1px solid #a855f740; border-left:3px solid #a855f7;
         border-radius:8px; padding:16px; margin-bottom:20px;'>
      <div style='font-family:Rajdhani,sans-serif; font-weight:700; color:#a855f7; font-size:1.1rem; margin-bottom:8px;'>How Password Intelligence Works</div>
      <div style='display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; margin-top:8px;'>
        <div style='background:#050810; border-radius:6px; padding:12px; border:1px solid #00f5a030;'>
          <div style='font-family:Rajdhani,sans-serif; font-weight:700; color:#00f5a0;'>SCRIPT_KIDDIE</div>
          <div style='font-size:0.78rem; color:#c8d8f0; margin-top:4px;'>Uses only common passwords like "123456", "admin", "password". Fully automated, low threat.</div>
        </div>
        <div style='background:#050810; border-radius:6px; padding:12px; border:1px solid #ffa50030;'>
          <div style='font-family:Rajdhani,sans-serif; font-weight:700; color:#ffa500;'>AUTOMATED</div>
          <div style='font-size:0.78rem; color:#c8d8f0; margin-top:4px;'>Mix of common and slightly varied passwords. Automated tool with a custom wordlist.</div>
        </div>
        <div style='background:#050810; border-radius:6px; padding:12px; border:1px solid #ff456030;'>
          <div style='font-family:Rajdhani,sans-serif; font-weight:700; color:#ff4560;'>TARGETED</div>
          <div style='font-size:0.78rem; color:#c8d8f0; margin-top:4px;'>Uses sophisticated, uncommon passwords. Likely researched your organisation specifically.</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    intel_counts = df["password_intelligence"].value_counts()
    intel_colors = {"SCRIPT_KIDDIE":"#00f5a0","AUTOMATED":"#ffa500","TARGETED":"#ff4560","NONE":"#4a5a7a"}

    c1, c2, c3, c4 = st.columns(4)
    metrics = [
        ("TARGETED", "Targeted Attacks", "#ff4560"),
        ("AUTOMATED", "Automated Tools", "#ffa500"),
        ("SCRIPT_KIDDIE", "Script Kiddies", "#00f5a0"),
        ("NONE", "No Passwords", "#4a5a7a"),
    ]
    for col, (key, label, color) in zip([c1,c2,c3,c4], metrics):
        count = intel_counts.get(key, 0)
        with col:
            st.markdown(f"""<div class='metric-card' style='border-left-color:{color}!important;'>
              <div class='metric-val' style='color:{color}!important;'>{count}</div>
              <div class='metric-lbl'>{label}</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🥧 Password Intelligence Distribution")
        colors = [intel_colors.get(p,"#888") for p in intel_counts.index]
        fig = go.Figure(go.Pie(
            labels=intel_counts.index, values=intel_counts.values,
            hole=0.55, marker=dict(colors=colors),
            textfont=dict(family="Rajdhani", size=13),
        ))
        fig.update_layout(paper_bgcolor="#050810", font=dict(color="#c8d8f0"),
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#c8d8f0")),
            margin=dict(l=0,r=0,t=10,b=0), height=300,
            annotations=[dict(text="INTEL", x=0.5, y=0.5,
                font=dict(family="Rajdhani",size=14,color="#c8d8f0"), showarrow=False)])
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🔑 Most Attempted Passwords")
        all_passwords = []
        for pwds in df["password_attempts"]:
            if isinstance(pwds, list):
                all_passwords.extend(pwds)
        top_pw = Counter(all_passwords).most_common(15)
        pw_df = pd.DataFrame(top_pw, columns=["password","count"])
        fig2 = go.Figure(go.Bar(
            x=pw_df["count"], y=pw_df["password"], orientation="h",
            marker=dict(color=pw_df["count"],
                colorscale=[[0,"#1a2540"],[0.5,"#a855f7"],[1,"#ff4560"]]),
            text=pw_df["count"], textposition="outside",
            textfont=dict(color="#c8d8f0", family="Share Tech Mono"),
        ))
        fig2.update_layout(paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            yaxis=dict(autorange="reversed", gridcolor="#1a2540",
                       tickfont=dict(family="Share Tech Mono",size=11)),
            xaxis=dict(gridcolor="#1a2540"),
            margin=dict(l=0,r=0,t=10,b=0), height=350)
        st.plotly_chart(fig2, use_container_width=True)

    # Password risk vs confidence scatter
    st.markdown("### 📈 Password Risk Score vs Threat Confidence")
    fig3 = go.Figure()
    for intel, color in intel_colors.items():
        sub = df[df["password_intelligence"] == intel]
        if sub.empty: continue
        fig3.add_trace(go.Scatter(
            x=sub["password_risk_score"], y=sub["final_confidence"],
            mode="markers", name=intel,
            marker=dict(color=color, size=6, opacity=0.7),
            hovertemplate=f"<b>{intel}</b><br>Password Risk: %{{x:.2f}}<br>Threat Conf: %{{y:.2f}}<extra></extra>",
        ))
    fig3.update_layout(paper_bgcolor="#050810", plot_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        xaxis=dict(gridcolor="#1a2540", title="Password Risk Score"),
        yaxis=dict(gridcolor="#1a2540", title="Final Threat Confidence"),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=0,r=0,t=10,b=0), height=320)
    st.plotly_chart(fig3, use_container_width=True)

    # Targeted attackers table
    st.markdown("### 🎯 Targeted Attackers — Sophisticated Password Users")
    targeted = df[df["password_intelligence"] == "TARGETED"].sort_values("final_confidence", ascending=False)
    for _, row in targeted.head(10).iterrows():
        pwds = row["password_attempts"]
        pwd_html = "".join([f'<code style="background:#1a0520;color:#a855f7;padding:2px 6px;border-radius:3px;font-size:0.7rem;margin:2px;">{p}</code>' for p in pwds])
        st.markdown(f"""
        <div style='background:#0a0f1e; border:1px solid #1a2540; border-left:3px solid #ff4560;
             border-radius:8px; padding:14px 16px; margin:4px 0;'>
          <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;'>
            <div>
              <span style='font-family:Share Tech Mono,monospace; color:#00c8ff;'>{row["ip"]}</span>
              <span style='font-family:Rajdhani,sans-serif; color:#c8d8f0; margin-left:12px;'>{row["country"]}</span>
              <span style='font-family:Rajdhani,sans-serif; color:#ff4560; font-size:0.8rem; margin-left:12px;'>🎯 TARGETED</span>
            </div>
            <span style='font-family:Rajdhani,sans-serif; font-size:1.4rem; font-weight:700; color:#ff4560;'>{int(row["final_confidence"]*100)}%</span>
          </div>
          <div style='font-size:0.72rem; color:#4a5a7a; margin-bottom:4px;'>Passwords tried: {pwd_html}</div>
        </div>
        """, unsafe_allow_html=True)
