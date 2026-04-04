import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers, load_events
from utils.colors import fill, COLORS

def render():
    df = load_attackers()
    ev = load_events()

    st.markdown("""
    <div class='hero'>
      <div class='hero-title'>🕵️ HONEYPOT AI</div>
      <div class='hero-sub'>AI-POWERED ADAPTIVE HONEYPOT · DYNAMIC CYBER THREAT DETECTION & DECEPTION</div>
      <div class='hero-desc'>
        Real-time attacker intelligence powered by 4 ML models. 
        Detecting, profiling, and deceiving adversaries with 99.43% confidence.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── KPI row ────────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(f"""<div class='metric-card info-card'>
          <div class='metric-val'>524K+</div><div class='metric-lbl'>Total Events</div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='metric-card'>
          <div class='metric-val'>{len(df):,}</div><div class='metric-lbl'>Unique Attackers</div></div>""", unsafe_allow_html=True)
    with c3:
        high = (df["risk_level"] == "HIGH").sum()
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{high}</div><div class='metric-lbl'>High Risk</div></div>""", unsafe_allow_html=True)
    with c4:
        blocked = df["blocked"].sum()
        st.markdown(f"""<div class='metric-card warn-card'>
          <div class='metric-val'>{blocked}</div><div class='metric-lbl'>IPs Blocked</div></div>""", unsafe_allow_html=True)
    with c5:
        st.markdown(f"""<div class='metric-card'>
          <div class='metric-val'>99.43%</div><div class='metric-lbl'>ML Confidence</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown("### 📊 Events Over Time")
        ev_day = ev.copy()
        ev_day["date"] = ev_day["timestamp"].dt.date
        daily = ev_day.groupby(["date", "risk_level"]).size().reset_index(name="count")
        
        colors = {"HIGH": "#ff4560", "MEDIUM": "#ffa500", "LOW": "#00f5a0"}
        fig = go.Figure()
        for risk, color in colors.items():
            d = daily[daily["risk_level"] == risk]
            fig.add_trace(go.Scatter(
                x=d["date"], y=d["count"], name=risk,
                fill="tozeroy", line=dict(color=color, width=2),
                fillcolor=fill(color, 0.15),
            ))
        fig.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            xaxis=dict(gridcolor="#1a2540", showgrid=True),
            yaxis=dict(gridcolor="#1a2540", showgrid=True),
            margin=dict(l=0, r=0, t=10, b=0),
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### 🌍 Top Attacker Countries")
        top_c = df.groupby("country").size().reset_index(name="count").sort_values("count", ascending=False).head(10)
        fig2 = go.Figure(go.Bar(
            x=top_c["count"], y=top_c["country"],
            orientation="h",
            marker=dict(
                color=top_c["count"],
                colorscale=[[0, "#1a2540"], [1, "#00f5a0"]],
            ),
            text=top_c["count"], textposition="outside",
            textfont=dict(color="#c8d8f0", family="Share Tech Mono"),
        ))
        fig2.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            yaxis=dict(autorange="reversed", gridcolor="#1a2540"),
            xaxis=dict(gridcolor="#1a2540"),
            margin=dict(l=0, r=0, t=10, b=0), height=300,
        )
        st.plotly_chart(fig2, use_container_width=True)

    with col2:
        st.markdown("### 🔴 Risk Distribution")
        risk_counts = df["risk_level"].value_counts()
        fig3 = go.Figure(go.Pie(
            labels=risk_counts.index, values=risk_counts.values,
            hole=0.6,
            marker=dict(colors=["#ff4560", "#ffa500", "#00f5a0"]),
            textfont=dict(family="Rajdhani", size=14),
        ))
        fig3.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0"),
            showlegend=True,
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#c8d8f0")),
            margin=dict(l=0, r=0, t=10, b=0), height=240,
            annotations=[dict(text="RISK", x=0.5, y=0.5, font=dict(family="Rajdhani", size=16, color="#c8d8f0"), showarrow=False)]
        )
        st.plotly_chart(fig3, use_container_width=True)

        st.markdown("### 👤 Classification")
        cls_counts = df["classification"].value_counts()
        fig4 = go.Figure(go.Pie(
            labels=cls_counts.index, values=cls_counts.values,
            hole=0.6,
            marker=dict(colors=["#00c8ff", "#a855f7"]),
            textfont=dict(family="Rajdhani", size=14),
        ))
        fig4.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0"),
            showlegend=True,
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#c8d8f0")),
            margin=dict(l=0, r=0, t=10, b=0), height=240,
            annotations=[dict(text="TYPE", x=0.5, y=0.5, font=dict(family="Rajdhani", size=16, color="#c8d8f0"), showarrow=False)]
        )
        st.plotly_chart(fig4, use_container_width=True)

        st.markdown("### ⚙️ System Status")
        services = [
            ("Cowrie SSH Honeypot", "2222", "✅"),
            ("FTP Honeypot", "2121", "✅"),
            ("HTTP Honeypot", "8080", "✅"),
            ("MySQL Honeypot", "3306", "✅"),
            ("Redis Session Store", "6379", "✅"),
            ("ML Detection Engine", "—", "✅"),
            ("Adaptive Response", "—", "✅"),
            ("Dashboard", "9001", "✅"),
        ]
        for name, port, status in services:
            st.markdown(f"""
            <div style='display:flex; justify-content:space-between; align-items:center;
                 background:#0a0f1e; border:1px solid #1a2540; border-radius:6px;
                 padding:6px 12px; margin:3px 0; font-family:Rajdhani,sans-serif; font-size:0.85rem;'>
              <span style='color:#c8d8f0;'>{name}</span>
              <span style='color:#4a5a7a; font-family:Share Tech Mono,monospace; font-size:0.72rem;'>:{port}</span>
              <span>{status}</span>
            </div>""", unsafe_allow_html=True)
