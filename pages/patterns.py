import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from collections import Counter
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers, load_events

def render():
    df = load_attackers()
    ev = load_events()

    st.markdown("## 🎯 Attack Pattern Recognition")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Identify known botnet signatures, brute-force tools, and targeted attack techniques from command sequences and credential patterns.</p>", unsafe_allow_html=True)

    PATTERN_INFO = {
        "Mirai Botnet": {
            "color": "#ff4560", "icon": "🤖",
            "desc": "IoT botnet — targets default credentials on routers and IP cameras. Signature: /bin/busybox MIRAI command.",
            "signatures": ["/bin/busybox MIRAI", "enable", "system", "shell"],
            "danger": "CRITICAL — can launch DDoS attacks from thousands of compromised devices",
        },
        "Medusa Brute-forcer": {
            "color": "#ffa500", "icon": "🔑",
            "desc": "Automated SSH brute-force tool. Tries massive credential dictionaries rapidly.",
            "signatures": ["Rapid credential attempts", "No commands after login", "Many username variants"],
            "danger": "HIGH — can cycle through millions of passwords per hour",
        },
        "Hajime Worm": {
            "color": "#a855f7", "icon": "🪱",
            "desc": "Self-propagating IoT worm. Known to fight other botnets for device control.",
            "signatures": ["./dvrHelper", "cat /proc/cpuinfo", "uname -a"],
            "danger": "HIGH — self-replicating, spreads to other vulnerable devices",
        },
        "Mozi Botnet": {
            "color": "#00c8ff", "icon": "🌐",
            "desc": "P2P botnet targeting home routers. Uses BitTorrent DHT protocol for C2.",
            "signatures": ["chmod 777", "./mozi", "wget http://mozi."],
            "danger": "HIGH — decentralised, hard to take down",
        },
        "Manual/Targeted": {
            "color": "#ff4560", "icon": "👤",
            "desc": "Human attacker operating manually. Methodical, reads sensitive files, uses advanced techniques.",
            "signatures": ["cat /etc/shadow", "find / -perm -4000", "nc -lvp", "cat passwords.txt"],
            "danger": "CRITICAL — skilled human attacker, likely targeted your system specifically",
        },
        "Unknown Scanner": {
            "color": "#00f5a0", "icon": "📡",
            "desc": "Automated port scanner. Just probing for open ports, no commands attempted.",
            "signatures": ["No commands", "Single connection", "No login"],
            "danger": "LOW — reconnaissance only, likely automated mass scan",
        },
    }

    # Pattern distribution
    pattern_counts = df["attack_pattern"].value_counts()

    st.markdown("### 📊 Detected Attack Patterns")
    cols = st.columns(3)
    for i, (pattern, count) in enumerate(pattern_counts.items()):
        info = PATTERN_INFO.get(pattern, {"color":"#888","icon":"❓","desc":"","danger":""})
        with cols[i % 3]:
            st.markdown(f"""
            <div style='background:#0a0f1e; border:1px solid #1a2540; border-top:3px solid {info["color"]};
                 border-radius:10px; padding:16px; margin-bottom:12px;'>
              <div style='font-size:1.8rem;'>{info["icon"]}</div>
              <div style='font-family:Rajdhani,sans-serif; font-size:1.1rem; font-weight:700; color:{info["color"]}; margin:4px 0;'>{pattern}</div>
              <div style='font-family:Rajdhani,sans-serif; font-size:2rem; font-weight:700; color:#c8d8f0;'>{count}</div>
              <div style='font-size:0.72rem; color:#4a5a7a; margin:6px 0;'>{info["desc"]}</div>
              <div style='background:{info["color"]}15; border:1px solid {info["color"]}30; border-radius:4px;
                   padding:4px 8px; font-family:Share Tech Mono,monospace; font-size:0.65rem; color:{info["color"]}; margin-top:8px;'>
                ⚠ {info["danger"]}
              </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 🥧 Pattern Breakdown")
        colors = [PATTERN_INFO.get(p, {}).get("color","#888") for p in pattern_counts.index]
        fig = go.Figure(go.Pie(
            labels=pattern_counts.index, values=pattern_counts.values,
            hole=0.5, marker=dict(colors=colors),
            textfont=dict(family="Rajdhani", size=13),
        ))
        fig.update_layout(paper_bgcolor="#050810", font=dict(color="#c8d8f0"),
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#c8d8f0")),
            margin=dict(l=0,r=0,t=10,b=0), height=300,
            annotations=[dict(text="PATTERNS", x=0.5, y=0.5,
                font=dict(family="Rajdhani",size=13,color="#c8d8f0"), showarrow=False)])
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🔐 Pattern vs Risk Level")
        cross = pd.crosstab(df["attack_pattern"], df["risk_level"])
        fig2 = go.Figure()
        risk_colors = {"HIGH":"#ff4560","MEDIUM":"#ffa500","LOW":"#00f5a0"}
        for risk in ["HIGH","MEDIUM","LOW"]:
            if risk in cross.columns:
                fig2.add_trace(go.Bar(name=risk, x=cross.index, y=cross[risk],
                    marker_color=risk_colors[risk]))
        fig2.update_layout(barmode="stack", paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540", tickangle=-20),
            yaxis=dict(gridcolor="#1a2540"),
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=0,r=0,t=10,b=60), height=300)
        st.plotly_chart(fig2, use_container_width=True)

    # Signature details
    st.markdown("### 🔬 Pattern Signatures & How We Detect Them")
    selected = st.selectbox("Select a pattern to inspect", list(PATTERN_INFO.keys()))
    info = PATTERN_INFO[selected]
    attackers_of_type = df[df["attack_pattern"] == selected]

    col1, col2 = st.columns(2)
    with col1:
        sigs_html = "".join([f'<div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; color:{info["color"]}; padding:3px 0;">→ {sig}</div>' for sig in info["signatures"]])
        st.markdown(f"""
        <div style='background:#0a0f1e; border:1px solid {info["color"]}40; border-radius:10px; padding:20px;'>
          <div style='font-family:Rajdhani,sans-serif; font-size:1.3rem; font-weight:700; color:{info["color"]};'>{info["icon"]} {selected}</div>
          <div style='font-size:0.85rem; color:#c8d8f0; margin:10px 0; line-height:1.6;'>{info["desc"]}</div>
          <div style='font-family:Rajdhani,sans-serif; font-size:0.7rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px; margin-top:12px;'>Detection Signatures</div>
          {sigs_html}
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div style='background:#0a0f1e; border:1px solid #1a2540; border-radius:10px; padding:20px;'>
          <div style='font-family:Rajdhani,sans-serif; font-size:0.7rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px;'>Attackers Matching This Pattern</div>
          <div style='font-family:Rajdhani,sans-serif; font-size:3rem; font-weight:700; color:{info["color"]};'>{len(attackers_of_type)}</div>
          <div style='font-family:Rajdhani,sans-serif; font-size:0.7rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px; margin-top:12px;'>High Risk Among Them</div>
          <div style='font-family:Rajdhani,sans-serif; font-size:2rem; font-weight:700; color:#ff4560;'>{(attackers_of_type["risk_level"]=="HIGH").sum()}</div>
          <div style='font-family:Rajdhani,sans-serif; font-size:0.7rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px; margin-top:12px;'>Avg Confidence</div>
          <div style='font-family:Rajdhani,sans-serif; font-size:2rem; font-weight:700; color:#00f5a0;'>{attackers_of_type["final_confidence"].mean():.1%}</div>
        </div>
        """, unsafe_allow_html=True)
