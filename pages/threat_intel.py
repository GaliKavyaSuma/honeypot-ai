import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers
from utils.colors import fill

def render():
    df = load_attackers()

    st.markdown("## 🛡️ Threat Intelligence Feed")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Cross-reference attacker IPs against global threat intelligence databases. Known malicious IPs flagged automatically.</p>", unsafe_allow_html=True)

    # How it works explanation
    st.markdown("""
    <div style='background:#0a0f1e; border:1px solid #1a2540; border-left:3px solid #00c8ff;
         border-radius:8px; padding:16px; margin-bottom:20px;'>
      <div style='font-family:Rajdhani,sans-serif; font-weight:700; color:#00c8ff; margin-bottom:8px;'>How This Works</div>
      <div style='font-family:Inter,sans-serif; font-size:0.85rem; color:#c8d8f0; line-height:1.6;'>
        Every attacker IP is checked against <b style='color:#00f5a0;'>AbuseIPDB</b> — a global crowdsourced database of
        malicious IPs reported by security researchers worldwide. If an IP has been reported before,
        we know it's a repeat offender. The <b style='color:#ffa500;'>Abuse Score</b> (0–100) reflects
        how many times it's been reported across the internet.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # AbuseIPDB API section
    st.markdown("### 🔑 AbuseIPDB Live Lookup")
    
    st.markdown("""
    <div style='background:#0a0f1e; border:1px solid #00f5a040; border-radius:8px; padding:12px 16px; margin-bottom:12px;'>
      <div style='font-family:Rajdhani,sans-serif; color:#00f5a0; font-weight:700; margin-bottom:4px;'>API Key — Optional</div>
      <div style='font-size:0.82rem; color:#c8d8f0;'>
        Without a key, the lookup uses <b>simulated threat data</b> — still great for demo purposes.<br>
        For real live lookups: get a free key at 
        <a href='https://www.abuseipdb.com/register' target='_blank' style='color:#00c8ff;'>abuseipdb.com/register</a> 
        (free, 1000 checks/day, no credit card).
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([3,1])
    with col1:
        test_ip = st.text_input("Enter any IP to check", placeholder="e.g. 185.220.101.45")
    with col2:
        api_key = st.text_input("AbuseIPDB API Key (optional)", type="password", placeholder="leave blank for demo")

    if st.button("🔍 Check IP Now", use_container_width=True):
        if test_ip:
            if api_key:
                # Real API call
                import requests
                try:
                    resp = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": api_key, "Accept": "application/json"},
                        params={"ipAddress": test_ip, "maxAgeInDays": 90},
                        timeout=5
                    )
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    country = data.get("countryCode", "Unknown")
                    isp = data.get("isp", "Unknown")
                    domain = data.get("domain", "Unknown")
                    last_reported = data.get("lastReportedAt", "Never")
                    source = "🟢 Live AbuseIPDB Data"
                except Exception as e:
                    st.error(f"API Error: {e}")
                    return
            else:
                # Simulated demo data
                import hashlib, random as rnd
                seed = int(hashlib.md5(test_ip.encode()).hexdigest()[:8], 16)
                rnd.seed(seed)
                score = rnd.randint(0, 100)
                reports = rnd.randint(0, 500)
                country = rnd.choice(["CN","RU","US","DE","NL","UA","BR","IN"])
                isp = rnd.choice(["AS12345 DigitalOcean LLC","AS16509 Amazon.com","AS9009 M247 Ltd","AS60068 Datacamp Ltd"])
                domain = rnd.choice(["digitalocean.com","amazonaws.com","m247.com","unknown"])
                last_reported = "2026-03-15T12:00:00+00:00"
                source = "🔵 Simulated Demo Data (no API key)"

            color = "#ff4560" if score > 75 else "#ffa500" if score > 25 else "#00f5a0"
            verdict = "MALICIOUS" if score > 75 else "SUSPICIOUS" if score > 25 else "CLEAN"
            st.markdown(f"""
            <div style='background:#0a0f1e; border:2px solid {color}; border-radius:10px; padding:20px; margin-top:12px;'>
              <div style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#4a5a7a; margin-bottom:12px;'>{source}</div>
              <div style='display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:16px;'>
                <div style='text-align:center;'>
                  <div style='font-family:Rajdhani,sans-serif; font-size:2.8rem; font-weight:700; color:{color};'>{score}%</div>
                  <div style='font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px;'>Abuse Score</div>
                </div>
                <div style='text-align:center;'>
                  <div style='font-family:Rajdhani,sans-serif; font-size:2.8rem; font-weight:700; color:#00c8ff;'>{reports}</div>
                  <div style='font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px;'>Reports</div>
                </div>
                <div style='text-align:center;'>
                  <div style='font-family:Rajdhani,sans-serif; font-size:2rem; font-weight:700; color:#c8d8f0;'>{country}</div>
                  <div style='font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px;'>Country</div>
                </div>
                <div style='text-align:center;'>
                  <div style='font-family:Rajdhani,sans-serif; font-size:2rem; font-weight:700; color:{color};'>{verdict}</div>
                  <div style='font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px;'>Verdict</div>
                </div>
              </div>
              <div style='font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#4a5a7a; border-top:1px solid #1a2540; padding-top:10px;'>
                ISP: {isp} &nbsp;|&nbsp; Domain: {domain} &nbsp;|&nbsp; Last Reported: {last_reported}
              </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("Enter an IP address above and click Check IP Now.")

    st.markdown("---")

    # Stats from dataset
    known_mal = df[df["is_known_malicious"] == True]
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{len(known_mal)}</div>
          <div class='metric-lbl'>Known Malicious IPs</div></div>""", unsafe_allow_html=True)
    with c2:
        avg_abuse = df["abuse_score"].mean()
        st.markdown(f"""<div class='metric-card warn-card'>
          <div class='metric-val'>{avg_abuse:.0f}</div>
          <div class='metric-lbl'>Avg Abuse Score</div></div>""", unsafe_allow_html=True)
    with c3:
        high_abuse = (df["abuse_score"] > 75).sum()
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{high_abuse}</div>
          <div class='metric-lbl'>High Abuse Score (&gt;75)</div></div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class='metric-card info-card'>
          <div class='metric-val'>AbuseIPDB</div>
          <div class='metric-lbl'>Intelligence Source</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 📊 Abuse Score Distribution")
        fig = go.Figure(go.Histogram(
            x=df["abuse_score"], nbinsx=20,
            marker=dict(color=df["abuse_score"], colorscale=[[0,"#00f5a0"],[0.5,"#ffa500"],[1,"#ff4560"]]),
        ))
        fig.update_layout(paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540", title="Abuse Score"),
            yaxis=dict(gridcolor="#1a2540", title="Count"),
            margin=dict(l=0,r=0,t=10,b=0), height=280)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🌍 Known Malicious IPs by Country")
        top = known_mal.groupby("country").size().reset_index(name="count").sort_values("count", ascending=False).head(10)
        fig2 = go.Figure(go.Bar(
            x=top["count"], y=top["country"], orientation="h",
            marker=dict(color="#ff4560"), text=top["count"], textposition="outside",
            textfont=dict(color="#c8d8f0"),
        ))
        fig2.update_layout(paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            yaxis=dict(autorange="reversed", gridcolor="#1a2540"),
            xaxis=dict(gridcolor="#1a2540"),
            margin=dict(l=0,r=0,t=10,b=0), height=280)
        st.plotly_chart(fig2, use_container_width=True)

    # Known malicious IP feed
    st.markdown("### 🚨 Known Malicious IP Feed")
    for _, row in known_mal.sort_values("abuse_score", ascending=False).head(15).iterrows():
        score = row["abuse_score"]
        color = "#ff4560" if score > 75 else "#ffa500"
        st.markdown(f"""
        <div style='background:#0a0f1e; border:1px solid #1a2540; border-left:3px solid {color};
             border-radius:6px; padding:12px 16px; margin:4px 0; display:flex; justify-content:space-between; align-items:center;'>
          <div>
            <span style='font-family:Share Tech Mono,monospace; color:#00c8ff;'>{row['ip']}</span>
            <span style='font-family:Rajdhani,sans-serif; color:#c8d8f0; margin-left:12px;'>{row['country']}</span>
            <span style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#4a5a7a; margin-left:12px;'>{row['attack_pattern']}</span>
          </div>
          <div style='font-family:Rajdhani,sans-serif; font-size:1.4rem; font-weight:700; color:{color};'>
            {score}/100
          </div>
        </div>
        """, unsafe_allow_html=True)
