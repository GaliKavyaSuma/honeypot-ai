import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers

def render():
    df = load_attackers()

    st.markdown("## 🍯 Deception Tokens (Honeytokens)")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Fake sensitive files planted inside the honeypot filesystem. Any attacker who touches them is immediately flagged — because no legitimate user would ever access these files.</p>", unsafe_allow_html=True)

    # Explanation
    st.markdown("""
    <div style='background:#0a0f1e; border:1px solid #ffa50040; border-left:3px solid #ffa500;
         border-radius:8px; padding:16px; margin-bottom:20px;'>
      <div style='font-family:Rajdhani,sans-serif; font-weight:700; color:#ffa500; font-size:1.1rem; margin-bottom:8px;'>What Are Honeytokens?</div>
      <div style='font-size:0.85rem; color:#c8d8f0; line-height:1.7;'>
        Honeytokens are <b style='color:#00f5a0;'>fake bait files</b> planted in the honeypot filesystem.
        Files like <code style='color:#a855f7;'>passwords.txt</code>, <code style='color:#a855f7;'>id_rsa</code>,
        and <code style='color:#a855f7;'>.aws/credentials</code> look like real sensitive files to an attacker.
        The moment they try to <code>cat</code> or read any of these files, an immediate
        <b style='color:#ff4560;'>HIGH RISK alert</b> is triggered — because a legitimate user would never
        be looking for these files on a server they don't recognise.
      </div>
    </div>
    """, unsafe_allow_html=True)

    HONEYTOKEN_INFO = [
        {"filename": "passwords.txt",    "type": "Credentials File",  "severity": "CRITICAL", "color": "#ff4560",
         "desc": "Fake password list — attackers looking to steal credentials"},
        {"filename": "id_rsa",           "type": "SSH Private Key",   "severity": "CRITICAL", "color": "#ff4560",
         "desc": "Fake SSH private key — attackers trying to pivot to other systems"},
        {"filename": ".aws/credentials", "type": "AWS Access Keys",   "severity": "CRITICAL", "color": "#ff4560",
         "desc": "Fake cloud credentials — attackers targeting cloud infrastructure"},
        {"filename": "backup.sql",       "type": "Database Backup",   "severity": "HIGH",     "color": "#ffa500",
         "desc": "Fake database dump — attackers after user data"},
        {"filename": "wallet.dat",       "type": "Crypto Wallet",     "severity": "HIGH",     "color": "#ffa500",
         "desc": "Fake Bitcoin wallet — crypto-theft motivated attackers"},
        {"filename": "config.php",       "type": "App Config",        "severity": "HIGH",     "color": "#ffa500",
         "desc": "Fake app config with DB credentials"},
        {"filename": ".env",             "type": "Environment File",  "severity": "HIGH",     "color": "#ffa500",
         "desc": "Fake .env file with API keys and secrets"},
        {"filename": "secret_keys.txt",  "type": "API Keys",          "severity": "CRITICAL", "color": "#ff4560",
         "desc": "Fake API key file — attackers after service credentials"},
    ]

    triggered = df[df["honeytoken_triggered"] == True]

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{len(triggered)}</div>
          <div class='metric-lbl'>Honeytokens Triggered</div></div>""", unsafe_allow_html=True)
    with c2:
        pct = len(triggered)/len(df)*100
        st.markdown(f"""<div class='metric-card warn-card'>
          <div class='metric-val'>{pct:.1f}%</div>
          <div class='metric-lbl'>Of All Attackers</div></div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{len(HONEYTOKEN_INFO)}</div>
          <div class='metric-lbl'>Bait Files Planted</div></div>""", unsafe_allow_html=True)
    with c4:
        auto_blocked = triggered["blocked"].sum()
        st.markdown(f"""<div class='metric-card'>
          <div class='metric-val'>{auto_blocked}</div>
          <div class='metric-lbl'>Auto-Blocked</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Honeytoken file cards
    st.markdown("### 🗂️ Planted Honeytoken Files")
    cols = st.columns(4)
    for i, ht in enumerate(HONEYTOKEN_INFO):
        # Count how many attackers accessed this specific file
        count = df["accessed_honeytokens"].apply(lambda x: ht["filename"] in x if isinstance(x, list) else False).sum()
        with cols[i % 4]:
            st.markdown(f"""
            <div style='background:#0a0f1e; border:1px solid #1a2540; border-top:3px solid {ht["color"]};
                 border-radius:8px; padding:14px; margin-bottom:10px; text-align:center;'>
              <div style='font-family:Share Tech Mono,monospace; font-size:0.75rem; color:{ht["color"]}; word-break:break-all;'>{ht["filename"]}</div>
              <div style='font-family:Rajdhani,sans-serif; font-size:0.7rem; color:#4a5a7a; margin:4px 0;'>{ht["type"]}</div>
              <div style='font-family:Rajdhani,sans-serif; font-size:1.8rem; font-weight:700; color:{ht["color"]};'>{count}</div>
              <div style='font-size:0.65rem; color:#4a5a7a;'>accesses</div>
              <div style='background:{ht["color"]}15; color:{ht["color"]}; border:1px solid {ht["color"]}30;
                   border-radius:4px; padding:2px 6px; font-size:0.6rem; font-family:Rajdhani,sans-serif;
                   font-weight:700; margin-top:6px; letter-spacing:1px;'>{ht["severity"]}</div>
            </div>
            """, unsafe_allow_html=True)

    # Attacker feed who triggered honeytokens
    st.markdown("### 🚨 Attackers Who Touched Honeytoken Files")
    for _, row in triggered.sort_values("final_confidence", ascending=False).head(20).iterrows():
        files = row["accessed_honeytokens"]
        files_html = "".join([
            f'<span style="background:#ff456015;color:#ff4560;border:1px solid #ff456040;'
            f'font-family:Share Tech Mono,monospace;font-size:0.68rem;padding:2px 6px;'
            f'border-radius:4px;margin:2px;">{f}</span>' for f in files
        ])
        st.markdown(f"""
        <div style='background:#0a0f1e; border:1px solid #1a2540; border-left:3px solid #ff4560;
             border-radius:8px; padding:14px 16px; margin:4px 0;'>
          <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;'>
            <div>
              <span style='font-family:Share Tech Mono,monospace; color:#00c8ff;'>{row["ip"]}</span>
              <span style='font-family:Rajdhani,sans-serif; color:#c8d8f0; margin-left:12px;'>{row["country"]}</span>
              <span style='font-family:Rajdhani,sans-serif; color:#ff4560; margin-left:12px; font-size:0.8rem;'>🍯 HONEYTOKEN ACCESSED</span>
            </div>
            <span style='font-family:Rajdhani,sans-serif; font-size:1.4rem; font-weight:700; color:#ff4560;'>{int(row["final_confidence"]*100)}%</span>
          </div>
          <div style='font-size:0.75rem; color:#4a5a7a; margin-bottom:4px;'>Files accessed:</div>
          <div>{files_html}</div>
        </div>
        """, unsafe_allow_html=True)
