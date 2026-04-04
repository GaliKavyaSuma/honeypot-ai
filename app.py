import streamlit as st
import os, sys

# Auto-generate data and models if missing (needed for Streamlit Cloud)
if not os.path.exists("data/attackers.json") or not os.path.exists("models/models.pkl"):
    import subprocess
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    if not os.path.exists("data/attackers.json"):
        subprocess.run([sys.executable, "data/generate_data.py"], capture_output=True)
    if not os.path.exists("models/models.pkl"):
        subprocess.run([sys.executable, "models/train.py"], capture_output=True)

st.set_page_config(
    page_title="HoneypotAI — Cyber Threat Intelligence",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Optional Password Gate ─────────────────────────────────────────────────
# Set DASHBOARD_PASSWORD env variable to enable password protection.
# Leave unset for open access (default for demo/teacher sharing).
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
if DASHBOARD_PASSWORD:
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if not st.session_state.authenticated:
        st.markdown("""
        <div style='max-width:360px;margin:80px auto;background:#0a0f1e;border:1px solid #1a2540;
             border-radius:12px;padding:40px;text-align:center;'>
          <div style='font-size:2.5rem;'>🕵️</div>
          <div style='font-family:Rajdhani,sans-serif;font-size:1.5rem;font-weight:700;
               color:#00f5a0;margin:8px 0;'>HoneypotAI</div>
          <div style='font-size:0.8rem;color:#4a5a7a;letter-spacing:2px;margin-bottom:24px;'>
               THREAT INTELLIGENCE</div>
        </div>
        """, unsafe_allow_html=True)
        pwd = st.text_input("Dashboard Password", type="password", placeholder="Enter password")
        if st.button("Access Dashboard", use_container_width=True):
            if pwd == DASHBOARD_PASSWORD:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Incorrect password.")
        st.stop()

# ── Global dark theme ─────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Inter:wght@300;400;500&display=swap');

/* Hide default Streamlit page nav links */
[data-testid="stSidebarNav"] { display: none !important; }
[data-testid="collapsedControl"] { display: none !important; }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
header { visibility: hidden; }

:root {
  --bg: #050810;
  --panel: #0a0f1e;
  --border: #1a2540;
  --accent: #00f5a0;
  --accent2: #00c8ff;
  --danger: #ff4560;
  --warn: #ffa500;
  --text: #c8d8f0;
  --muted: #4a5a7a;
}

html, body, [data-testid="stAppViewContainer"] { background: var(--bg) !important; }
[data-testid="stSidebar"] { background: var(--panel) !important; border-right: 1px solid var(--border); }
[data-testid="stSidebar"] * { color: var(--text) !important; font-family: 'Rajdhani', sans-serif; }

h1,h2,h3,h4 { font-family: 'Rajdhani', sans-serif !important; color: var(--accent) !important; letter-spacing: 1px; }
p, li, span, div { font-family: 'Inter', sans-serif; color: var(--text); }

.metric-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 8px;
  padding: 18px 22px;
  margin: 6px 0;
  font-family: 'Rajdhani', sans-serif;
}
.metric-val { font-size: 2.2rem; font-weight: 700; color: var(--accent); line-height: 1; }
.metric-lbl { font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 2px; margin-top: 4px; }

.danger-card { border-left-color: var(--danger) !important; }
.danger-card .metric-val { color: var(--danger); }
.warn-card { border-left-color: var(--warn) !important; }
.warn-card .metric-val { color: var(--warn); }
.info-card { border-left-color: var(--accent2) !important; }
.info-card .metric-val { color: var(--accent2); }

.hero {
  background: linear-gradient(135deg, #050810 0%, #0a1628 50%, #050810 100%);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 48px 40px;
  text-align: center;
  position: relative;
  overflow: hidden;
  margin-bottom: 32px;
}
.hero::before {
  content: '';
  position: absolute; inset: 0;
  background: radial-gradient(ellipse at 50% 0%, rgba(0,245,160,0.08) 0%, transparent 60%);
}
.hero-title {
  font-family: 'Rajdhani', sans-serif;
  font-size: 3.2rem; font-weight: 700;
  color: var(--accent) !important;
  letter-spacing: 3px;
  margin: 0;
}
.hero-sub {
  font-family: 'Share Tech Mono', monospace;
  color: var(--accent2);
  font-size: 0.95rem;
  margin-top: 10px;
  letter-spacing: 2px;
}
.hero-desc { color: var(--text); font-size: 1rem; margin-top: 20px; max-width: 600px; margin-left: auto; margin-right: auto; }

.tag {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 4px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 0.72rem;
  margin: 3px;
  letter-spacing: 1px;
}
.tag-high { background: rgba(255,69,96,0.15); color: var(--danger); border: 1px solid rgba(255,69,96,0.3); }
.tag-medium { background: rgba(255,165,0,0.15); color: var(--warn); border: 1px solid rgba(255,165,0,0.3); }
.tag-low { background: rgba(0,245,160,0.1); color: var(--accent); border: 1px solid rgba(0,245,160,0.2); }
.tag-info { background: rgba(0,200,255,0.1); color: var(--accent2); border: 1px solid rgba(0,200,255,0.2); }

.nav-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
}
.nav-card:hover { border-color: var(--accent); }
.nav-icon { font-size: 2.5rem; }
.nav-title { font-family: 'Rajdhani', sans-serif; font-size: 1.2rem; font-weight: 700; color: var(--accent); margin-top: 8px; }
.nav-desc { font-size: 0.82rem; color: var(--muted); margin-top: 4px; }

/* Hide keyboard_double_arrow collapse button */
[data-testid="collapsedControl"] { display: none !important; }
button[kind="header"] { display: none !important; }
.st-emotion-cache-czk5ss { display: none !important; }
[aria-label="Close sidebar"] { display: none !important; }
[aria-label="Open sidebar"] { display: none !important; }

/* Fix multiselect tags */
[data-baseweb="tag"] {
  background-color: #1a2540 !important;
  border: 1px solid #00f5a0 !important;
}
[data-baseweb="tag"] span {
  color: #00f5a0 !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-weight: 600 !important;
}
[data-baseweb="tag"] svg { fill: #00f5a0 !important; }

/* Sidebar buttons - must override the * rule */
[data-testid="stSidebar"] .stButton > button {
  background: #0a1628 !important;
  border: 1px solid #1a2540 !important;
  color: #c8d8f0 !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.92rem !important;
  letter-spacing: 0.5px !important;
  border-radius: 6px !important;
  padding: 8px 16px !important;
  width: 100% !important;
  text-align: left !important;
  margin: 2px 0 !important;
  transition: all 0.15s !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
  background: #1a2540 !important;
  border-color: #00f5a0 !important;
  color: #00f5a0 !important;
}
[data-testid="stSidebar"] .stButton > button[kind="primary"] {
  background: #0d2a1a !important;
  border: 1px solid #00f5a0 !important;
  color: #00f5a0 !important;
}

/* Main area buttons */
.stButton>button {
  background: transparent;
  border: 1px solid var(--accent);
  color: var(--accent);
  font-family: 'Rajdhani', sans-serif;
  font-weight: 600;
  letter-spacing: 1px;
  border-radius: 6px;
  padding: 8px 20px;
}
.stButton>button:hover { background: rgba(0,245,160,0.1); }

[data-testid="stMetricValue"] { font-family: 'Rajdhani', sans-serif; color: var(--accent); }
[data-testid="stMetricLabel"] { color: var(--muted); }

.stTabs [data-baseweb="tab"] { color: var(--muted); font-family: 'Rajdhani', sans-serif; }
.stTabs [aria-selected="true"] { color: var(--accent); }
.stTabs [data-baseweb="tab-border"] { background: var(--accent); }
</style>
""", unsafe_allow_html=True)

# ── Sidebar navigation ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 16px 0 24px;'>
      <div style='font-family:Rajdhani,sans-serif; font-size:1.5rem; font-weight:700; color:#00f5a0; letter-spacing:2px;'>🕵️ HoneypotAI</div>
      <div style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#00c8ff; letter-spacing:3px; margin-top:4px;'>THREAT INTELLIGENCE</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("<div style='font-size:0.7rem; color:#4a5a7a; letter-spacing:2px; text-transform:uppercase; margin-bottom:8px;'>Navigation</div>", unsafe_allow_html=True)
    
    pages = {
        "🏠 Overview":           "Live stats & system status",
        "📡 Live Feed":          "Real-time Redis event stream",
        "🌍 Attack Map":         "Real-time world map of attacker IPs",
        "👤 Attacker Profiles":  "Deep-dive attacker intelligence cards",
        "🤖 ML Engine":          "Model performance & live prediction",
        "⏱️ Timeline":           "Attack replay & session timeline",
        "🔔 Alerts":             "High-risk detections & blocked IPs",
        "🧪 Live Detector":      "Test an IP against all 4 models",
        "─────────────": None,
        "🛡️ Threat Intel":       "AbuseIPDB cross-reference",
        "🎯 Attack Patterns":    "Mirai, Medusa, APT detection",
        "🍯 Honeytokens":        "Deception token alerts",
        "🔐 Password Intel":     "Password sophistication analysis",
        "🌐 GeoIP Scoring":      "Country risk heat map",
    }
    
    if "page" not in st.session_state:
        st.session_state.page = "🏠 Overview"
    
    for name, desc in pages.items():
        if desc is None:
            st.markdown("<hr style='border-color:#1a2540; margin:8px 0;'>", unsafe_allow_html=True)
            continue
        is_active = st.session_state.page == name
        if st.button(name, key=f"nav_{name}", use_container_width=True,
                     type="primary" if is_active else "secondary"):
            st.session_state.page = name
            st.rerun()
    
    st.markdown("---")
    st.markdown("""
    <div style='font-size:0.72rem; color:#4a5a7a; text-align:center; line-height:1.6;'>
      Final Year Project<br>
      AI-Powered Adaptive Honeypot<br>
      <span style='color:#00f5a0;'>v3.0 — 2026</span>
    </div>
    """, unsafe_allow_html=True)

# ── Page routing ──────────────────────────────────────────────────────────────
page = st.session_state.page

if page == "🏠 Overview":
    import pages.overview as p; p.render()
elif page == "📡 Live Feed":
    import pages.live_feed as p; p.render()
elif page == "🌍 Attack Map":
    import pages.attack_map as p; p.render()
elif page == "👤 Attacker Profiles":
    import pages.profiles as p; p.render()
elif page == "🤖 ML Engine":
    import pages.ml_engine as p; p.render()
elif page == "⏱️ Timeline":
    import pages.timeline as p; p.render()
elif page == "🔔 Alerts":
    import pages.alerts as p; p.render()
elif page == "🧪 Live Detector":
    import pages.live_detector as p; p.render()
elif page == "🛡️ Threat Intel":
    import pages.threat_intel as p; p.render()
elif page == "🎯 Attack Patterns":
    import pages.patterns as p; p.render()
elif page == "🍯 Honeytokens":
    import pages.honeytokens as p; p.render()
elif page == "🔐 Password Intel":
    import pages.password_intel as p; p.render()
elif page == "🌐 GeoIP Scoring":
    import pages.geoip as p; p.render()
