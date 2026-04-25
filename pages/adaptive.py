import streamlit as st
import json, os
from datetime import datetime, timezone, timedelta
import sys; sys.path.insert(0, ".")

IST = timezone(timedelta(hours=5, minutes=30))

def get_redis():
    try:
        import redis as rl
        redis_url = os.environ.get("REDIS_URL","") or os.environ.get("RENDER_REDIS_URL","")
        if redis_url:
            # Only use ssl_cert_reqs=None for TLS connections (rediss://)
            if redis_url.startswith("rediss://"):
                r = rl.from_url(redis_url, decode_responses=True, ssl_cert_reqs=None, socket_timeout=5)
            else:
                r = rl.from_url(redis_url, decode_responses=True, socket_timeout=5)
            r.ping()
            return r
        for port in [6380, 6379, 6381]:
            try:
                r = rl.Redis(host="127.0.0.1", port=port, db=0,
                            decode_responses=True, socket_timeout=2)
                r.ping(); return r
            except: continue
        for host in ["honeypot-redis", "redis", "localhost"]:
            try:
                r = rl.Redis(host=host, port=6379, db=0,
                            decode_responses=True, socket_timeout=2)
                r.ping(); return r
            except: continue
    except: pass
    return None

def fmt_ts(ts):
    try:
        t = datetime.fromisoformat(str(ts).replace("Z","+00:00"))
        if t.tzinfo is None: t = t.replace(tzinfo=timezone.utc)
        return t.astimezone(IST).strftime("%H:%M:%S IST")
    except: return str(ts)[:19]

PROFILE_COLORS = {
    "SCANNER":"#4a5a7a","BRUTEFORCE":"#ffa500","EXPLOITER":"#ff8c00",
    "DROPPER":"#a855f7","PERSISTENT":"#ff4560","APT":"#ff0000","DEFAULT":"#4a5a7a",
}
RESPONSE_ICONS = {
    "SLOW_DOWN":"🐌","THROTTLE":"⏱","ENGAGE":"🎣",
    "CAPTURE":"📦","MONITOR":"👁","FULL_DECEPTION":"🎭",
}

def render():
    st.markdown("## ⚙️ Adaptive Engine")
    st.markdown("<p style='color:#4a5a7a;font-size:0.85rem;'>The honeypot dynamically changes behavior based on ML attacker classification. Each attacker type sees a completely different environment.</p>", unsafe_allow_html=True)

    # ── How it works ──────────────────────────────────────────────────────────
    st.markdown("""
    <div style='background:#0a0f1e;border:1px solid #00f5a040;border-left:3px solid #00f5a0;
         border-radius:8px;padding:16px;margin-bottom:20px;'>
      <div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#00f5a0;font-size:1.05rem;margin-bottom:8px;'>How Adaptive Deception Works</div>
      <div style='font-size:0.84rem;color:#c8d8f0;line-height:1.9;'>
        1. Attacker connects to SSH or NexaCorp website<br>
        2. ML models classify their behaviour (SCANNER → APT) in real time<br>
        3. Adaptive Controller stores profile in Redis with 1-hour expiry<br>
        4. Website/Cowrie reads profile → changes delay, content, filesystem<br>
        5. Result: each attacker type sees a completely different honeypot
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── 6 profile cards ───────────────────────────────────────────────────────
    st.markdown("### 🎭 Attacker Profiles — Behavioral Mapping")
    profiles = [
        ("SCANNER",    "🐌 SLOW_DOWN",     "3.0s", "minimal",   "❌ No",  "#4a5a7a",
         "Few connections, no commands. Frustrate with 3s delay + empty system."),
        ("BRUTEFORCE", "⏱ THROTTLE",      "1.5s", "minimal",   "❌ No",  "#ffa500",
         "Many login attempts. Throttle with 1.5s delay, deny login, waste time."),
        ("EXPLOITER",  "🎣 ENGAGE",        "0.2s", "developer", "✅ Yes", "#ff8c00",
         "Ran system commands. Show realistic dev environment with partial bait."),
        ("DROPPER",    "📦 CAPTURE",       "0.1s", "server",    "✅ Yes", "#a855f7",
         "Tries to download malware. Let in to capture payload samples."),
        ("PERSISTENT", "👁 MONITOR",       "0.0s", "server",    "✅ Yes", "#ff4560",
         "Reconnects repeatedly. Full server env. Log every single command."),
        ("APT",        "🎭 FULL_DECEPTION","0.0s", "corporate", "✅ Yes", "#ff0000",
         "Sophisticated attacker. Full corporate environment with all credentials."),
    ]
    cols = st.columns(3)
    for i, (atype, response, delay, fs, login, color, desc) in enumerate(profiles):
        with cols[i % 3]:
            st.markdown(f"""
            <div style='background:#0a0f1e;border:1px solid #1a2540;border-top:3px solid {color};
                 border-radius:8px;padding:14px;margin-bottom:12px;min-height:195px;'>
              <div style='font-family:Rajdhani,sans-serif;font-size:1.05rem;font-weight:700;color:{color};'>{atype}</div>
              <div style='font-size:0.72rem;color:#4a5a7a;margin:4px 0 10px;font-family:Share Tech Mono,monospace;'>{response}</div>
              <div style='font-size:0.8rem;color:#c8d8f0;line-height:1.9;'>
                <b style='color:#4a5a7a;'>Delay:</b> {delay}<br>
                <b style='color:#4a5a7a;'>Environment:</b> {fs}<br>
                <b style='color:#4a5a7a;'>Login:</b> {login}
              </div>
              <div style='font-size:0.72rem;color:#4a5a7a;margin-top:8px;line-height:1.5;'>{desc}</div>
            </div>""", unsafe_allow_html=True)

    # ── Redis connection ───────────────────────────────────────────────────────
    r = get_redis()

    # ── Active adaptations ────────────────────────────────────────────────────
    st.markdown("### 🔴 Active Adaptations (Live)")

    if not r:
        st.warning("Redis not connected. Bridge must be running to sync adaptations from VM.")
    else:
        # Get adaptation keys — use keys() as fallback if scan_iter not supported
        try:
            keys = list(r.scan_iter("adaptation:*"))
        except Exception:
            try:
                keys = [k for k in r.keys("adaptation:*")]
            except Exception:
                keys = []

        if not keys:
            st.markdown("""
            <div style='background:#0a0f1e;border:1px dashed #1a2540;border-radius:8px;
                 padding:28px;text-align:center;'>
              <div style='font-size:1.5rem;'>⚙️</div>
              <div style='font-family:Rajdhani,sans-serif;color:#4a5a7a;margin-top:8px;'>No active adaptations yet</div>
              <div style='font-size:0.82rem;color:#2a3a5a;margin-top:8px;'>
                Run <code style='color:#00f5a0;'>python3 adaptive_controller.py</code> on your VM<br>
                Or run <code style='color:#00c8ff;'>python3 simulate_attacks.py</code> to generate test data
              </div>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"<p style='color:#4a5a7a;font-size:0.82rem;'>{len(keys)} IP(s) currently adapted</p>",
                       unsafe_allow_html=True)
            for key in keys[:25]:
                ip = key.replace("adaptation:","")
                try:
                    profile = r.hgetall(key)
                    ttl = r.ttl(key)
                except Exception:
                    continue
                atype   = profile.get("attacker_type","?")
                color   = PROFILE_COLORS.get(atype,"#888")
                response= profile.get("response","?")
                icon    = RESPONSE_ICONS.get(response,"⚙️")
                st.markdown(f"""
                <div style='background:#0a0f1e;border:1px solid #1a2540;border-left:3px solid {color};
                     border-radius:6px;padding:10px 16px;margin:3px 0;
                     display:flex;align-items:center;gap:14px;flex-wrap:wrap;'>
                  <span style='font-family:Share Tech Mono,monospace;font-size:0.82rem;color:#00c8ff;min-width:130px;'>{ip}</span>
                  <span style='background:{color}20;color:{color};border:1px solid {color}40;
                       font-family:Rajdhani,sans-serif;font-size:0.72rem;font-weight:700;
                       padding:2px 10px;border-radius:10px;'>{atype}</span>
                  <span style='color:#c8d8f0;font-size:0.8rem;'>{icon} {response}</span>
                  <span style='color:#4a5a7a;font-size:0.75rem;'>Env: {profile.get('fs_profile','?')}</span>
                  <span style='color:#4a5a7a;font-size:0.75rem;'>Delay: {profile.get('delay','?')}s</span>
                  <span style='color:#4a5a7a;font-size:0.75rem;'>Login: {profile.get('allow_login','?')}</span>
                  <span style='color:#2a3a5a;font-size:0.72rem;font-family:Share Tech Mono,monospace;margin-left:auto;'>TTL: {ttl}s</span>
                </div>""", unsafe_allow_html=True)

    # ── Recent adaptation events ───────────────────────────────────────────────
    st.markdown("### 📋 Recent Adaptation Events")
    if not r:
        st.info("Connect Redis to see recent adaptation events.")
        return

    try:
        raw = r.lrange("honeypot:events", 0, 999)
        adapt_events = []
        for ev_raw in raw:
            try:
                ev = json.loads(ev_raw)
                if ev.get("service") == "ADAPTIVE_ENGINE":
                    adapt_events.append(ev)
            except: pass

        if not adapt_events:
            st.info("No adaptation events yet. Run adaptive_controller.py and simulate_attacks.py on your VM.")
        else:
            for ev in adapt_events[:20]:
                ts    = fmt_ts(ev.get("timestamp",""))
                ip    = ev.get("ip","?")
                etype = ev.get("event_type","?")
                atype = etype.replace("ADAPTED_","")
                color = PROFILE_COLORS.get(atype,"#4a5a7a")
                st.markdown(f"""
                <div style='background:#0a0f1e;border:1px solid #1a2540;border-left:3px solid {color};
                     border-radius:5px;padding:7px 14px;margin:2px 0;font-size:0.82rem;'>
                  <span style='color:#4a5a7a;font-family:Share Tech Mono,monospace;margin-right:12px;'>{ts}</span>
                  <span style='color:#00c8ff;font-family:Share Tech Mono,monospace;margin-right:12px;'>{ip}</span>
                  <span style='color:{color};font-weight:700;font-family:Rajdhani,sans-serif;margin-right:12px;'>{atype}</span>
                  <span style='color:#4a5a7a;'>{ev.get("data","")[:80]}</span>
                </div>""", unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Error loading events: {e}")
