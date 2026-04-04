import streamlit as st
import json, time
from datetime import datetime, timezone, timedelta
import sys; sys.path.insert(0, ".")

IST = timezone(timedelta(hours=5, minutes=30))

def get_redis():
    """Try to connect to Redis. Returns None gracefully if not available."""
    try:
        import os
        import redis as redis_lib

        redis_host = os.environ.get("REDIS_HOST", "")
        if redis_host and redis_host != "127.0.0.1":
            r = redis_lib.Redis(host=redis_host, port=6379, db=0,
                               decode_responses=True, socket_timeout=2)
            r.ping()
            return r

        for port in [6380, 6379]:
            try:
                r = redis_lib.Redis(host="127.0.0.1", port=port, db=0,
                                   decode_responses=True, socket_timeout=2)
                r.ping()
                return r
            except Exception:
                continue
    except ImportError:
        pass
    return None

def format_ts(ts_str):
    try:
        ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        return str(ts_str)[:19] if ts_str else "?"

def render():
    st.markdown("## 📡 Live Attack Feed")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Real-time events from SSH, FTP, HTTP, MySQL and Web Portal honeypots. Timestamps in IST.</p>", unsafe_allow_html=True)

    r = get_redis()

    if not r:
        st.markdown("""
        <div style='background:#1a2540; border:1px solid #00c8ff40; border-left:3px solid #00c8ff;
             border-radius:8px; padding:20px; margin-bottom:20px;'>
          <div style='font-family:Rajdhani,sans-serif; font-size:1.1rem; color:#00c8ff; font-weight:700; margin-bottom:8px;'>
            ℹ️ Live Feed — VM Required
          </div>
          <div style='font-size:0.85rem; color:#c8d8f0; line-height:1.7;'>
            The Live Feed requires Redis which runs on your VM.<br>
            This page works when accessing via your local or VM network.<br><br>
            <b style='color:#00f5a0;'>To see live events:</b> Access the dashboard at 
            <code style='color:#00f5a0;'>http://127.0.0.1:9001</code> on your laptop,
            or use the Cloudflare tunnel URL.<br><br>
            You can still upload Cowrie log files below to analyse past attacks.
          </div>
        </div>
        """, unsafe_allow_html=True)
        # Fall through to show upload section even without Redis
        _show_upload_section()
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        auto_refresh = st.toggle("🔄 Auto Refresh (5s)", value=False)
    with col2:
        limit = st.selectbox("Show last", [50, 100, 200, 500], index=0)
    with col3:
        filter_svc = st.selectbox("Filter", ["ALL","SSH","WEB_HONEYPOT","FTP","HTTP","MySQL"])

    raw = r.lrange("honeypot:events", 0, limit - 1)
    total = r.llen("honeypot:events")

    events = []
    for e in raw:
        try:
            ev = json.loads(e)
            if filter_svc == "ALL" or ev.get("service","") == filter_svc:
                events.append(ev)
        except Exception:
            pass

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""<div class='metric-card info-card'>
          <div class='metric-val'>{total:,}</div><div class='metric-lbl'>Total in Redis</div></div>""",
          unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='metric-card warn-card'>
          <div class='metric-val'>{sum(1 for e in events if e.get("service")=="WEB_HONEYPOT")}</div>
          <div class='metric-lbl'>Web Portal Hits</div></div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{sum(1 for e in events if e.get("event_type") in ["LOGIN_ATTEMPT","CMD"])}</div>
          <div class='metric-lbl'>Login+CMD Events</div></div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class='metric-card'>
          <div class='metric-val'>{len(set(e.get("ip","") for e in events))}</div>
          <div class='metric-lbl'>Unique IPs</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if not events:
        st.markdown("""
        <div style='background:#0a0f1e;border:1px dashed #1a2540;border-radius:10px;padding:40px;text-align:center;'>
          <div style='font-size:2rem;'>🎯</div>
          <div style='font-family:Rajdhani,sans-serif;font-size:1.1rem;color:#4a5a7a;margin-top:10px;'>No events yet</div>
          <div style='font-size:0.82rem;color:#2a3a5a;margin-top:10px;line-height:1.9;'>
            SSH: <code style='color:#00f5a0;'>ssh root@127.0.0.1 -p 2222</code> (password: 123456)<br>
            Web: <code style='color:#00c8ff;'>http://127.0.0.1:8888</code>
          </div>
        </div>""", unsafe_allow_html=True)
    else:
        now_ist = datetime.now(IST).strftime("%H:%M:%S IST")
        st.markdown(
            f"<div style='display:flex;justify-content:space-between;margin-bottom:10px;'>"
            f"<span style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;'>🔴 Live Event Stream ({len(events)})</span>"
            f"<span style='font-family:Share Tech Mono,monospace;font-size:0.72rem;color:#4a5a7a;'>Updated: {now_ist}</span>"
            f"</div>", unsafe_allow_html=True)

        svc_colors = {"WEB_HONEYPOT":"#00c8ff","SSH":"#00f5a0","FTP":"#a855f7","HTTP":"#ffa500","MySQL":"#ff4560"}
        evt_colors = {
            "LOGIN_ATTEMPT":"#ff4560","CMD":"#00f5a0","PAGE_VISIT":"#00c8ff",
            "ADMIN_ACCESS":"#ff4560","ROBOTS_TXT":"#ffa500","SENSITIVE_PATH_PROBE":"#ffa500",
            "PATH_PROBE":"#4a5a7a","connection":"#00c8ff","file_download":"#a855f7",
            "API_PROBE":"#a855f7","SSO_PROBE":"#ffa500",
        }

        for ev in events:
            ts    = format_ts(ev.get("timestamp",""))
            ip    = ev.get("ip","?")
            svc   = ev.get("service","?")
            etype = ev.get("event_type","?")
            data  = str(ev.get("data",""))[:100]
            sc    = svc_colors.get(svc,"#888")
            ec    = evt_colors.get(etype,"#c8d8f0")
            st.markdown(f"""
            <div style='background:#0a0f1e;border:1px solid #1a2540;border-left:3px solid {sc};
                 border-radius:5px;padding:7px 14px;margin:2px 0;
                 display:flex;align-items:center;gap:12px;flex-wrap:wrap;'>
              <span style='font-family:Share Tech Mono,monospace;font-size:0.67rem;color:#4a5a7a;min-width:175px;'>{ts}</span>
              <span style='font-family:Share Tech Mono,monospace;font-size:0.78rem;color:#00c8ff;min-width:105px;'>{ip}</span>
              <span style='background:{sc}20;color:{sc};border:1px solid {sc}40;
                   font-family:Rajdhani,sans-serif;font-size:0.68rem;font-weight:700;
                   padding:2px 8px;border-radius:4px;min-width:110px;text-align:center;'>{svc}</span>
              <span style='color:{ec};font-family:Rajdhani,sans-serif;font-size:0.78rem;font-weight:600;min-width:145px;'>{etype}</span>
              <span style='font-family:Share Tech Mono,monospace;font-size:0.68rem;color:#4a5a7a;flex:1;'>{data}</span>
            </div>""", unsafe_allow_html=True)

    if auto_refresh:
        st.markdown("<div style='text-align:center;color:#4a5a7a;font-size:0.72rem;font-family:Share Tech Mono,monospace;margin-top:12px;'>⟳ Refreshing in 5s...</div>",
                    unsafe_allow_html=True)
        time.sleep(5)
        st.rerun()

    st.markdown("---")
    _show_upload_section()


def _show_upload_section():
    """Upload and analyse Cowrie log files."""
    st.markdown("### 📂 Upload & Analyse Cowrie Log Files")
    st.markdown("""
    <div style='background:#0a0f1e;border:1px solid #1a2540;border-left:3px solid #a855f7;
         border-radius:8px;padding:16px;margin-bottom:16px;'>
      <div style='font-size:0.85rem;color:#c8d8f0;line-height:1.7;'>
        Upload your Cowrie JSON log files (<code>cowrie.json</code>) to analyse past attacks.
        The system will extract all attacker IPs, commands, credentials and display them below.
        <br><b style='color:#a855f7;'>Supported:</b> cowrie.json, cowrie.json.YYYY-MM-DD (all rotated log files)
      </div>
    </div>
    """, unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Upload Cowrie JSON log file(s)",
        type=["json","log"],
        accept_multiple_files=True,
        help="Upload cowrie.json or rotated log files like cowrie.json.2026-03-29"
    )

    if not uploaded:
        return

    # Parse uploaded files
    all_events = []
    for f in uploaded:
        content = f.read().decode("utf-8", errors="ignore")
        lines = content.strip().split("\n")
        parsed = 0
        for line in lines:
            try:
                ev = json.loads(line.strip())
                if ev.get("src_ip") or ev.get("srcip"):
                    all_events.append(ev)
                    parsed += 1
            except Exception:
                continue
        st.success(f"✅ {f.name} — parsed {parsed:,} events")

    if not all_events:
        st.warning("No valid Cowrie events found in uploaded files.")
        return

    # Group by IP
    from collections import defaultdict, Counter
    by_ip = defaultdict(list)
    for ev in all_events:
        ip = ev.get("src_ip", ev.get("srcip","unknown"))
        by_ip[ip].append(ev)

    st.markdown(f"### 📊 Analysis Results — {len(all_events):,} Events from {len(by_ip):,} Attackers")

    # KPIs
    login_events = [e for e in all_events if "login" in e.get("eventid","")]
    cmd_events   = [e for e in all_events if "command" in e.get("eventid","")]
    dl_events    = [e for e in all_events if "download" in e.get("eventid","")]

    c1,c2,c3,c4 = st.columns(4)
    with c1:
        st.markdown(f"""<div class='metric-card info-card'>
          <div class='metric-val'>{len(all_events):,}</div>
          <div class='metric-lbl'>Total Events</div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{len(login_events):,}</div>
          <div class='metric-lbl'>Login Attempts</div></div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class='metric-card'>
          <div class='metric-val'>{len(cmd_events):,}</div>
          <div class='metric-lbl'>Commands Run</div></div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class='metric-card warn-card'>
          <div class='metric-val'>{len(dl_events):,}</div>
          <div class='metric-lbl'>Downloads</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Top attackers table
    st.markdown("#### 🔴 Top Attackers by Event Count")
    rows = []
    for ip, evs in sorted(by_ip.items(), key=lambda x: -len(x[1]))[:20]:
        logins = [e for e in evs if "login" in e.get("eventid","")]
        cmds   = [e for e in evs if "command" in e.get("eventid","")]
        pwds   = list(set(e.get("password","") for e in logins if e.get("password")))[:3]
        users  = list(set(e.get("username","") for e in logins if e.get("username")))[:3]
        cmd_list = list(set(e.get("input","") for e in cmds if e.get("input")))[:3]
        sessions = len(set(e.get("session","") for e in evs))
        rows.append({
            "IP": ip,
            "Sessions": sessions,
            "Events": len(evs),
            "Logins": len(logins),
            "Commands": len(cmds),
            "Passwords tried": ", ".join(pwds) or "—",
            "Usernames tried": ", ".join(users) or "—",
            "Commands tried": ", ".join(cmd_list) or "—",
        })

    import pandas as pd
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, height=400)

    # Most common passwords
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### 🔑 Top Passwords Used")
        all_pwds = [e.get("password","") for e in login_events if e.get("password")]
        top_pwds = Counter(all_pwds).most_common(15)
        if top_pwds:
            pwd_df = pd.DataFrame(top_pwds, columns=["Password","Count"])
            st.dataframe(pwd_df, use_container_width=True, height=300)

    with col2:
        st.markdown("#### 💻 Top Commands Run")
        all_cmds = [e.get("input","") for e in cmd_events if e.get("input")]
        top_cmds = Counter(all_cmds).most_common(15)
        if top_cmds:
            cmd_df = pd.DataFrame(top_cmds, columns=["Command","Count"])
            st.dataframe(cmd_df, use_container_width=True, height=300)

    # Download URLs
    if dl_events:
        st.markdown("#### 📥 Malware Download Attempts")
        for e in dl_events[:10]:
            url = e.get("url", e.get("shasum",""))
            ip  = e.get("src_ip", e.get("srcip","?"))
            st.markdown(
                f"<div style='background:#1a050a;border:1px solid #ff456040;border-radius:5px;"
                f"padding:8px 14px;margin:3px 0;font-family:Share Tech Mono,monospace;font-size:0.78rem;'>"
                f"<span style='color:#00c8ff;'>{ip}</span> → "
                f"<span style='color:#ff4560;'>{url}</span></div>",
                unsafe_allow_html=True)

    st.success("✅ Analysis complete! Run `python3 collect_real_data.py` on your VM to update the full dashboard with this data.")
