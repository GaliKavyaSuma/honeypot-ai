import streamlit as st
import json, time, os
from datetime import datetime, timezone, timedelta
import sys; sys.path.insert(0, ".")

IST = timezone(timedelta(hours=5, minutes=30))

def get_redis():
    """Connect to Redis — checks REDIS_URL first (Render), then local ports."""
    try:
        import redis as redis_lib

        # ── Render / Railway: full URL ────────────────────────────────────
        redis_url = os.environ.get("REDIS_URL", "")
        if redis_url:
            try:
                if redis_url.startswith("rediss://"):
                    r = redis_lib.from_url(redis_url, decode_responses=True,
                                          ssl_cert_reqs=None, socket_timeout=5)
                else:
                    r = redis_lib.from_url(redis_url, decode_responses=True,
                                          socket_timeout=5)
                r.ping()
                return r
            except Exception as e:
                pass  # fall through to local

        # ── Docker internal hostname ───────────────────────────────────────
        redis_host = os.environ.get("REDIS_HOST", "")
        if redis_host and redis_host != "127.0.0.1":
            try:
                r = redis_lib.Redis(host=redis_host, port=6379, db=0,
                                   decode_responses=True, socket_timeout=2)
                r.ping()
                return r
            except Exception:
                pass

        # ── Local VM: try Docker mapped 6380, then system 6379 ────────────
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
            ℹ️ Live Feed — Redis Not Connected
          </div>
          <div style='font-size:0.85rem; color:#c8d8f0; line-height:1.7;'>
            Could not connect to Redis. Check that your Redis service is running.<br>
            You can still upload Cowrie log files below to analyse past attacks.
          </div>
        </div>
        """, unsafe_allow_html=True)
        _show_upload_section()
        return

    # ── Controls ──────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        auto_refresh = st.toggle("🔄 Auto Refresh (5s)", value=False)
    with col2:
        limit_choice = st.selectbox("Show last", [50, 100, 200, 500, "All"], index=0)
        limit = 99999 if limit_choice == "All" else int(limit_choice)
    with col3:
        filter_svc = st.selectbox("Filter", ["ALL","SSH","WEB_HONEYPOT","FTP","HTTP","MySQL"])

    raw   = r.lrange("honeypot:events", 0, limit - 1)
    total = r.llen("honeypot:events")

    events = []
    for e in raw:
        try:
            ev = json.loads(e)
            ip = ev.get("ip","").strip()
            if not ip:
                continue
            if filter_svc == "ALL" or ev.get("service","") == filter_svc:
                events.append(ev)
        except Exception:
            pass

    # ── KPI cards ─────────────────────────────────────────────────────────
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
          <div class='metric-val'>{sum(1 for e in events if e.get("event_type") in ["LOGIN_ATTEMPT","CMD","SQL_INJECTION_ATTEMPT"])}</div>
          <div class='metric-lbl'>Attack Events</div></div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class='metric-card'>
          <div class='metric-val'>{len(set(e.get("ip","") for e in events if e.get("ip")))}</div>
          <div class='metric-lbl'>Unique IPs</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if not events:
        st.markdown("""
        <div style='background:#0a0f1e;border:1px dashed #1a2540;border-radius:10px;padding:40px;text-align:center;'>
          <div style='font-size:2rem;'>🎯</div>
          <div style='font-family:Rajdhani,sans-serif;font-size:1.1rem;color:#4a5a7a;margin-top:10px;'>No events yet</div>
          <div style='font-size:0.82rem;color:#2a3a5a;margin-top:10px;line-height:1.9;'>
            SSH: <code style='color:#00f5a0;'>ssh root@127.0.0.1 -p 2222</code> (password: 123456)<br>
            Web: visit NexaCorp and try logging in / exploring pages
          </div>
        </div>""", unsafe_allow_html=True)
    else:
        now_ist = datetime.now(IST).strftime("%H:%M:%S IST")
        st.markdown(
            f"<div style='display:flex;justify-content:space-between;margin-bottom:10px;'>"
            f"<span style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;'>🔴 Live Event Stream ({len(events)})</span>"
            f"<span style='font-family:Share Tech Mono,monospace;font-size:0.72rem;color:#4a5a7a;'>Updated: {now_ist}</span>"
            f"</div>", unsafe_allow_html=True)

        svc_colors = {
            "WEB_HONEYPOT":"#00c8ff","SSH":"#00f5a0",
            "FTP":"#a855f7","HTTP":"#ffa500","MySQL":"#ff4560"
        }
        evt_colors = {
            "LOGIN_ATTEMPT":"#ff4560","CMD":"#00f5a0",
            "PAGE_VISIT":"#00c8ff","ADMIN_ACCESS":"#ff4560",
            "ROBOTS_TXT":"#ffa500","SENSITIVE_PATH_PROBE":"#ffa500",
            "PATH_PROBE":"#4a5a7a","connection":"#00c8ff",
            "file_download":"#a855f7","API_PROBE":"#a855f7",
            "SSO_PROBE":"#ffa500","HONEYTOKEN_ACCESS":"#ff4560",
            "SQL_INJECTION_ATTEMPT":"#ff4560","GIT_PROBE":"#a855f7",
            "SUPPORT_TICKET":"#00c8ff","CAREERS_APPLICATION":"#00c8ff",
            "ACCOUNT_LOCKED":"#ff4560","SCANNER_DETECTED":"#ffa500",
        }

        for ev in events:
            ts    = format_ts(ev.get("timestamp",""))
            ip    = ev.get("ip","?")
            svc   = ev.get("service","?")
            etype = ev.get("event_type","?")
            data  = str(ev.get("data",""))[:120]
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
        Upload your Cowrie JSON log files (<code>cowrie.json</code>) to analyse past SSH attacks.
        <br><b style='color:#a855f7;'>Supported:</b> cowrie.json, cowrie.json.YYYY-MM-DD (all rotated log files)
      </div>
    </div>
    """, unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Upload Cowrie JSON log file(s)",
        type=["json","log"],
        accept_multiple_files=True,
    )

    if not uploaded:
        return

    all_events = []
    for f in uploaded:
        content = f.read().decode("utf-8", errors="ignore")
        parsed = 0
        for line in content.strip().split("\n"):
            try:
                ev = json.loads(line.strip())
                if ev.get("src_ip") or ev.get("srcip"):
                    all_events.append(ev)
                    parsed += 1
            except Exception:
                continue
        st.success(f"✅ {f.name} — parsed {parsed:,} events")

    if not all_events:
        st.warning("No valid Cowrie events found.")
        return

    from collections import defaultdict, Counter
    by_ip = defaultdict(list)
    for ev in all_events:
        ip = ev.get("src_ip", ev.get("srcip","unknown"))
        by_ip[ip].append(ev)

    st.markdown(f"### 📊 Analysis — {len(all_events):,} Events, {len(by_ip):,} Attackers")

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

    import pandas as pd
    st.markdown("#### 🔴 Top Attackers")
    rows = []
    for ip, evs in sorted(by_ip.items(), key=lambda x: -len(x[1]))[:20]:
        logins  = [e for e in evs if "login" in e.get("eventid","")]
        cmds    = [e for e in evs if "command" in e.get("eventid","")]
        pwds    = list(set(e.get("password","") for e in logins if e.get("password")))[:3]
        users   = list(set(e.get("username","") for e in logins if e.get("username")))[:3]
        cmd_l   = list(set(e.get("input","") for e in cmds if e.get("input")))[:3]
        rows.append({"IP":ip,"Events":len(evs),"Logins":len(logins),"Commands":len(cmds),
                     "Passwords":str(pwds),"Users":str(users),"Commands used":str(cmd_l)})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, height=350)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### 🔑 Top Passwords")
        all_pwds = [e.get("password","") for e in login_events if e.get("password")]
        if all_pwds:
            st.dataframe(pd.DataFrame(Counter(all_pwds).most_common(15),
                         columns=["Password","Count"]), use_container_width=True, height=280)
    with col2:
        st.markdown("#### 💻 Top Commands")
        all_cmds = [e.get("input","") for e in cmd_events if e.get("input")]
        if all_cmds:
            st.dataframe(pd.DataFrame(Counter(all_cmds).most_common(15),
                         columns=["Command","Count"]), use_container_width=True, height=280)
