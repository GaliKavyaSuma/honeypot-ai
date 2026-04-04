import json, pickle, os
import pandas as pd
import streamlit as st
from datetime import datetime, timezone

def _try_redis():
    import os
    redis_host = os.environ.get("REDIS_HOST", "")
    try:
        import redis as redis_lib
        if redis_host and redis_host != "127.0.0.1":
            r = redis_lib.Redis(host=redis_host, port=6379, db=0,
                               decode_responses=True, socket_timeout=2)
            r.ping()
            return r
    except Exception:
        pass
    for port in [6380, 6379]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(host="127.0.0.1", port=port, db=0,
                               decode_responses=True, socket_timeout=2)
            r.ping()
            return r
        except Exception:
            continue
    return None

def _build_live_attacker(ip, events):
    """Build an attacker profile from live Redis events for a single IP."""
    logins   = [e for e in events if e.get("event_type") == "LOGIN_ATTEMPT"]
    commands = [e for e in events if e.get("event_type") == "CMD"]
    service  = events[0].get("service", "SSH") if events else "SSH"

    passwords = []
    usernames = []
    cmds_used = []
    for e in logins:
        data = e.get("data", "")
        if "pass=" in data:
            try: passwords.append(data.split("pass=")[1].split(" ")[0])
            except: pass
        if "user=" in data:
            try: usernames.append(data.split("user=")[1].split(" ")[0])
            except: pass
    for e in commands:
        cmd = e.get("data", "").strip()
        if cmd: cmds_used.append(cmd)

    timestamps = [e.get("timestamp","") for e in events if e.get("timestamp")]
    first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()
    last_seen  = max(timestamps) if timestamps else first_seen

    session_count = max(1, len(set(e.get("timestamp","")[:10] for e in events)))
    total_events  = len(events)
    final_conf    = min(1.0, 0.3 + len(logins)*0.05 + len(cmds_used)*0.08)
    if final_conf > 0.65:   risk = "HIGH"
    elif final_conf > 0.35: risk = "MEDIUM"
    else:                   risk = "LOW"

    honeytoken_files = ["passwords.txt","id_rsa",".aws","backup.sql",".env","secret_keys"]
    accessed_ht = [f for f in honeytoken_files if any(f in c for c in cmds_used)]

    return {
        "attacker_id": abs(hash(ip)) % 100000,
        "ip": ip, "country": "Live", "country_code": "XX",
        "lat": 0.0, "lon": 0.0,
        "session_count": session_count,
        "classification": "PERSISTENT" if session_count >= 3 else "SCANNER",
        "attack_pattern": "Manual/Targeted" if cmds_used else "Unknown Scanner",
        "risk_level": risk,
        "rf_score": round(final_conf, 3),
        "lr_score": round(final_conf * 0.97, 3),
        "svm_score": round(final_conf * 0.95, 3),
        "final_confidence": round(final_conf, 3),
        "commands_tried": cmds_used[:10],
        "username_attempts": usernames[:5],
        "password_attempts": passwords[:5],
        "password_intelligence": "TARGETED" if passwords else "NONE",
        "password_risk_score": 0.5,
        "geo_risk_score": 0.5,
        "honeytoken_triggered": len(accessed_ht) > 0,
        "accessed_honeytokens": accessed_ht,
        "abuse_score": int(final_conf * 100),
        "is_known_malicious": final_conf > 0.75,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "blocked": risk == "HIGH",
        "total_events": total_events,
        "data_source": "LIVE",
    }

@st.cache_data(ttl=15)
def load_attackers():
    """Load attacker profiles — merges JSON dataset with live Redis data."""
    with open("data/attackers.json") as f:
        base_data = json.load(f)
    df = pd.DataFrame(base_data)

    # Merge live Redis attackers
    r = _try_redis()
    if r:
        try:
            raw = r.lrange("honeypot:events", 0, 4999)
            by_ip = {}
            for raw_ev in raw:
                try:
                    ev = json.loads(raw_ev)
                    ip = ev.get("ip","")
                    if ip and ip not in ("127.0.0.1", "unknown", ""):
                        by_ip.setdefault(ip, []).append(ev)
                except: pass

            if by_ip:
                live_profiles = [_build_live_attacker(ip, evs) for ip, evs in by_ip.items()]
                live_df = pd.DataFrame(live_profiles)
                # Remove duplicates — prefer live data over simulated for same IP
                existing_ips = set(df["ip"].tolist())
                new_live = live_df[~live_df["ip"].isin(existing_ips)]
                if not new_live.empty:
                    df = pd.concat([new_live, df], ignore_index=True)
        except Exception:
            pass

    return df

@st.cache_data(ttl=15)
def load_events():
    """Load events — merges JSON dataset with live Redis events."""
    with open("data/events.json") as f:
        base_data = json.load(f)
    df = pd.DataFrame(base_data)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    r = _try_redis()
    if r:
        try:
            raw = r.lrange("honeypot:events", 0, 4999)
            live_rows = []
            for raw_ev in raw:
                try:
                    ev = json.loads(raw_ev)
                    ip = ev.get("ip","")
                    if not ip or ip in ("unknown",): continue
                    live_rows.append({
                        "timestamp": pd.to_datetime(ev.get("timestamp",
                                     datetime.now(timezone.utc).isoformat())),
                        "ip": ip,
                        "country": "Live",
                        "event_type": ev.get("event_type","connection"),
                        "risk_level": "HIGH" if ev.get("event_type") in
                                      ["LOGIN_ATTEMPT","ADMIN_ACCESS","CMD"] else "MEDIUM",
                        "attack_pattern": "Live Attack",
                        "command": ev.get("data","")[:80],
                    })
                except: pass
            if live_rows:
                live_df = pd.DataFrame(live_rows)
                df = pd.concat([live_df, df], ignore_index=True)
                df = df.sort_values("timestamp", ascending=False)
        except Exception:
            pass

    return df

@st.cache_resource
def load_models():
    with open("models/models.pkl", "rb") as f:
        return pickle.load(f)

def risk_color(risk):
    return {"HIGH":"#ff4560","MEDIUM":"#ffa500","LOW":"#00f5a0"}.get(risk,"#888")

def risk_tag(risk):
    cls = {"HIGH":"tag-high","MEDIUM":"tag-medium","LOW":"tag-low"}.get(risk,"tag-info")
    return f'<span class="tag {cls}">{risk}</span>'

def conf_bar(val, color="#00f5a0"):
    pct = int(val*100)
    return (f"<div style='background:#0a0f1e;border-radius:4px;height:6px;margin:4px 0;overflow:hidden;'>"
            f"<div style='background:{color};width:{pct}%;height:100%;border-radius:4px;'></div></div>"
            f"<div style='font-family:Share Tech Mono,monospace;font-size:0.72rem;color:{color};'>{pct}%</div>")


@st.cache_data(ttl=10)  # refresh every 10 seconds
def load_attackers():
    with open("data/attackers.json") as f:
        data = json.load(f)
    df = pd.DataFrame(data)

    # Merge in any live web honeypot login attempts from Redis
    r = _try_redis()
    if r:
        try:
            raw_events = r.lrange("honeypot:events", 0, 999)
            live = []
            for e in raw_events:
                try:
                    ev = json.loads(e)
                    if ev.get("event_type") == "LOGIN_ATTEMPT" and ev.get("data"):
                        live.append(ev)
                except Exception:
                    pass
            if live:
                st.session_state["live_web_events"] = live
        except Exception:
            pass

    return df

@st.cache_data(ttl=10)
def load_events():
    with open("data/events.json") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Merge live Redis events
    r = _try_redis()
    if r:
        try:
            raw_events = r.lrange("honeypot:events", 0, 4999)
            live_rows = []
            for e in raw_events:
                try:
                    ev = json.loads(e)
                    live_rows.append({
                        "timestamp": pd.to_datetime(ev.get("timestamp")),
                        "ip": ev.get("ip","unknown"),
                        "country": "Live",
                        "event_type": ev.get("event_type","connection"),
                        "risk_level": "HIGH" if ev.get("event_type") in ["LOGIN_ATTEMPT","honeytoken_access"] else "MEDIUM",
                        "attack_pattern": "Live Attack",
                        "command": ev.get("data",""),
                    })
                except Exception:
                    pass
            if live_rows:
                live_df = pd.DataFrame(live_rows)
                df = pd.concat([live_df, df], ignore_index=True).sort_values("timestamp", ascending=False)
        except Exception:
            pass

    return df

@st.cache_resource
def load_models():
    with open("models/models.pkl", "rb") as f:
        return pickle.load(f)

def risk_color(risk):
    return {"HIGH": "#ff4560", "MEDIUM": "#ffa500", "LOW": "#00f5a0"}.get(risk, "#888")

def risk_tag(risk):
    cls = {"HIGH": "tag-high", "MEDIUM": "tag-medium", "LOW": "tag-low"}.get(risk, "tag-info")
    return f'<span class="tag {cls}">{risk}</span>'

def conf_bar(val, color="#00f5a0"):
    pct = int(val * 100)
    return f"""
    <div style='background:#0a0f1e; border-radius:4px; height:6px; margin:4px 0; overflow:hidden;'>
      <div style='background:{color}; width:{pct}%; height:100%; border-radius:4px;'></div>
    </div>
    <div style='font-family:Share Tech Mono,monospace; font-size:0.72rem; color:{color};'>{pct}%</div>
    """
