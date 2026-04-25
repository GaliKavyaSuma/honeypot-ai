import json, pickle, os
import pandas as pd
import streamlit as st
from datetime import datetime, timezone

def _try_redis():
    """Connect to Redis — supports REDIS_URL (Render), Docker hostname, and local ports."""
    try:
        import redis as redis_lib

        # Render / Railway provide full Redis URL
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
            except Exception:
                pass

        # Docker internal hostname
        redis_host = os.environ.get("REDIS_HOST", "")
        if redis_host and redis_host != "127.0.0.1":
            try:
                r = redis_lib.Redis(host=redis_host, port=6379, db=0,
                                   decode_responses=True, socket_timeout=2)
                r.ping()
                return r
            except Exception:
                pass

        # Local — try Docker mapped 6380 then system 6379
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

def _score_with_ml(features_dict):
    """Score a live attacker using the trained ML models."""
    try:
        import numpy as np
        models = load_models()
        feat = np.array([[
            features_dict["session_count"],
            features_dict["total_events"],
            features_dict["commands_tried"],
            features_dict["username_attempts"],
            features_dict["password_attempts"],
            features_dict["geo_risk_score"],
            features_dict["password_risk_score"],
            features_dict["honeytoken_score"],
        ]])
        feat_scaled = models["scaler"].transform(feat)
        rf_s  = float(models["rf_session"].predict_proba(feat)[0][1])
        lr_s  = float(models["lr_session"].predict_proba(feat_scaled)[0][1])
        svm_raw = float(models["svm_attacker"].decision_function(feat_scaled)[0])
        svm_s = float(1 / (1 + __import__('math').exp(-svm_raw)))
        ens = rf_s * 0.40 + lr_s * 0.35 + svm_s * 0.25
        return round(rf_s,3), round(lr_s,3), round(svm_s,3), round(ens,3)
    except Exception:
        base = features_dict.get("base_conf", 0.5)
        return round(base,3), round(base*0.97,3), round(base*0.95,3), round(base,3)

HONEYTOKEN_FILES = ["passwords.txt","id_rsa",".aws","backup.sql",".env",
                    "secret_keys","wallet.dat","vpn.ovpn"]

COUNTRY_RISK = {
    "CN":0.95,"RU":0.90,"UA":0.80,"IR":0.85,"KP":0.95,"BR":0.60,
    "IN":0.55,"VN":0.70,"RO":0.65,"NG":0.70,"US":0.40,"DE":0.35,
    "GB":0.35,"NL":0.45,"SG":0.50,"KR":0.45,
}

COMMON_PASSWORDS = {"123456","password","admin","root","toor","12345",
                    "pass","test","admin123","raspberry","111111","qwerty","guest"}

def _build_live_attacker(ip, events):
    """Build a real ML-scored attacker profile from live Redis events."""
    logins   = [e for e in events if e.get("event_type") in
                ["LOGIN_ATTEMPT","login.failed","login.success"]]
    commands = [e for e in events if e.get("event_type") in ["CMD","command"]]
    honeytok = [e for e in events if e.get("event_type") == "HONEYTOKEN_ACCESS"]
    sqli     = [e for e in events if e.get("event_type") == "SQL_INJECTION_ATTEMPT"]

    passwords, usernames, cmds_used = [], [], []
    for e in logins:
        data = e.get("data","")
        if "pass=" in data:
            try: passwords.append(data.split("pass=")[1].split(" ")[0])
            except: pass
        if "user=" in data:
            try: usernames.append(data.split("user=")[1].split(" ")[0])
            except: pass
    for e in commands:
        cmd = e.get("data","").strip()
        if cmd: cmds_used.append(cmd)

    timestamps = [e.get("timestamp","") for e in events if e.get("timestamp")]
    first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()
    last_seen  = max(timestamps) if timestamps else first_seen

    session_count = max(1, len(set(e.get("timestamp","")[:10] for e in events)))
    total_ev      = len(events)

    # Password intelligence
    if passwords:
        common_ratio = sum(1 for p in passwords if p in COMMON_PASSWORDS) / len(passwords)
        pw_risk = 0.2 if common_ratio > 0.8 else 0.5 if common_ratio > 0.5 else 0.85
    else:
        pw_risk = 0.1

    geo_risk  = 0.5  # default (no GeoIP lookup in real-time for speed)
    ht_score  = 0.3 if honeytok else 0.0
    sqli_flag = len(sqli) > 0

    accessed_ht = list(set(
        e.get("data","").replace("Downloaded: ","").strip()
        for e in honeytok if e.get("data")
    ))

    # Score with ML models
    features = {
        "session_count":     session_count,
        "total_events":      total_ev,
        "commands_tried":    len(set(cmds_used)),
        "username_attempts": len(set(usernames)),
        "password_attempts": len(set(passwords)),
        "geo_risk_score":    geo_risk,
        "password_risk_score": pw_risk,
        "honeytoken_score":  ht_score,
        "base_conf": min(1.0, 0.25 + len(logins)*0.04 + len(cmds_used)*0.06 + ht_score*0.3),
    }
    rf_s, lr_s, svm_s, final_conf = _score_with_ml(features)

    # Override: honeytoken always = HIGH
    if honeytok or sqli_flag:
        final_conf = max(final_conf, 0.80)

    if final_conf > 0.65:   risk = "HIGH"
    elif final_conf > 0.35: risk = "MEDIUM"
    else:                   risk = "LOW"

    # Classification
    if session_count >= 15 and len(cmds_used) >= 10: cls = "APT"
    elif session_count >= 8:                           cls = "PERSISTENT"
    elif len(cmds_used) >= 8:                         cls = "EXPLOITER"
    elif any("wget" in c or "curl" in c for c in cmds_used): cls = "DROPPER"
    elif session_count <= 2 and not cmds_used:         cls = "SCANNER"
    else:                                              cls = "BRUTEFORCE"

    # Password intel label
    if not passwords:        pw_intel = "NONE"
    elif pw_risk < 0.3:      pw_intel = "SCRIPT_KIDDIE"
    elif pw_risk < 0.7:      pw_intel = "AUTOMATED"
    else:                    pw_intel = "TARGETED"

    # Attack pattern
    cmd_str = " ".join(cmds_used)
    if "/bin/busybox MIRAI" in cmd_str or "enable" in cmd_str: pattern = "Mirai Botnet"
    elif "dvrHelper" in cmd_str:                                pattern = "Hajime Worm"
    elif "mozi" in cmd_str.lower():                             pattern = "Mozi Botnet"
    elif "cat /etc/shadow" in cmd_str or "find / -perm" in cmd_str: pattern = "Manual/Targeted"
    elif sqli_flag:                                             pattern = "SQL Injection"
    elif cmds_used:                                             pattern = "Bruteforce"
    else:                                                       pattern = "Unknown Scanner"

    return {
        "attacker_id":       abs(hash(ip)) % 100000,
        "ip":                ip,
        "country":           "Live",
        "country_code":      "XX",
        "lat":               0.0,
        "lon":               0.0,
        "session_count":     session_count,
        "classification":    cls,
        "attack_pattern":    pattern,
        "risk_level":        risk,
        "rf_score":          rf_s,
        "lr_score":          lr_s,
        "svm_score":         svm_s,
        "final_confidence":  final_conf,
        "commands_tried":    list(set(cmds_used))[:15],
        "username_attempts": list(set(usernames))[:10],
        "password_attempts": list(set(passwords))[:10],
        "password_intelligence": pw_intel,
        "password_risk_score":   round(pw_risk, 2),
        "geo_risk_score":        round(geo_risk, 2),
        "honeytoken_triggered":  len(honeytok) > 0,
        "accessed_honeytokens":  accessed_ht,
        "abuse_score":           int(final_conf * 100),
        "is_known_malicious":    final_conf > 0.75,
        "first_seen":            first_seen,
        "last_seen":             last_seen,
        "blocked":               risk == "HIGH",
        "total_events":          total_ev,
        "data_source":           "LIVE",
        "sql_injection":         sqli_flag,
    }

@st.cache_data(ttl=15)
def load_attackers():
    """
    Load attacker profiles.
    Priority: LIVE Redis attackers first, then simulated dataset as background.
    Real attackers get proper ML scoring and appear in ALL dashboard pages.
    """
    r = _try_redis()
    live_profiles = []

    if r:
        try:
            raw = r.lrange("honeypot:events", 0, 9999)
            by_ip = {}
            for raw_ev in raw:
                try:
                    ev = json.loads(raw_ev)
                    ip = ev.get("ip","").strip()
                    # Accept all IPs except empty and pure localhost
                    if ip and ip != "unknown":
                        by_ip.setdefault(ip, []).append(ev)
                except Exception:
                    pass

            # Build ML-scored profiles for every real attacker
            live_profiles = [_build_live_attacker(ip, evs)
                             for ip, evs in by_ip.items()]
        except Exception:
            pass

    # Load simulated base dataset
    try:
        with open("data/attackers.json") as f:
            base_data = json.load(f)
        base_df = pd.DataFrame(base_data)
    except Exception:
        base_df = pd.DataFrame()

    if live_profiles:
        live_df   = pd.DataFrame(live_profiles)
        live_ips  = set(live_df["ip"].tolist())

        if not base_df.empty:
            # Keep simulated data for IPs not seen live
            sim_only = base_df[~base_df["ip"].isin(live_ips)]
            df = pd.concat([live_df, sim_only], ignore_index=True)
        else:
            df = live_df
    else:
        df = base_df if not base_df.empty else pd.DataFrame()

    return df

@st.cache_data(ttl=15)
def load_events():
    """Load events — live Redis events first, then simulated dataset."""
    r = _try_redis()
    live_rows = []

    if r:
        try:
            raw = r.lrange("honeypot:events", 0, 9999)
            for raw_ev in raw:
                try:
                    ev = json.loads(raw_ev)
                    ip = ev.get("ip","").strip()
                    if not ip or ip == "unknown":
                        continue
                    etype = ev.get("event_type","connection")
                    high_events = {"LOGIN_ATTEMPT","CMD","ADMIN_ACCESS",
                                   "HONEYTOKEN_ACCESS","SQL_INJECTION_ATTEMPT"}
                    live_rows.append({
                        "timestamp":      pd.to_datetime(ev.get("timestamp",
                                          datetime.now(timezone.utc).isoformat())),
                        "ip":             ip,
                        "country":        "Live",
                        "event_type":     etype,
                        "risk_level":     "HIGH" if etype in high_events else "MEDIUM",
                        "attack_pattern": "Live Attack",
                        "command":        ev.get("data","")[:80],
                        "service":        ev.get("service","WEB_HONEYPOT"),
                    })
                except Exception:
                    pass
        except Exception:
            pass

    try:
        with open("data/events.json") as f:
            base_data = json.load(f)
        base_df = pd.DataFrame(base_data)
        base_df["timestamp"] = pd.to_datetime(base_df["timestamp"])
    except Exception:
        base_df = pd.DataFrame()

    if live_rows:
        live_df = pd.DataFrame(live_rows)
        if not base_df.empty:
            df = pd.concat([live_df, base_df], ignore_index=True)
        else:
            df = live_df
        df = df.sort_values("timestamp", ascending=False)
    else:
        df = base_df

    return df

@st.cache_resource
def load_models():
    """Load ML models — auto-generates them if models.pkl doesn't exist (e.g. on Render)."""
    if not os.path.exists("models/models.pkl"):
        # Auto-generate models on first run (needed on Render where pkl is gitignored)
        try:
            import subprocess, sys
            # Generate data first if needed
            if not os.path.exists("data/attackers.json"):
                subprocess.run([sys.executable, "data/generate_data.py"], check=True)
            subprocess.run([sys.executable, "models/train.py"], check=True)
        except Exception as e:
            # Return dummy models if generation fails
            st.warning(f"Model generation failed: {e}. Using fallback.")
            return _dummy_models()

    try:
        with open("models/models.pkl", "rb") as f:
            return pickle.load(f)
    except Exception:
        return _dummy_models()

def _dummy_models():
    """Minimal fallback when models.pkl unavailable."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import LinearSVC
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    X = np.random.rand(100, 8)
    y = np.random.randint(0, 2, 100)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    return {
        "rf_session":   RandomForestClassifier(n_estimators=10).fit(X, y),
        "lr_session":   LogisticRegression(max_iter=100).fit(Xs, y),
        "rf_attacker":  RandomForestClassifier(n_estimators=10).fit(X, y),
        "svm_attacker": LinearSVC(max_iter=100).fit(Xs, y),
        "scaler":       scaler,
    }

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
