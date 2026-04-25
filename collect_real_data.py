#!/usr/bin/env python3
"""
HoneypotAI — Real Attack Data Collector
Reads actual Cowrie SSH honeypot logs and builds real attacker profiles.
Replaces the simulated dataset with real attack data from your honeypot.
Run: python3 collect_real_data.py
"""
import json, os, glob, pickle, redis, datetime
import numpy as np
from collections import defaultdict
from pathlib import Path

# ── Connect to Redis ──────────────────────────────────────────────────────────
def connect_redis():
    for port in [6380, 6379]:
        try:
            r = redis.Redis(host='127.0.0.1', port=port, db=0,
                           decode_responses=True, socket_timeout=2)
            r.ping()
            print(f"Connected to Redis on port {port}")
            return r
        except Exception:
            continue
    return None

# ── Find all Cowrie log files ─────────────────────────────────────────────────
def find_cowrie_logs():
    patterns = [
        "/opt/cowrie/var/log/cowrie/cowrie.json*",
        "/opt/cowrie/var/log/cowrie.json*",
        "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*",
    ]
    logs = []
    for pattern in patterns:
        logs.extend(glob.glob(pattern))
    return sorted(logs)

# ── Parse Cowrie JSON log ─────────────────────────────────────────────────────
def parse_logs(log_files):
    """Parse all Cowrie log files into structured attacker profiles."""
    sessions = defaultdict(lambda: {
        "ip": "",
        "session_ids": set(),
        "login_attempts": [],
        "commands": [],
        "downloads": [],
        "first_seen": None,
        "last_seen": None,
        "countries": [],
        "total_events": 0,
    })

    total_events = 0
    for log_file in log_files:
        print(f"  Reading: {log_file}")
        try:
            with open(log_file) as f:
                for line in f:
                    try:
                        ev = json.loads(line.strip())
                        etype = ev.get("eventid", "")
                        ip = ev.get("src_ip", ev.get("srcip", ""))
                        ts = ev.get("timestamp", "")
                        session = ev.get("session", "")

                        if not ip:
                            continue

                        total_events += 1
                        s = sessions[ip]
                        s["ip"] = ip
                        s["total_events"] += 1
                        if session:
                            s["session_ids"].add(session)

                        # Track timestamps
                        if ts:
                            if not s["first_seen"] or ts < s["first_seen"]:
                                s["first_seen"] = ts
                            if not s["last_seen"] or ts > s["last_seen"]:
                                s["last_seen"] = ts

                        # Categorise event
                        if "login" in etype:
                            user = ev.get("username", "")
                            pwd = ev.get("password", "")
                            s["login_attempts"].append({"user": user, "pwd": pwd})

                        elif "command" in etype:
                            cmd = ev.get("input", "").strip()
                            if cmd:
                                s["commands"].append(cmd)

                        elif "download" in etype or "shasum" in ev:
                            url = ev.get("url", ev.get("shasum", ""))
                            if url:
                                s["downloads"].append(url)

                    except Exception:
                        continue
        except Exception as e:
            print(f"  Error reading {log_file}: {e}")

    return sessions, total_events

# ── GeoIP lookup ──────────────────────────────────────────────────────────────
def geoip_lookup(ip):
    """Simple GeoIP using ip-api.com (free, no key needed)."""
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,lat,lon"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
            return (
                data.get("country", "Unknown"),
                data.get("countryCode", "XX"),
                data.get("lat", 0.0),
                data.get("lon", 0.0),
            )
    except Exception:
        return ("Unknown", "XX", 0.0, 0.0)

# ── Build attacker profiles ───────────────────────────────────────────────────
COMMON_PASSWORDS = ["123456","password","admin","root","toor","12345","pass",
                    "test","admin123","raspberry","111111","qwerty","guest"]

HONEYTOKEN_FILES = ["passwords.txt","id_rsa",".aws/credentials",
                    "backup.sql","wallet.dat","config.php",".env"]

COUNTRY_RISK = {
    "CN":0.95,"RU":0.90,"UA":0.80,"IR":0.85,"KP":0.95,"BR":0.60,
    "IN":0.55,"VN":0.70,"RO":0.65,"NG":0.70,"US":0.40,"DE":0.35,
    "GB":0.35,"NL":0.45,"SG":0.50,"KR":0.45,
}

def classify_password_intel(passwords):
    if not passwords:
        return "NONE", 0.1
    common = sum(1 for p in passwords if p in COMMON_PASSWORDS)
    ratio = common / len(passwords)
    if ratio > 0.8:   return "SCRIPT_KIDDIE", 0.2
    elif ratio > 0.5: return "AUTOMATED",     0.5
    else:             return "TARGETED",       0.85

def detect_pattern(commands):
    cmd_str = " ".join(commands)
    if "/bin/busybox MIRAI" in cmd_str or "enable" in cmd_str:
        return "Mirai Botnet"
    if "dvrHelper" in cmd_str:
        return "Hajime Worm"
    if "mozi" in cmd_str:
        return "Mozi Botnet"
    if "cat /etc/shadow" in cmd_str or "find / -perm" in cmd_str:
        return "Manual/Targeted"
    if not commands:
        return "Unknown Scanner"
    return "Bruteforce"

def build_profiles(sessions, use_geoip=False):
    profiles = []
    models = pickle.load(open("models/models.pkl", "rb"))

    print(f"\nBuilding profiles for {len(sessions)} real attackers...")

    for i, (ip, s) in enumerate(sessions.items()):
        session_count = len(s["session_ids"]) or 1
        commands      = list(set(s["commands"]))[:25]
        usernames     = list(set(a["user"] for a in s["login_attempts"]))[:10]
        passwords     = list(set(a["pwd"]  for a in s["login_attempts"]))[:10]
        downloads     = s["downloads"][:5]

        pw_intel, pw_risk = classify_password_intel(passwords)
        pattern = detect_pattern(commands)

        # GeoIP
        if use_geoip and i % 10 == 0:
            print(f"  GeoIP lookup {i+1}/{len(sessions)}...")
        country, code, lat, lon = ("Unknown","XX",0.0,0.0)
        if use_geoip:
            import time; time.sleep(0.5)  # rate limit
            country, code, lat, lon = geoip_lookup(ip)

        geo_risk  = COUNTRY_RISK.get(code, 0.4)
        honeytoken_triggered = any(f in " ".join(commands) for f in HONEYTOKEN_FILES)
        accessed_ht = [f for f in HONEYTOKEN_FILES if any(f in c for c in commands)]

        # ML scoring
        features = np.array([[
            session_count, s["total_events"], len(commands),
            len(usernames), len(passwords),
            0.5, 0.5, 0.5
        ]])
        try:
            features_scaled = models["scaler"].transform(features)
            rf_score  = float(models["rf_session"].predict_proba(features)[0][1])
            lr_score  = float(models["lr_session"].predict_proba(features_scaled)[0][1])
            svm_raw   = float(models["svm_attacker"].decision_function(features_scaled)[0])
            svm_score = 1 / (1 + np.exp(-svm_raw))
            base_risk = max(geo_risk*0.3, pw_risk*0.3, min(session_count/40,1)*0.4)
            rf_score  = min(1.0, max(0.0, rf_score + base_risk * 0.2))
            if honeytoken_triggered: rf_score = min(1.0, rf_score + 0.3)
            final_conf = rf_score*0.4 + lr_score*0.35 + svm_score*0.25
        except Exception:
            rf_score = lr_score = svm_score = final_conf = 0.5

        if honeytoken_triggered or final_conf > 0.65: risk = "HIGH"
        elif final_conf > 0.35: risk = "MEDIUM"
        else: risk = "LOW"

        if   session_count >= 15 and len(commands) >= 10: classification = "APT"
        elif session_count >= 8:  classification = "PERSISTENT"
        elif len(commands) >= 8:  classification = "EXPLOITER"
        elif any("wget" in c or "curl" in c for c in commands): classification = "DROPPER"
        elif session_count <= 2 and not commands: classification = "SCANNER"
        else: classification = "BRUTEFORCE"

        abuse_score = int(min(100, final_conf * 100))

        profiles.append({
            "attacker_id": i + 1,
            "ip": ip,
            "country": country, "country_code": code,
            "lat": round(lat, 4), "lon": round(lon, 4),
            "session_count": session_count,
            "classification": classification,
            "attack_pattern": pattern,
            "risk_level": risk,
            "rf_score": round(rf_score, 4),
            "lr_score": round(lr_score, 4),
            "svm_score": round(svm_score, 4),
            "final_confidence": round(final_conf, 4),
            "commands_tried": commands,
            "username_attempts": usernames,
            "password_attempts": passwords,
            "password_intelligence": pw_intel,
            "password_risk_score": round(pw_risk, 2),
            "geo_risk_score": round(geo_risk, 2),
            "honeytoken_triggered": honeytoken_triggered,
            "accessed_honeytokens": accessed_ht,
            "abuse_score": abuse_score,
            "is_known_malicious": abuse_score > 75,
            "first_seen": s["first_seen"] or datetime.datetime.utcnow().isoformat(),
            "last_seen": s["last_seen"] or datetime.datetime.utcnow().isoformat(),
            "blocked": risk == "HIGH",
            "total_events": s["total_events"],
            "downloads": downloads,
            "data_source": "REAL",  # marks this as real data, not simulated
        })

    return profiles

# ── Save and push to Redis ────────────────────────────────────────────────────
def save_and_push(profiles, total_events, r):
    # Save to JSON (replaces simulated data)
    with open("data/attackers.json", "w") as f:
        json.dump(profiles, f)
    print(f"\nSaved {len(profiles)} real attacker profiles to data/attackers.json")

    # Push summary to Redis
    if r:
        summary = {
            "total_attackers": len(profiles),
            "total_events": total_events,
            "high_risk": sum(1 for p in profiles if p["risk_level"] == "HIGH"),
            "blocked": sum(1 for p in profiles if p["blocked"]),
            "last_updated": datetime.datetime.utcnow().isoformat(),
            "data_source": "REAL_COWRIE_LOGS",
        }
        r.set("honeypot:summary", json.dumps(summary))
        print("Pushed summary to Redis.")

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  HoneypotAI — Real Attack Data Collector")
    print("=" * 55)

    import sys
    use_geoip = "--geoip" in sys.argv

    # Find logs
    logs = find_cowrie_logs()
    if not logs:
        print("\nNo Cowrie logs found.")
        print("Make sure Cowrie is running and has received connections.")
        print("Expected location: /opt/cowrie/var/log/cowrie/cowrie.json")
        exit(1)

    print(f"\nFound {len(logs)} log file(s):")
    for l in logs:
        size = os.path.getsize(l)
        print(f"  {l} ({size:,} bytes)")

    # Parse
    print("\nParsing logs...")
    sessions, total_events = parse_logs(logs)
    print(f"Parsed: {total_events:,} events from {len(sessions):,} unique IPs")

    if len(sessions) == 0:
        print("\nNo attacker sessions found yet.")
        print("Wait for some attacks then run this again.")
        exit(0)

    # Build profiles
    if use_geoip:
        print("\nGeoIP lookups enabled (slow but accurate).")
        print("Remove --geoip flag to skip GeoIP and run faster.")
    else:
        print("\nTip: Run with --geoip flag for real country data:")
        print("  python3 collect_real_data.py --geoip")

    profiles = build_profiles(sessions, use_geoip=use_geoip)

    # Connect Redis and save
    r = connect_redis()
    save_and_push(profiles, total_events, r)

    # Stats
    print("\n" + "=" * 55)
    print("  Real Data Collection Complete!")
    print("=" * 55)
    print(f"  Total unique attackers:  {len(profiles)}")
    print(f"  Total events processed:  {total_events:,}")
    print(f"  HIGH risk:               {sum(1 for p in profiles if p['risk_level']=='HIGH')}")
    print(f"  MEDIUM risk:             {sum(1 for p in profiles if p['risk_level']=='MEDIUM')}")
    print(f"  LOW risk:                {sum(1 for p in profiles if p['risk_level']=='LOW')}")
    from collections import Counter
    patterns = Counter(p["attack_pattern"] for p in profiles)
    print(f"\n  Attack patterns detected:")
    for pattern, count in patterns.most_common():
        print(f"    {pattern}: {count}")
    print()
    print("  Restart the dashboard to see real data:")
    print("  sudo docker-compose restart honeypot-dashboard")
    print("  OR: pkill -f streamlit && streamlit run app.py ...")
