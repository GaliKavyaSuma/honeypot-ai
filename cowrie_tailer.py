#!/usr/bin/env python3
"""
Cowrie Log Tailer — reads Cowrie logs and pushes to Redis in real time.
Handles both JSON output and text log formats.
Run: python3 cowrie_tailer.py
"""
import json, time, os, datetime, re

def connect_redis():
    import redis as redis_lib
    for port in [6380, 6379]:
        try:
            r = redis_lib.Redis(host='127.0.0.1', port=port, db=0,
                               decode_responses=True, socket_timeout=2)
            r.ping()
            print(f"[Cowrie Tailer] Connected to Redis on port {port}")
            return r
        except Exception:
            continue
    print("[Cowrie Tailer] WARNING: Redis not available.")
    return None

r = connect_redis()

# Possible Cowrie log locations — tries each one
POSSIBLE_JSON = [
    "/opt/cowrie/var/log/cowrie/cowrie.json",
    "/opt/cowrie/var/log/cowrie.json",
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
]
POSSIBLE_TEXT = [
    "/opt/cowrie/var/log/cowrie/cowrie.log",
    "/opt/cowrie/var/log/cowrie.log",
]

def find_log():
    """Find whichever Cowrie log file exists."""
    for p in POSSIBLE_JSON:
        if os.path.exists(p):
            return p, "json"
    for p in POSSIBLE_TEXT:
        if os.path.exists(p):
            return p, "text"
    return None, None

def push_event(ip, event_type, data="", service="SSH"):
    if not r:
        return
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ip": ip, "port": 2222, "service": service,
        "event_type": event_type, "data": str(data)[:200],
    }
    try:
        r.lpush("honeypot:events", json.dumps(event))
        r.ltrim("honeypot:events", 0, 99999)
        print(f"[SSH] {ip} — {event_type}: {data[:60]}")
    except Exception:
        pass

def parse_json_line(line):
    try:
        ev = json.loads(line.strip())
        etype = ev.get("eventid", "")
        ip = ev.get("src_ip", ev.get("srcip", "unknown"))
        if "login" in etype:
            user = ev.get("username","")
            pwd  = ev.get("password","")
            push_event(ip, "LOGIN_ATTEMPT", f"user={user} pass={pwd}")
        elif "command" in etype:
            push_event(ip, "CMD", ev.get("input",""))
        elif "session.connect" in etype:
            push_event(ip, "connection", f"New connection from {ip}")
        elif "download" in etype:
            push_event(ip, "file_download", ev.get("url", ev.get("shasum","")))
    except Exception:
        pass

def parse_text_line(line):
    """Parse Cowrie text log lines."""
    try:
        # Extract IP from text log lines like: [HoneyPotSSHTransport,0,10.0.2.2]
        ip_match = re.search(r'HoneyPotSSH\S+,(\d+\.\d+\.\d+\.\d+)', line)
        if not ip_match:
            return
        ip = ip_match.group(1)

        if "login attempt" in line or "CMD:" in line.upper():
            # Login: login attempt [admin/admin] succeeded
            cred_match = re.search(r'\[(.+?)/(.+?)\]', line)
            if cred_match:
                push_event(ip, "LOGIN_ATTEMPT", f"user={cred_match.group(1)} pass={cred_match.group(2)}")
        elif "CMD:" in line:
            cmd_match = re.search(r'CMD:\s+(.+)', line)
            if cmd_match:
                push_event(ip, "CMD", cmd_match.group(1).strip())
        elif "Connection lost" in line or "New connection" in line:
            push_event(ip, "connection", "SSH connection")
    except Exception:
        pass

def tail_forever():
    print("[Cowrie Tailer] Starting up...")

    log_path = None
    log_type = None

    while not log_path:
        log_path, log_type = find_log()
        if not log_path:
            print("[Cowrie Tailer] Log not found yet, waiting...")
            print(f"  Checked: {POSSIBLE_JSON + POSSIBLE_TEXT}")
            time.sleep(5)

    print(f"[Cowrie Tailer] Found {log_type} log: {log_path}")
    print("[Cowrie Tailer] Watching for SSH attacks...")

    with open(log_path, "r") as f:
        f.seek(0, 2)  # seek to end, don't replay old events
        while True:
            line = f.readline()
            if line and line.strip():
                if log_type == "json":
                    parse_json_line(line)
                else:
                    parse_text_line(line)
            else:
                time.sleep(0.3)

if __name__ == "__main__":
    tail_forever()
