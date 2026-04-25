#!/usr/bin/env python3
"""
HoneypotAI — Adaptive Controller
Reads ML classifications from Redis and dynamically adjusts
Cowrie honeypot behavior per attacker IP.

This is what makes the system ADAPTIVE, not just reactive.

Run: python3 adaptive_controller.py
"""
import redis, json, time, datetime, os

# ── Redis connection ──────────────────────────────────────────────────────────
def connect_redis():
    import os
    url = os.environ.get("RENDER_REDIS_URL", "") or os.environ.get("REDIS_URL", "")
    if url:
        try:
            r = redis.from_url(url, decode_responses=True, ssl_cert_reqs=None)
            r.ping()
            print(f"[Adaptive] Connected via URL")
            return r
        except Exception as e:
            print(f"[Adaptive] URL failed: {e}")
    # Try all local ports
    for port in [6380, 6379, 6381]:
        try:
            r = redis.Redis(host='127.0.0.1', port=port, db=0,
                           decode_responses=True, socket_timeout=2)
            r.ping()
            print(f"[Adaptive] Connected to Redis on port {port}")
            return r
        except Exception:
            continue
    return None

r = connect_redis()

# ── Attacker profiles — define HOW Cowrie should behave per type ──────────────
#
# delay       = seconds to wait before responding (frustrate scanners)
# fs_profile  = which fake filesystem to present
#               'minimal'   = empty server, few files, boring
#               'developer' = dev tools, git repos, code files
#               'server'    = web server, config files, logs
#               'corporate' = full company data, PDFs, credentials
# allow_login = whether attacker can get a shell prompt
# decoy_level = how convincing the deception is (1=low, 3=high)
# response    = what action the system takes
#
PROFILES = {
    'SCANNER': {
        'delay':       3.0,
        'fs_profile':  'minimal',
        'allow_login': False,
        'decoy_level': 1,
        'response':    'SLOW_DOWN',
        'description': 'Frustrate scanner with delays and empty system',
    },
    'BRUTEFORCE': {
        'delay':       1.5,
        'fs_profile':  'minimal',
        'allow_login': False,
        'decoy_level': 1,
        'response':    'THROTTLE',
        'description': 'Throttle brute forcer, deny login, waste time',
    },
    'EXPLOITER': {
        'delay':       0.2,
        'fs_profile':  'developer',
        'allow_login': True,
        'decoy_level': 2,
        'response':    'ENGAGE',
        'description': 'Engage exploiter with realistic dev environment',
    },
    'DROPPER': {
        'delay':       0.1,
        'fs_profile':  'server',
        'allow_login': True,
        'decoy_level': 2,
        'response':    'CAPTURE',
        'description': 'Let dropper in to capture malware samples',
    },
    'PERSISTENT': {
        'delay':       0.0,
        'fs_profile':  'server',
        'allow_login': True,
        'decoy_level': 3,
        'response':    'MONITOR',
        'description': 'Full server environment to keep persistent attacker engaged',
    },
    'APT': {
        'delay':       0.0,
        'fs_profile':  'corporate',
        'allow_login': True,
        'decoy_level': 3,
        'response':    'FULL_DECEPTION',
        'description': 'Corporate environment with sensitive-looking data to trap APT',
    },
}

# Fake filesystem file lists per profile
FAKE_FILESYSTEMS = {
    'minimal': [
        '/etc/passwd', '/etc/hostname', '/tmp',
    ],
    'developer': [
        '/home/dev/projects/app.py', '/home/dev/.ssh/id_rsa',
        '/home/dev/.gitconfig', '/home/dev/notes.txt',
        '/etc/passwd', '/etc/sudoers',
        '/var/log/syslog',
    ],
    'server': [
        '/var/www/html/index.php', '/etc/apache2/sites-enabled/default',
        '/etc/nginx/nginx.conf', '/home/ubuntu/.ssh/authorized_keys',
        '/var/log/apache2/access.log', '/etc/mysql/my.cnf',
        '/home/ubuntu/db_backup.sql', '/etc/passwd',
    ],
    'corporate': [
        '/home/admin/passwords.txt', '/home/admin/.aws/credentials',
        '/home/admin/backup.sql', '/home/admin/id_rsa',
        '/home/admin/salary_data.xlsx', '/var/www/portal/config.php',
        '/etc/passwd', '/home/admin/.bash_history',
        '/home/admin/vpn_config.ovpn', '/home/admin/wallet.dat',
    ],
}

def apply_adaptation(ip, attacker_type):
    """Apply behavioral profile to an attacker IP in Redis."""
    profile = PROFILES.get(attacker_type, PROFILES['SCANNER'])

    # Write full profile to Redis so Cowrie hook can read it
    adaptation_data = {
        'attacker_type': attacker_type,
        'delay':         str(profile['delay']),
        'fs_profile':    profile['fs_profile'],
        'allow_login':   str(profile['allow_login']),
        'decoy_level':   str(profile['decoy_level']),
        'response':      profile['response'],
        'applied_at':    datetime.datetime.utcnow().isoformat(),
    }

    if r:
        r.hset(f'adaptation:{ip}', mapping=adaptation_data)
        r.expire(f'adaptation:{ip}', 3600)  # expires after 1 hour

        # Also log this adaptation event
        ev = {
            'timestamp':    datetime.datetime.utcnow().isoformat(),
            'ip':           ip,
            'service':      'ADAPTIVE_ENGINE',
            'event_type':   f'ADAPTED_{attacker_type}',
            'data':         f"Profile: {profile['fs_profile']} | "
                           f"Delay: {profile['delay']}s | "
                           f"Login: {profile['allow_login']} | "
                           f"Response: {profile['response']}",
        }
        r.lpush('honeypot:events', json.dumps(ev))
        r.ltrim('honeypot:events', 0, 99999)

    print(f"[Adaptive] {ip} → {attacker_type}")
    print(f"  Profile:  {profile['fs_profile']}")
    print(f"  Delay:    {profile['delay']}s")
    print(f"  Login:    {profile['allow_login']}")
    print(f"  Response: {profile['response']}")
    print(f"  Reason:   {profile['description']}")

def get_adaptation(ip):
    """Get current adaptation for an IP (used by Cowrie hook)."""
    if not r:
        return None
    profile = r.hgetall(f'adaptation:{ip}')
    return profile if profile else None

def run_from_redis_stream():
    """
    Listen for ML classifications published to Redis
    and apply adaptations automatically.
    """
    print("=" * 55)
    print("  HoneypotAI — Adaptive Controller")
    print("=" * 55)
    print("  Listening for ML classifications...")
    print("  Profiles: SCANNER → BRUTEFORCE → EXPLOITER")
    print("            → DROPPER → PERSISTENT → APT")
    print("=" * 55)

    if not r:
        print("[Adaptive] Cannot connect to Redis")
        return

    # Also process existing attacker profiles from data
    # by reading recent high-confidence detections
    last_processed = set()

    while True:
        try:
            # Read recent events and auto-classify new IPs
            raw_events = r.lrange('honeypot:events', 0, 199)
            ip_event_counts = {}

            for raw in raw_events:
                try:
                    ev = json.loads(raw)
                    ip = ev.get('ip','').strip()
                    etype = ev.get('event_type','')
                    if ip and ip != 'unknown':
                        if ip not in ip_event_counts:
                            ip_event_counts[ip] = {
                                'total':0,'logins':0,'cmds':0,
                                'honeytokens':0,'sqli':0
                            }
                        ip_event_counts[ip]['total'] += 1
                        if etype == 'LOGIN_ATTEMPT': ip_event_counts[ip]['logins'] += 1
                        if etype == 'CMD':           ip_event_counts[ip]['cmds']   += 1
                        if etype == 'HONEYTOKEN_ACCESS': ip_event_counts[ip]['honeytokens'] += 1
                        if etype == 'SQL_INJECTION_ATTEMPT': ip_event_counts[ip]['sqli'] += 1
                except Exception:
                    continue

            # Apply adaptations for new IPs
            for ip, counts in ip_event_counts.items():
                if ip in last_processed:
                    continue

                # Classify based on behavior
                if counts['honeytokens'] > 0 or counts['sqli'] > 0:
                    atype = 'APT'
                elif counts['cmds'] >= 10:
                    atype = 'EXPLOITER'
                elif counts['total'] >= 15:
                    atype = 'PERSISTENT'
                elif any(k in str(r.hget(f'adaptation:{ip}','attacker_type') or '')
                        for k in ['wget','curl','dropper']):
                    atype = 'DROPPER'
                elif counts['logins'] >= 5:
                    atype = 'BRUTEFORCE'
                else:
                    atype = 'SCANNER'

                apply_adaptation(ip, atype)
                last_processed.add(ip)

            time.sleep(10)

        except KeyboardInterrupt:
            print("\n[Adaptive] Stopped.")
            break
        except Exception as e:
            print(f"[Adaptive] Error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    run_from_redis_stream()
