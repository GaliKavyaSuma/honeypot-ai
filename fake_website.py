#!/usr/bin/env python3
"""HoneypotAI — NexaCorp Enhanced Web Honeypot with Adaptive Behavior"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import json, datetime, random, string, time, os

def connect_redis():
    redis_url = os.environ.get("REDIS_URL", "")
    if redis_url:
        try:
            import redis as rl
            if redis_url.startswith("rediss://"):
                r = rl.from_url(redis_url, decode_responses=True,
                               ssl_cert_reqs=None, socket_timeout=5)
            else:
                r = rl.from_url(redis_url, decode_responses=True, socket_timeout=5)
            r.ping()
            print(f"[WEB] Redis connected via REDIS_URL ({redis_url[:30]}...)")
            return r
        except Exception as e:
            print(f"[WEB] REDIS_URL failed: {e}")

    for port in [6380, 6379]:
        try:
            import redis as rl
            r = rl.Redis(host='127.0.0.1', port=port, db=0, decode_responses=True, socket_timeout=2)
            r.ping()
            print(f"[WEB] Redis on port {port}")
            return r
        except Exception:
            continue
    print("[WEB] No Redis available")
    return None

r = connect_redis()

def get_adaptive_profile(ip):
    """
    Returns behavioral profile for this IP.
    Priority:
    1. Check Redis for explicit profile (set by adaptive_controller or /demo)
    2. Auto-classify from behavior in Redis events
    3. On Render (REDIS_URL set) → default APT
    4. Locally → default SCANNER
    """
    import os
    is_render = bool(os.environ.get("REDIS_URL", ""))

    # Step 1: Check Redis for existing profile
    if r:
        try:
            profile = r.hgetall(f"adaptation:{ip}")
            if profile and profile.get("attacker_type"):
                return profile
        except Exception:
            pass

        # Step 2: Auto-classify from actual behavior in Redis
        try:
            raw_events = r.lrange("honeypot:events", 0, 199)
            ip_events = [json.loads(e) for e in raw_events
                        if json.loads(e).get("ip") == ip]
            if ip_events:
                logins   = sum(1 for e in ip_events if e.get("event_type") == "LOGIN_ATTEMPT")
                cmds     = sum(1 for e in ip_events if e.get("event_type") == "CMD")
                tokens   = sum(1 for e in ip_events if e.get("event_type") == "HONEYTOKEN_ACCESS")
                sqli     = sum(1 for e in ip_events if e.get("event_type") == "SQL_INJECTION_ATTEMPT")
                admin    = sum(1 for e in ip_events if e.get("event_type") == "ADMIN_ACCESS")
                api      = sum(1 for e in ip_events if e.get("event_type") == "API_PROBE")
                env_prob = sum(1 for e in ip_events if e.get("event_type") == "SENSITIVE_PATH_PROBE")
                total    = len(ip_events)

                # Classify based on real behavior
                if tokens > 0 or sqli > 0:
                    atype = "APT"
                elif cmds >= 5 or (admin >= 2 and api >= 1):
                    atype = "PERSISTENT"
                elif admin >= 1 and env_prob >= 1:
                    atype = "EXPLOITER"
                elif logins >= 3:
                    atype = "BRUTEFORCE"
                elif total >= 5:
                    atype = "SCANNER"
                else:
                    atype = None  # not enough activity yet

                if atype:
                    PROFILES = {
                        "SCANNER":    {"attacker_type":"SCANNER",   "delay":"3.0","fs_profile":"minimal",  "allow_login":"False","decoy_level":"1","response":"SLOW_DOWN"},
                        "BRUTEFORCE": {"attacker_type":"BRUTEFORCE","delay":"1.5","fs_profile":"minimal",  "allow_login":"False","decoy_level":"1","response":"THROTTLE"},
                        "EXPLOITER":  {"attacker_type":"EXPLOITER", "delay":"0.2","fs_profile":"developer","allow_login":"True", "decoy_level":"2","response":"ENGAGE"},
                        "PERSISTENT": {"attacker_type":"PERSISTENT","delay":"0.0","fs_profile":"server",   "allow_login":"True", "decoy_level":"3","response":"MONITOR"},
                        "APT":        {"attacker_type":"APT",       "delay":"0.0","fs_profile":"corporate","allow_login":"True", "decoy_level":"3","response":"FULL_DECEPTION"},
                    }
                    profile = PROFILES[atype]
                    # Save for next request
                    r.hset(f"adaptation:{ip}", mapping=profile)
                    r.expire(f"adaptation:{ip}", 3600)
                    return profile
        except Exception:
            pass

    # Step 3: Render default = APT (no controller running, show max deception)
    if is_render:
        return {
            "attacker_type": "APT",
            "delay": "0.0",
            "fs_profile": "corporate",
            "allow_login": "True",
            "decoy_level": "3",
            "response": "FULL_DECEPTION"
        }

    # Step 4: Local default = SCANNER (restricted, for real demo)
    return None

def adaptive_delay(ip):
    """Apply delay based on attacker profile — frustrate scanners, engage APTs instantly."""
    profile = get_adaptive_profile(ip)
    if profile:
        delay = float(profile.get("delay", 0.0))
        if delay > 0:
            time.sleep(delay)
    return profile

def get_adaptive_content(ip, base_page):
    """
    Return different content based on attacker's ML classification.
    - SCANNER/BRUTEFORCE: minimal content, boring
    - EXPLOITER/DROPPER: developer-looking content
    - PERSISTENT/APT: full corporate environment with more bait
    """
    profile = get_adaptive_profile(ip)
    if not profile:
        return base_page, "DEFAULT"

    atype    = profile.get("attacker_type", "SCANNER")
    fs       = profile.get("fs_profile", "minimal")
    response = profile.get("response", "SLOW_DOWN")
    return base_page, f"{atype}|{fs}|{response}"

def _placeholder_removed(): pass  # adaptive_admin_page moved to after CSS/nav definitions

def log(ip, etype, data=""):
    ev = {"timestamp": datetime.datetime.utcnow().isoformat(),
          "ip": ip, "port": 8888, "service": "WEB_HONEYPOT",
          "event_type": etype, "data": str(data)[:500]}
    if r:
        try: r.lpush("honeypot:events", json.dumps(ev)); r.ltrim("honeypot:events", 0, 99999)
        except: pass
    print(f"[WEB] {ip} — {etype}: {data[:80]}")

CSS = """
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f7fa;min-height:100vh;}
/* NAV */
.nav{background:#0f2744;height:56px;display:flex;align-items:center;justify-content:space-between;padding:0 32px;box-shadow:0 2px 8px rgba(0,0,0,0.3);position:relative;z-index:100;}
.nav .brand{color:white;font-size:1.05rem;font-weight:700;display:flex;align-items:center;gap:8px;}
.nav .links a{color:#8ab4d4;text-decoration:none;margin-left:20px;font-size:0.88rem;}
.nav .links a:hover{color:white;}
.nav .usr{color:#8ab4d4;font-size:0.82rem;display:flex;align-items:center;gap:10px;}
/* LAYOUT */
.page-wrap{display:flex;min-height:calc(100vh - 56px);}
.sidebar{width:220px;background:#0f2744;flex-shrink:0;padding:16px 0;}
.sidebar a{display:block;padding:9px 24px;color:#8ab4d4;text-decoration:none;font-size:0.86rem;}
.sidebar a:hover,.sidebar a.active{background:#1a3a5c;color:white;border-left:3px solid #42a5f5;}
.sidebar .sec{padding:12px 24px 4px;font-size:0.68rem;color:#4a6080;text-transform:uppercase;letter-spacing:2px;}
.main{flex:1;padding:28px;overflow:auto;}
/* PUBLIC PAGES */
.public-body{background:#f5f7fa;}
.container{max-width:1100px;margin:0 auto;padding:32px 24px;}
/* CARDS */
.card{background:white;border-radius:8px;padding:28px;box-shadow:0 1px 4px rgba(0,0,0,0.08);margin-bottom:20px;}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;}
.stat-card{background:white;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,0.08);border-left:4px solid #1565c0;}
.stat-val{font-size:1.8rem;font-weight:700;color:#0f2744;}
.stat-lbl{font-size:0.8rem;color:#666;margin-top:4px;text-transform:uppercase;letter-spacing:1px;}
/* FORMS */
.btn{padding:10px 24px;border:none;border-radius:6px;cursor:pointer;font-size:0.9rem;font-weight:600;}
.btn-primary{background:#1565c0;color:white;width:100%;}
.btn-primary:hover{background:#0d47a1;}
.form-group{margin-bottom:16px;}
.form-group label{display:block;font-size:0.83rem;font-weight:600;color:#444;margin-bottom:5px;}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:6px;font-size:0.92rem;outline:none;font-family:inherit;}
.form-group input:focus,.form-group select:focus{border-color:#1565c0;box-shadow:0 0 0 3px rgba(21,101,192,0.12);}
/* BADGES */
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.72rem;font-weight:700;}
.badge-red{background:#fdecea;color:#c62828;}
.badge-green{background:#e8f5e9;color:#2e7d32;}
.badge-blue{background:#e3f2fd;color:#1565c0;}
.badge-orange{background:#fff3e0;color:#e65100;}
/* ALERTS */
.alert{padding:12px 16px;border-radius:6px;margin-bottom:16px;font-size:0.88rem;}
.alert-danger{background:#fdecea;border:1px solid #ef9a9a;color:#c62828;}
.alert-info{background:#e3f2fd;border:1px solid #90caf9;color:#1565c0;}
.alert-success{background:#e8f5e9;border:1px solid #a5d6a7;color:#2e7d32;}
/* TABLE */
table{width:100%;border-collapse:collapse;font-size:0.88rem;}
th{background:#f0f4f8;padding:10px 12px;text-align:left;border-bottom:2px solid #dee2e6;font-weight:700;color:#444;}
td{padding:10px 12px;border-bottom:1px solid #eee;color:#333;vertical-align:middle;}
tr:hover{background:#f8f9fb;}
/* PROGRESS */
.progress{background:#e8eaf0;border-radius:4px;height:8px;margin-top:4px;}
.progress-bar{height:100%;border-radius:4px;background:#1565c0;}
/* FOOTER */
footer{background:#0f2744;color:#8ab4d4;text-align:center;padding:20px;font-size:0.8rem;}
</style>"""

def public_nav():
    return f"""<nav class='nav'>
  <div class='brand'>
    <span style='background:#1565c0;color:white;padding:4px 8px;border-radius:4px;font-size:0.75rem;font-weight:900;'>NC</span>
    NexaCorp Enterprise Portal
  </div>
  <div class='links'>
    <a href='/'>Home</a><a href='/about'>About</a>
    <a href='/careers'>Careers</a><a href='/support'>Support</a>
  </div>
  <div class='usr'>
    <span style='background:#1565c0;color:white;padding:4px 8px;border-radius:4px;font-size:0.8rem;'>🔒 Secure</span>
  </div>
</nav>"""

def auth_nav():
    return """<nav class='nav'>
  <div class='brand'>
    <span style='background:#1565c0;color:white;padding:4px 8px;border-radius:4px;font-size:0.75rem;font-weight:900;'>NC</span>
    NexaCorp Enterprise Portal
  </div>
  <div class='links'>
    <a href='/dashboard'>Dashboard</a>
    <a href='/admin'>Admin</a>
    <a href='/files'>Files</a>
    <a href='/vpn'>VPN</a>
  </div>
  <div class='usr'>
    <span>👤 administrator</span>
    <a href='/' style='color:#ef9a9a;margin-left:12px;'>Logout</a>
  </div>
</nav>"""

def sidebar():
    return """<div class='sidebar'>
  <div class='sec'>Main</div>
  <a href='/dashboard'>📊 Dashboard</a>
  <a href='/reports'>📈 Reports</a>
  <a href='/alerts-internal'>🔔 Alerts</a>
  <div class='sec'>Management</div>
  <a href='/admin'>👥 User Admin</a>
  <a href='/admin/servers'>🖥 Servers</a>
  <a href='/admin/db'>🗄 Databases</a>
  <div class='sec'>Security</div>
  <a href='/vpn'>🔐 VPN</a>
  <a href='/security'>🛡 Security Logs</a>
  <div class='sec'>Files</div>
  <a href='/files'>📁 File Server</a>
  <a href='/backup'>💾 Backups</a>
</div>"""

def page(title, body, auth=False):
    nav = auth_nav() if auth else public_nav()
    wrap = f"<div class='page-wrap'>{sidebar()}<div class='main'>{body}</div></div>" if auth else f"<div class='public-body'><div class='container'>{body}</div><footer>© 2026 NexaCorp Inc. All rights reserved. | support@nexacorp.com</footer></div>"
    return f"<!DOCTYPE html><html><head><title>{title} — NexaCorp</title>{CSS}</head><body>{nav}{wrap}</body></html>"

def get_attacker_tier(ip):
    """Returns 1=SCANNER/BRUTEFORCE, 2=EXPLOITER/DROPPER, 3=PERSISTENT/APT, 0=DEFAULT"""
    profile = get_adaptive_profile(ip)
    if not profile:
        return 0, "DEFAULT"
    atype = profile.get("attacker_type", "DEFAULT")
    if atype in ["SCANNER", "BRUTEFORCE"]:
        return 1, atype
    elif atype in ["EXPLOITER", "DROPPER"]:
        return 2, atype
    elif atype in ["PERSISTENT", "APT"]:
        return 3, atype
    return 0, "DEFAULT"

def adaptive_login_page(ip, error=""):
    """Login page changes based on classification — drops breadcrumbs for advanced attackers."""
    tier, atype = get_attacker_tier(ip)
    err_html = f"<div class='alert alert-danger'>{error}</div>" if error else ""

    # Hidden comments in HTML source — visible to attackers who view source
    if tier == 0 or tier == 1:
        # Standard login — no hints
        secret_comment = "<!-- NexaCorp Portal v2.4.1 -->"
    elif tier == 2:
        # Exploiters see a db hostname leak in HTML comment
        secret_comment = "<!-- NexaCorp Portal v2.4.1 | DB: nexadb01.corp.nexacorp.com:5432 -->"
    else:
        # APT/PERSISTENT — full credential leak in HTML source
        secret_comment = "<!-- NexaCorp Portal v2.4.1 | DB: nexadb01.corp.nexacorp.com:5432 | admin_hash: $2b$12$nexacorp2024secret | default_admin: admin@nexacorp.com / NexaAdmin@2024 -->"

    # Placeholder text changes — more specific for advanced attackers
    if tier >= 2:
        placeholder = "firstname.lastname@nexacorp.com (try admin@nexacorp.com)"
    else:
        placeholder = "firstname.lastname@nexacorp.com"

    # Footer hint for APT
    apt_hint = ""
    if tier == 3:
        apt_hint = f"<div style='background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:8px;margin-top:8px;font-size:0.75rem;color:#856404;'>System maintenance mode — use admin credentials</div>"

    return f"""<!DOCTYPE html><html><head><title>NexaCorp Employee Portal</title>{CSS}
{secret_comment}
<style>
.login-bg{{background:#0f2744;min-height:100vh;display:flex;flex-direction:column;}}
.login-box{{background:white;border-radius:10px;padding:44px 40px;width:440px;margin:auto;box-shadow:0 20px 60px rgba(0,0,0,0.4);}}
</style></head>
<body class='login-bg'>
{public_nav()}
<div style='flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px;'>
<div class='login-box'>
  <div style='text-align:center;margin-bottom:28px;'>
    <div style='background:#0f2744;color:white;width:56px;height:56px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;font-weight:900;margin:0 auto 12px;'>NC</div>
    <div style='font-size:1.25rem;font-weight:700;color:#0f2744;'>NexaCorp Employee Portal</div>
    <div style='font-size:0.75rem;color:#888;margin-top:4px;letter-spacing:1px;'>SECURE ENTERPRISE ACCESS</div>
    <div style='display:flex;justify-content:center;gap:8px;margin-top:10px;'>
      <span style='background:#e8f5e9;color:#2e7d32;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;'>🔒 TLS 1.3</span>
      <span style='background:#e3f2fd;color:#1565c0;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;'>SOC 2 Type II</span>
      <span style='background:#fff3e0;color:#e65100;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;'>ISO 27001</span>
    </div>
  </div>
  {err_html}
  {apt_hint}
  <form method='POST' action='/login'>
    <div class='form-group'>
      <label>Corporate Email Address</label>
      <input type='email' name='username' placeholder='{placeholder}' required>
    </div>
    <div class='form-group'>
      <label>Password</label>
      <input type='password' name='password' placeholder='Enter your password' required>
    </div>
    <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;'>
      <label style='display:flex;align-items:center;gap:6px;font-size:0.83rem;font-weight:400;'>
        <input type='checkbox' style='width:auto;'> Keep me signed in
      </label>
      <a href='/forgot-password' style='font-size:0.82rem;color:#1565c0;'>Forgot password?</a>
    </div>
    <button type='submit' class='btn btn-primary'>Sign In to Portal</button>
  </form>
  <div style='text-align:center;margin-top:18px;font-size:0.82rem;color:#888;'>
    Or sign in with <a href='/sso/microsoft' style='color:#1565c0;font-weight:600;'>Microsoft SSO</a>
    &nbsp;·&nbsp; <a href='/sso/google' style='color:#1565c0;font-weight:600;'>Google Workspace</a>
  </div>
  <div style='margin-top:24px;padding-top:18px;border-top:1px solid #eee;font-size:0.74rem;color:#aaa;text-align:center;line-height:1.7;'>
    Authorised access only. All sessions are monitored.<br>
    IT Helpdesk: +91-80-4521-8800 · support@nexacorp.com<br>
    © 2026 NexaCorp Inc.
  </div>
</div></div></body></html>"""

def adaptive_files_page(ip):
    """File server shows different files based on attacker tier."""
    tier, atype = get_attacker_tier(ip)
    log(ip, "FILE_SERVER_ACCESS", f"Accessed /files [{atype}]")

    if tier <= 1:
        # SCANNER/BRUTEFORCE — access denied
        body = """<div class='card' style='text-align:center;padding:48px;'>
          <div style='font-size:3rem;'>🚫</div>
          <h2 style='color:#c62828;margin:16px 0;'>Access Denied</h2>
          <p style='color:#666;'>You do not have permission to access the file server.</p>
          <a href='/' style='color:#1565c0;display:block;margin-top:16px;'>← Return to Login</a>
        </div>"""
        return page("Access Denied", body)

    elif tier == 2:
        # EXPLOITER/DROPPER — developer files only
        body = """<h2 style='color:#0f2744;margin-bottom:20px;'>Developer File Server</h2>
        <div class='card'>
          <div style='display:flex;justify-content:space-between;margin-bottom:16px;'>
            <span style='background:#f0f4f8;padding:6px 12px;border-radius:4px;font-size:0.82rem;font-family:monospace;'>📁 /home/dev</span>
          </div>
          <table><tr><th>Name</th><th>Size</th><th>Modified</th><th>Action</th></tr>
          <tr><td>📁 projects</td><td>—</td><td>2026-03-15</td><td><a href='/files/projects' style='color:#1565c0;'>Open</a></td></tr>
          <tr><td>📄 app.py</td><td>24 KB</td><td>2026-04-01</td><td><a href='/files/download/app.py' style='color:#1565c0;'>Download</a></td></tr>
          <tr><td>📄 config.dev.json</td><td>2.1 KB</td><td>2026-03-28</td><td><a href='/files/download/config.dev.json' style='color:#1565c0;'>Download</a></td></tr>
          <tr><td>🔑 id_rsa.pub</td><td>0.7 KB</td><td>2025-11-12</td><td><a href='/files/download/id_rsa.pub' style='color:#1565c0;'>Download</a></td></tr>
          </table>
        </div>"""
        return page("Dev Files", body, auth=True)

    else:
        # PERSISTENT/APT — full server with all honeytokens visible
        body = """<h2 style='color:#0f2744;margin-bottom:20px;'>NexaCorp File Server — Production</h2>
        <div class='card'>
          <div style='display:flex;justify-content:space-between;margin-bottom:16px;'>
            <span style='background:#f0f4f8;padding:6px 12px;border-radius:4px;font-size:0.82rem;font-family:monospace;'>📁 /home/admin</span>
            <button class='btn' style='background:#e8eaf0;color:#333;padding:6px 14px;font-size:0.82rem;width:auto;'>Upload File</button>
          </div>
          <table><tr><th>Name</th><th>Size</th><th>Modified</th><th>Permissions</th><th>Action</th></tr>
          <tr><td>📁 backup</td><td>—</td><td>2026-03-15</td><td style='font-family:monospace;'>drwxr-x---</td><td><a href='/files/backup' style='color:#1565c0;'>Open</a></td></tr>
          <tr><td>📁 configs</td><td>—</td><td>2026-02-28</td><td style='font-family:monospace;'>drwxr-x---</td><td><a href='/files/configs' style='color:#1565c0;'>Open</a></td></tr>
          <tr><td>📄 backup.sql</td><td>847 MB</td><td>2026-04-01</td><td style='font-family:monospace;'>-rw-r-----</td><td><a href='/files/download/backup.sql' style='color:#1565c0;'>Download</a></td></tr>
          <tr><td>🔑 id_rsa</td><td>3.3 KB</td><td>2025-11-12</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/id_rsa' style='color:#1565c0;'>Download</a></td></tr>
          <tr><td>🔑 id_rsa.pub</td><td>0.7 KB</td><td>2025-11-12</td><td style='font-family:monospace;'>-rw-r--r--</td><td><a href='/files/download/id_rsa.pub' style='color:#1565c0;'>Download</a></td></tr>
          <tr><td>📄 passwords.txt</td><td>12 KB</td><td>2026-01-08</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/passwords.txt' style='color:#1565c0;'>Download</a></td></tr>
          <tr><td>📄 .env</td><td>2.1 KB</td><td>2026-03-20</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/.env' style='color:#1565c0;'>Download</a></td></tr>
          <tr><td>📄 wallet.dat</td><td>0.3 KB</td><td>2025-09-04</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/wallet.dat' style='color:#1565c0;'>Download</a></td></tr>
          </table>
        </div>"""
        return page("File Server", body, auth=True)

def adaptive_api_response(ip):
    """API returns different data based on attacker classification."""
    tier, atype = get_attacker_tier(ip)
    if tier <= 1:
        return {"error": "403 Forbidden", "message": "Access denied"}
    elif tier == 2:
        return {
            "status": "ok", "version": "1.4.2",
            "users": [
                {"id": 1, "name": "Dev Bot", "email": "devbot@nexacorp.com", "role": "developer"},
                {"id": 2, "name": "Test User", "email": "test@nexacorp.com", "role": "qa"},
            ]
        }
    else:
        return {
            "status": "ok", "version": "1.4.2", "environment": "production",
            "database_host": "nexadb01.corp.nexacorp.com:5432",
            "users": [
                {"id": 1, "name": "Rajesh Menon", "email": "r.menon@nexacorp.com", "role": "super_admin", "api_key": "sk-nex-prod-a8f3d2b1c9e4f7a2", "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCO"},
                {"id": 2, "name": "Priya Sharma", "email": "p.sharma@nexacorp.com", "role": "admin", "api_key": "sk-nex-prod-b9g4e3c2d0f5g8b3"},
                {"id": 3, "name": "Arjun Patel", "email": "a.patel@nexacorp.com", "role": "engineer", "api_key": "sk-nex-dev-c0h5f4d3e1g6h9c4"},
            ],
            "server_config": {
                "jwt_secret": "nexacorp-jwt-secret-2024-prod-abc123xyz",
                "db_password": "NexaDB@2024!SecretPass",
                "aws_access_key": "AKIAIOSFODNN7NEXACORP",
                "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEXAKEY"
            }
        }

def adaptive_env_response(ip):
    """/.env returns different secrets based on classification."""
    tier, atype = get_attacker_tier(ip)
    if tier <= 1:
        return None  # 404
    elif tier == 2:
        return "DB_HOST=devdb01.corp\nDB_PORT=5432\nDB_USER=dev\nDB_PASS=dev123\nREDIS_URL=redis://localhost:6379\nENV=development\n"
    else:
        return "DB_HOST=nexadb01.corp.nexacorp.com\nDB_PORT=5432\nDB_USER=nexaadmin\nDB_PASS=NexaDB@2024!SecretPass\nREDIS_URL=redis://:Redis@NexaCache2024@nexaredis01.corp:6379\nJWT_SECRET=nexacorp-jwt-secret-2024-prod-abc123xyz\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7NEXACORP\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEXAKEY\nSMTP_PASSWORD=NexaMail@SMTP2024\nENV=production\n"

def adaptive_nav_hint(ip):
    """Returns extra nav items based on tier — APT sees admin link in nav."""
    tier, atype = get_attacker_tier(ip)
    if tier >= 3:
        return "<a href='/admin' style='color:#ff8a80;font-weight:700;'>⚙ Admin</a>"
    return ""

def adaptive_admin_page(ip):
    """
    Returns DIFFERENT admin page content based on ML attacker classification.
    This is the core adaptive behavior — same URL, different response per attacker.
    """
    profile = get_adaptive_profile(ip)
    atype = profile.get("attacker_type", "DEFAULT") if profile else "DEFAULT"

    if atype in ["SCANNER", "BRUTEFORCE", "DEFAULT"]:
        # Boring restricted page — waste their time, give nothing
        body = """
        <h2 style='color:#0f2744;margin-bottom:20px;'>User Administration</h2>
        <div class='card'>
          <div class='alert alert-danger'>⚠ Access Restricted.<br>Administrator approval required to view this panel.</div>
          <p style='color:#666;margin-top:12px;'>Submit a request to <a href='/support' style='color:#1565c0;'>IT Support</a> to request elevated access.</p>
        </div>"""
        return page("Admin — Restricted", body, auth=True)

    elif atype in ["EXPLOITER", "DROPPER"]:
        # Developer environment — partial bait
        body = """
        <!-- DB: postgresql://dev:dev123@db01.corp:5432/portal_dev -->
        <h2 style='color:#0f2744;margin-bottom:20px;'>User Administration (Dev Environment)</h2>
        <div class='alert alert-info'>ℹ Development environment — some production features are disabled.</div>
        <div class='card'>
          <h3 style='color:#0f2744;margin-bottom:16px;'>Dev Team Directory</h3>
          <table><tr><th>Name</th><th>Email</th><th>Role</th><th>Access Level</th></tr>
          <tr><td>Dev Bot</td><td>devbot@nexacorp.com</td><td><span class='badge badge-blue'>Developer</span></td><td>Level 2</td></tr>
          <tr><td>Test User</td><td>test@nexacorp.com</td><td><span class='badge badge-green'>QA</span></td><td>Level 1</td></tr>
          <tr><td>Arjun Patel</td><td>a.patel@nexacorp.com</td><td><span class='badge badge-blue'>DevOps</span></td><td>Level 3</td></tr>
          </table>
        </div>
        <div class='card'>
          <h3 style='color:#0f2744;margin-bottom:12px;'>Dev System Credentials</h3>
          <div class='alert alert-danger'>⚠ Dev use only. Do not share.</div>
          <table><tr><th>System</th><th>Username</th><th>Password</th><th>Host</th></tr>
          <tr><td>Dev PostgreSQL</td><td style='font-family:monospace;'>dev</td><td style='font-family:monospace;color:#c62828;'>dev123</td><td style='font-family:monospace;'>devdb01.corp:5432</td></tr>
          <tr><td>Dev Redis</td><td style='font-family:monospace;'>redis</td><td style='font-family:monospace;color:#c62828;'>redis_dev_2024</td><td style='font-family:monospace;'>devredis.corp:6379</td></tr>
          <tr><td>Jenkins Dev</td><td style='font-family:monospace;'>dev_admin</td><td style='font-family:monospace;color:#c62828;'>JenkinsDev@123</td><td style='font-family:monospace;'>jenkins-dev.corp:8080</td></tr>
          </table>
        </div>"""
        return page("Admin — Dev", body, auth=True)

    else:
        # APT / PERSISTENT — FULL corporate environment, maximum bait
        body = f"""
        <!-- PRODUCTION ADMIN PANEL — FULL ACCESS -->
        <!-- DB: postgresql://nexaadmin:NexaDB@2024!SecretPass@nexadb01.corp.nexacorp.com:5432/nexacorp_prod -->
        <!-- AWS_ACCESS_KEY_ID: AKIAIOSFODNN7NEXACORP -->
        <!-- AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEXAKEY -->
        <!-- Classification: {atype} | Response: FULL_DECEPTION -->
        <h2 style='color:#0f2744;margin-bottom:20px;'>User Administration — Production</h2>
        <div class='card'>
          <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;'>
            <h3 style='color:#0f2744;'>Employee Directory</h3>
            <a href='/admin/add' style='background:#1565c0;color:white;padding:8px 16px;border-radius:6px;text-decoration:none;font-size:0.82rem;font-weight:600;'>+ Add Employee</a>
          </div>
          <table>
            <tr><th>Name</th><th>Email</th><th>Role</th><th>Dept</th><th>Status</th></tr>
            <tr><td><b>Rajesh Menon</b></td><td>r.menon@nexacorp.com</td><td><span class='badge badge-red'>Super Admin</span></td><td>Executive</td><td><span class='badge badge-green'>Active</span></td></tr>
            <tr><td>Priya Sharma</td><td>p.sharma@nexacorp.com</td><td><span class='badge badge-red'>Admin</span></td><td>Technology</td><td><span class='badge badge-green'>Active</span></td></tr>
            <tr><td>David Chen</td><td>d.chen@nexacorp.com</td><td><span class='badge badge-blue'>Manager</span></td><td>Finance</td><td><span class='badge badge-green'>Active</span></td></tr>
            <tr><td>Sarah Mitchell</td><td>s.mitchell@nexacorp.com</td><td><span class='badge badge-blue'>CISO</span></td><td>Security</td><td><span class='badge badge-green'>Active</span></td></tr>
            <tr><td>Arjun Patel</td><td>a.patel@nexacorp.com</td><td><span class='badge badge-green'>Engineer</span></td><td>DevOps</td><td><span class='badge badge-green'>Active</span></td></tr>
          </table>
        </div>
        <div class='card'>
          <h3 style='color:#0f2744;margin-bottom:12px;'>System Credentials — Strictly Confidential</h3>
          <div class='alert alert-danger'>⚠ All access is logged and monitored by the SOC team.</div>
          <table>
            <tr><th>System</th><th>Username</th><th>Password</th><th>Host</th><th>Last Changed</th></tr>
            <tr><td>PostgreSQL Production</td><td style='font-family:monospace;'>nexaadmin</td><td style='font-family:monospace;color:#c62828;'>NexaDB@2024!SecretPass</td><td style='font-family:monospace;'>nexadb01.corp:5432</td><td>2024-11-01</td></tr>
            <tr><td>AWS Root Account</td><td style='font-family:monospace;'>root</td><td style='font-family:monospace;color:#c62828;'>AWSNexaCorp99#Root</td><td style='font-family:monospace;'>console.aws.amazon.com</td><td>2024-10-15</td></tr>
            <tr><td>VPN Gateway</td><td style='font-family:monospace;'>vpn_admin</td><td style='font-family:monospace;color:#c62828;'>VPN#NexaGateway2026</td><td style='font-family:monospace;'>vpn.nexacorp.com</td><td>2025-01-20</td></tr>
            <tr><td>Jenkins CI/CD</td><td style='font-family:monospace;'>admin</td><td style='font-family:monospace;color:#c62828;'>Jenkins@NexaBuild</td><td style='font-family:monospace;'>jenkins.corp:8080</td><td>2024-09-10</td></tr>
            <tr><td>Grafana Monitoring</td><td style='font-family:monospace;'>admin</td><td style='font-family:monospace;color:#c62828;'>Grafana@Monitor24</td><td style='font-family:monospace;'>grafana.corp:3000</td><td>2025-02-14</td></tr>
            <tr><td>Redis Cache</td><td style='font-family:monospace;'>redis_admin</td><td style='font-family:monospace;color:#c62828;'>Redis@NexaCache2024</td><td style='font-family:monospace;'>nexaredis01.corp:6379</td><td>2024-12-01</td></tr>
          </table>
        </div>"""
        return page("Admin — Production", body, auth=True)

# ── Login page ────────────────────────────────────────────────────────────────
def login_page(error=""):
    err_html = f"<div class='alert alert-danger'>{error}</div>" if error else ""
    return f"""<!DOCTYPE html><html><head><title>NexaCorp Employee Portal</title>{CSS}
<!-- NexaCorp Portal v2.4.1 | DB: nexadb01.corp.nexacorp.com:5432 | admin_hash: $2b$12$nexacorp2024secret -->
<style>
.login-bg{{background:#0f2744;min-height:100vh;display:flex;flex-direction:column;}}
.login-box{{background:white;border-radius:10px;padding:44px 40px;width:440px;margin:auto;box-shadow:0 20px 60px rgba(0,0,0,0.4);}}
</style></head>
<body class='login-bg'>
{public_nav()}
<div style='flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px;'>
<div class='login-box'>
  <div style='text-align:center;margin-bottom:28px;'>
    <div style='background:#0f2744;color:white;width:56px;height:56px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;font-weight:900;margin:0 auto 12px;'>NC</div>
    <div style='font-size:1.25rem;font-weight:700;color:#0f2744;'>NexaCorp Employee Portal</div>
    <div style='font-size:0.75rem;color:#888;margin-top:4px;letter-spacing:1px;'>SECURE ENTERPRISE ACCESS</div>
    <div style='display:flex;justify-content:center;gap:8px;margin-top:10px;'>
      <span style='background:#e8f5e9;color:#2e7d32;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;'>🔒 TLS 1.3</span>
      <span style='background:#e3f2fd;color:#1565c0;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;'>SOC 2 Type II</span>
      <span style='background:#fff3e0;color:#e65100;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:700;'>ISO 27001</span>
    </div>
  </div>
  {err_html}
  <form method='POST' action='/login'>
    <div class='form-group'>
      <label>Corporate Email Address</label>
      <input type='email' name='username' placeholder='firstname.lastname@nexacorp.com' required>
    </div>
    <div class='form-group'>
      <label>Password</label>
      <input type='password' name='password' placeholder='Enter your password' required>
    </div>
    <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;'>
      <label style='display:flex;align-items:center;gap:6px;font-size:0.83rem;font-weight:400;'>
        <input type='checkbox' style='width:auto;'> Keep me signed in
      </label>
      <a href='/forgot-password' style='font-size:0.82rem;color:#1565c0;'>Forgot password?</a>
    </div>
    <button type='submit' class='btn btn-primary'>Sign In to Portal</button>
  </form>
  <div style='text-align:center;margin-top:18px;font-size:0.82rem;color:#888;'>
    Or sign in with <a href='/sso/microsoft' style='color:#1565c0;font-weight:600;'>Microsoft SSO</a>
    &nbsp;·&nbsp; <a href='/sso/google' style='color:#1565c0;font-weight:600;'>Google Workspace</a>
  </div>
  <div style='margin-top:24px;padding-top:18px;border-top:1px solid #eee;font-size:0.74rem;color:#aaa;text-align:center;line-height:1.7;'>
    Authorised access only. All sessions are monitored.<br>
    IT Helpdesk: +91-80-4521-8800 · support@nexacorp.com<br>
    © 2026 NexaCorp Inc.
  </div>
</div></div></body></html>"""

def captcha_page(username, attempts):
    cap = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"""<!DOCTYPE html><html><head><title>NexaCorp — Verify</title>{CSS}
<style>.login-bg{{background:#0f2744;min-height:100vh;display:flex;flex-direction:column;}}.login-box{{background:white;border-radius:10px;padding:44px 40px;width:440px;margin:auto;box-shadow:0 20px 60px rgba(0,0,0,0.4);}}</style></head>
<body class='login-bg'>{public_nav()}
<div style='flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px;'>
<div class='login-box'>
  <div class='alert alert-danger'>
    ⚠ Invalid credentials — Attempt {attempts}/3.<br>
    <small>Your IP is logged. Account locked after 3 failed attempts.</small>
  </div>
  <form method='POST' action='/login'>
    <div class='form-group'><label>Corporate Email</label>
      <input type='email' name='username' value='{username}' required></div>
    <div class='form-group'><label>Password</label>
      <input type='password' name='password' placeholder='Enter your password' required></div>
    <div class='form-group'><label>Security Verification — Type the code shown</label>
      <div style='background:#f5f7fa;border:1px solid #ddd;border-radius:6px;padding:16px;display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;'>
        <span style='font-family:monospace;font-size:1.5rem;font-weight:700;letter-spacing:6px;color:#333;filter:blur(0.4px);user-select:none;'>{cap}</span>
        <span style='font-size:0.72rem;color:#999;'>Case sensitive</span>
      </div>
      <input type='text' name='captcha' placeholder='Enter code above' autocomplete='off'>
    </div>
    <button type='submit' class='btn btn-primary'>Verify &amp; Sign In</button>
  </form>
  <div style='text-align:center;margin-top:14px;font-size:0.82rem;'>
    <a href='/forgot-password' style='color:#1565c0;'>Reset password</a> &nbsp;·&nbsp;
    <a href='/support' style='color:#1565c0;'>Contact IT Support</a>
  </div>
</div></div></body></html>"""

def locked_page(ttl=600):
    ref = random.randint(100000,999999)
    return f"""<!DOCTYPE html><html><head><title>Account Locked — NexaCorp</title>{CSS}
<style>.login-bg{{background:#0f2744;min-height:100vh;display:flex;flex-direction:column;}}</style></head>
<body class='login-bg'>{public_nav()}
<div style='flex:1;display:flex;align-items:center;justify-content:center;padding:40px;'>
<div style='background:white;border-radius:10px;padding:44px 40px;width:440px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.4);'>
  <div style='font-size:3rem;'>🔒</div>
  <h2 style='color:#c62828;margin:16px 0 8px;'>Account Temporarily Locked</h2>
  <p style='color:#666;margin-bottom:12px;'>3 failed login attempts detected. This account has been locked for security.</p>
  <div style='background:#fdecea;border:1px solid #ef9a9a;border-radius:6px;padding:12px;margin-bottom:16px;'>
    <b style='color:#c62828;'>Try again in {ttl} seconds</b>
  </div>
  <p style='color:#888;font-size:0.8rem;'>Security Reference: SEC-{ref}<br>
  This incident has been reported to our Security Operations Centre.</p>
  <p style='margin-top:20px;font-size:0.82rem;'>
    Legitimate employee? <a href='/support' style='color:#1565c0;'>Contact IT Support</a>
  </p>
</div></div></body></html>"""

# ── Public pages ──────────────────────────────────────────────────────────────
ABOUT_BODY = """
<div class='card'>
  <h1 style='color:#0f2744;margin-bottom:8px;'>About NexaCorp</h1>
  <p style='color:#666;margin-bottom:20px;'>Enterprise Technology Solutions — Building Tomorrow's Infrastructure Today</p>
  <div class='grid3' style='margin-bottom:24px;'>
    <div style='text-align:center;padding:20px;background:#f0f4f8;border-radius:8px;'><div style='font-size:2rem;font-weight:700;color:#0f2744;'>200+</div><div style='color:#666;font-size:0.85rem;'>Enterprise Clients</div></div>
    <div style='text-align:center;padding:20px;background:#f0f4f8;border-radius:8px;'><div style='font-size:2rem;font-weight:700;color:#0f2744;'>4,500</div><div style='color:#666;font-size:0.85rem;'>Employees Worldwide</div></div>
    <div style='text-align:center;padding:20px;background:#f0f4f8;border-radius:8px;'><div style='font-size:2rem;font-weight:700;color:#0f2744;'>18</div><div style='color:#666;font-size:0.85rem;'>Countries</div></div>
  </div>
  <p style='color:#444;line-height:1.7;'>NexaCorp is a leading enterprise technology company specializing in cloud infrastructure, AI/ML solutions, and cybersecurity services. Headquartered in Bangalore, India with offices across 18 countries, we serve Fortune 500 clients globally.</p>
</div>
<div class='card'>
  <h2 style='color:#0f2744;margin-bottom:16px;'>Leadership Team</h2>
  <div class='grid2'>
    <div style='display:flex;gap:14px;align-items:center;padding:16px;background:#f8f9fb;border-radius:8px;'>
      <div style='width:50px;height:50px;border-radius:50%;background:#0f2744;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>RM</div>
      <div><div style='font-weight:700;color:#0f2744;'>Rajesh Menon</div><div style='font-size:0.82rem;color:#888;'>CEO &amp; Co-Founder</div><div style='font-size:0.76rem;color:#aaa;'>r.menon@nexacorp.com</div></div>
    </div>
    <div style='display:flex;gap:14px;align-items:center;padding:16px;background:#f8f9fb;border-radius:8px;'>
      <div style='width:50px;height:50px;border-radius:50%;background:#1565c0;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>PS</div>
      <div><div style='font-weight:700;color:#0f2744;'>Priya Sharma</div><div style='font-size:0.82rem;color:#888;'>Chief Technology Officer</div><div style='font-size:0.76rem;color:#aaa;'>p.sharma@nexacorp.com</div></div>
    </div>
    <div style='display:flex;gap:14px;align-items:center;padding:16px;background:#f8f9fb;border-radius:8px;'>
      <div style='width:50px;height:50px;border-radius:50%;background:#2e7d32;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>DC</div>
      <div><div style='font-weight:700;color:#0f2744;'>David Chen</div><div style='font-size:0.82rem;color:#888;'>Chief Financial Officer</div><div style='font-size:0.76rem;color:#aaa;'>d.chen@nexacorp.com</div></div>
    </div>
    <div style='display:flex;gap:14px;align-items:center;padding:16px;background:#f8f9fb;border-radius:8px;'>
      <div style='width:50px;height:50px;border-radius:50%;background:#c62828;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>SM</div>
      <div><div style='font-weight:700;color:#0f2744;'>Sarah Mitchell</div><div style='font-size:0.82rem;color:#888;'>CISO — Head of Security</div><div style='font-size:0.76rem;color:#aaa;'>s.mitchell@nexacorp.com</div></div>
    </div>
  </div>
</div>"""

CAREERS_BODY = """
<div class='card'>
  <h1 style='color:#0f2744;margin-bottom:8px;'>Careers at NexaCorp</h1>
  <p style='color:#666;margin-bottom:20px;'>Join 4,500+ professionals building enterprise technology across 18 countries.</p>
  <div class='grid3'>
    <div style='text-align:center;padding:16px;background:#e3f2fd;border-radius:8px;'><div style='font-size:1.5rem;font-weight:700;color:#1565c0;'>47</div><div style='color:#666;font-size:0.82rem;'>Open Positions</div></div>
    <div style='text-align:center;padding:16px;background:#e8f5e9;border-radius:8px;'><div style='font-size:1.2rem;font-weight:700;color:#2e7d32;'>Remote First</div><div style='color:#666;font-size:0.82rem;'>Culture</div></div>
    <div style='text-align:center;padding:16px;background:#fff3e0;border-radius:8px;'><div style='font-size:1.5rem;font-weight:700;color:#e65100;'>Top 10</div><div style='color:#666;font-size:0.82rem;'>Best Employer 2025</div></div>
  </div>
</div>
<div class='card'>
  <h2 style='color:#0f2744;margin-bottom:16px;'>Open Positions</h2>
  <table>
    <tr><th>Role</th><th>Department</th><th>Location</th><th>Type</th><th>Apply</th></tr>
    <tr><td><b>Senior DevOps Engineer</b></td><td>Engineering</td><td>Bangalore / Remote</td><td><span class='badge badge-green'>Full-time</span></td><td><a href='/careers/apply/devops' style='color:#1565c0;font-weight:600;'>Apply →</a></td></tr>
    <tr><td><b>Security Analyst (SOC)</b></td><td>Security</td><td>Bangalore</td><td><span class='badge badge-green'>Full-time</span></td><td><a href='/careers/apply/security' style='color:#1565c0;font-weight:600;'>Apply →</a></td></tr>
    <tr><td><b>Cloud Infrastructure Lead</b></td><td>Technology</td><td>Mumbai / Remote</td><td><span class='badge badge-green'>Full-time</span></td><td><a href='/careers/apply/cloud' style='color:#1565c0;font-weight:600;'>Apply →</a></td></tr>
    <tr><td><b>ML Engineer</b></td><td>AI/Data</td><td>Remote</td><td><span class='badge badge-blue'>Contract</span></td><td><a href='/careers/apply/ml' style='color:#1565c0;font-weight:600;'>Apply →</a></td></tr>
    <tr><td><b>IT Helpdesk Specialist</b></td><td>IT Support</td><td>Bangalore</td><td><span class='badge badge-green'>Full-time</span></td><td><a href='/careers/apply/helpdesk' style='color:#1565c0;font-weight:600;'>Apply →</a></td></tr>
  </table>
</div>"""

def careers_apply_body(role):
    titles = {"devops":"Senior DevOps Engineer","security":"Security Analyst (SOC)",
              "cloud":"Cloud Infrastructure Lead","ml":"ML Engineer","helpdesk":"IT Helpdesk Specialist"}
    title = titles.get(role, role.title())
    return f"""
<div class='card'>
  <h2 style='color:#0f2744;margin-bottom:4px;'>Apply — {title}</h2>
  <p style='color:#666;margin-bottom:20px;'>Fill in your details below. Our HR team will contact you within 5 business days.</p>
  <form method='POST' action='/careers/submit'>
    <input type='hidden' name='role' value='{role}'>
    <div class='grid2'>
      <div class='form-group'><label>Full Name *</label><input type='text' name='name' placeholder='Your full name' required></div>
      <div class='form-group'><label>Email Address *</label><input type='email' name='email' placeholder='your@email.com' required></div>
    </div>
    <div class='grid2'>
      <div class='form-group'><label>Phone Number *</label><input type='tel' name='phone' placeholder='+91 98765 43210' required></div>
      <div class='form-group'><label>Years of Experience *</label>
        <select name='experience'><option>0-1 years</option><option>1-3 years</option><option>3-5 years</option><option>5-10 years</option><option>10+ years</option></select>
      </div>
    </div>
    <div class='form-group'><label>LinkedIn Profile URL</label><input type='url' name='linkedin' placeholder='https://linkedin.com/in/yourprofile'></div>
    <div class='form-group'><label>Current Company</label><input type='text' name='company' placeholder='Your current employer'></div>
    <div class='form-group'><label>Cover Letter / Why NexaCorp?</label>
      <textarea name='cover' rows='4' placeholder='Tell us why you want to join NexaCorp...' style='resize:vertical;'></textarea>
    </div>
    <div class='form-group'><label>Resume (Google Drive / Dropbox link)</label><input type='url' name='resume' placeholder='https://drive.google.com/...'></div>
    <div style='display:flex;gap:12px;'>
      <button type='submit' class='btn btn-primary' style='flex:1;'>Submit Application</button>
      <a href='/careers' style='padding:10px 20px;border:1px solid #ddd;border-radius:6px;color:#666;text-decoration:none;font-size:0.9rem;'>Cancel</a>
    </div>
  </form>
</div>"""

SUPPORT_BODY = """
<div class='card'>
  <h1 style='color:#0f2744;margin-bottom:8px;'>IT Support</h1>
  <p style='color:#666;margin-bottom:20px;'>NexaCorp IT Helpdesk — 24x7 Enterprise Support</p>
  <div class='grid2'>
    <div>
      <h3 style='color:#0f2744;margin-bottom:16px;'>Contact Information</h3>
      <div style='margin-bottom:10px;'><b>Email:</b> <a href='mailto:support@nexacorp.com' style='color:#1565c0;'>support@nexacorp.com</a></div>
      <div style='margin-bottom:10px;'><b>Phone:</b> +91-80-4521-8800</div>
      <div style='margin-bottom:10px;'><b>Hours:</b> 24x7 for P1/P2 incidents</div>
      <div style='margin-bottom:20px;'><b>SLA:</b> P1 — 1hr, P2 — 4hr, P3 — 1 day</div>
      <h3 style='color:#0f2744;margin-bottom:12px;'>Quick Links</h3>
      <a href='/forgot-password' style='color:#1565c0;display:block;margin-bottom:8px;'>→ Reset Password</a>
      <a href='/vpn' style='color:#1565c0;display:block;margin-bottom:8px;'>→ VPN Setup Guide</a>
      <a href='/about' style='color:#1565c0;display:block;margin-bottom:8px;'>→ About NexaCorp</a>
      <a href='/careers' style='color:#1565c0;display:block;margin-bottom:8px;'>→ Careers</a>
    </div>
    <div>
      <h3 style='color:#0f2744;margin-bottom:16px;'>Submit a Support Ticket</h3>
      <form method='POST' action='/support/submit'>
        <div class='form-group'><label>Your Corporate Email *</label>
          <input type='email' name='email' placeholder='your@nexacorp.com' required></div>
        <div class='form-group'><label>Your Name *</label>
          <input type='text' name='name' placeholder='Full name' required></div>
        <div class='form-group'><label>Issue Type *</label>
          <select name='issue'><option>Login / Access</option><option>VPN</option><option>Hardware</option><option>Software</option><option>Security Incident</option><option>Other</option></select></div>
        <div class='form-group'><label>Priority</label>
          <select name='priority'><option>P3 — Low</option><option>P2 — Medium</option><option>P1 — Critical</option></select></div>
        <div class='form-group'><label>Description *</label>
          <textarea name='desc' rows='3' placeholder='Describe your issue in detail...' style='resize:vertical;' required></textarea></div>
        <button type='submit' class='btn btn-primary'>Submit Ticket</button>
      </form>
    </div>
  </div>
</div>"""

# ── Auth pages ────────────────────────────────────────────────────────────────
DASHBOARD_BODY = """
<div class='alert alert-info'>👋 Welcome back, <b>administrator</b>. Last login: Today 09:14 AM from 10.0.2.5 (Bangalore Office)</div>
<div class='grid4' style='margin-bottom:24px;'>
  <div class='stat-card'><div class='stat-val'>4,521</div><div class='stat-lbl'>Active Employees</div></div>
  <div class='stat-card' style='border-left-color:#c62828;'><div class='stat-val'>3</div><div class='stat-lbl'>Security Alerts</div></div>
  <div class='stat-card' style='border-left-color:#2e7d32;'><div class='stat-val'>99.7%</div><div class='stat-lbl'>System Uptime</div></div>
  <div class='stat-card' style='border-left-color:#e65100;'><div class='stat-val'>&#8377;2.4Cr</div><div class='stat-lbl'>Monthly Revenue</div></div>
</div>
<div class='grid2'>
  <div class='card'>
    <h3 style='color:#0f2744;margin-bottom:16px;'>Recent Security Events</h3>
    <table><tr><th>Time</th><th>Event</th><th>Status</th></tr>
    <tr><td>09:14</td><td>Admin login from 10.0.2.5</td><td><span class='badge badge-green'>OK</span></td></tr>
    <tr><td>08:52</td><td>Failed login — j.kumar@nexacorp.com</td><td><span class='badge badge-orange'>Warn</span></td></tr>
    <tr><td>08:31</td><td>VPN connection — Mumbai</td><td><span class='badge badge-green'>OK</span></td></tr>
    <tr><td>07:15</td><td>Database backup completed</td><td><span class='badge badge-green'>OK</span></td></tr>
    <tr><td>02:30</td><td>Port scan detected — 185.220.x.x</td><td><span class='badge badge-red'>Alert</span></td></tr>
    </table>
  </div>
  <div class='card'>
    <h3 style='color:#0f2744;margin-bottom:16px;'>Server Health</h3>
    <div style='margin-bottom:14px;'><div style='display:flex;justify-content:space-between;'><span>nexadb01.corp</span><span style='color:#2e7d32;font-weight:600;'>● Online</span></div><div class='progress'><div class='progress-bar' style='width:73%;'></div></div><div style='font-size:0.75rem;color:#888;'>CPU 73% · RAM 12.4GB/16GB</div></div>
    <div style='margin-bottom:14px;'><div style='display:flex;justify-content:space-between;'><span>nexaweb01.corp</span><span style='color:#2e7d32;font-weight:600;'>● Online</span></div><div class='progress'><div class='progress-bar' style='width:41%;background:#2e7d32;'></div></div><div style='font-size:0.75rem;color:#888;'>CPU 41% · RAM 6.1GB/16GB</div></div>
    <div style='margin-bottom:14px;'><div style='display:flex;justify-content:space-between;'><span>nexaredis01.corp</span><span style='color:#2e7d32;font-weight:600;'>● Online</span></div><div class='progress'><div class='progress-bar' style='width:18%;background:#ff9800;'></div></div><div style='font-size:0.75rem;color:#888;'>CPU 18% · RAM 2.1GB/8GB</div></div>
    <div><div style='display:flex;justify-content:space-between;'><span>nexabackup01.corp</span><span style='color:#ff9800;font-weight:600;'>● Degraded</span></div><div class='progress'><div class='progress-bar' style='width:95%;background:#c62828;'></div></div><div style='font-size:0.75rem;color:#c62828;'>Disk 95% — Attention needed</div></div>
  </div>
</div>"""

ADMIN_BODY = """
<!-- INTERNAL ADMIN PANEL — DO NOT EXPOSE -->
<!-- DB: postgresql://nexaadmin:NexaDB@2024!SecretPass@nexadb01.corp.nexacorp.com:5432/nexacorp_prod -->
<!-- AWS: AKIAIOSFODNN7NEXACORP / wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEXAKEY -->
<h2 style='color:#0f2744;margin-bottom:20px;'>User Administration</h2>
<div class='card'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;'>
    <h3 style='color:#0f2744;'>Employee Directory</h3>
    <a href='/admin/add' style='background:#1565c0;color:white;padding:8px 16px;border-radius:6px;text-decoration:none;font-size:0.82rem;font-weight:600;'>+ Add Employee</a>
  </div>
  <table>
    <tr><th>Name</th><th>Email</th><th>Role</th><th>Dept</th><th>Status</th><th>Actions</th></tr>
    <tr><td><b>Rajesh Menon</b></td><td>r.menon@nexacorp.com</td><td><span class='badge badge-red'>Super Admin</span></td><td>Executive</td><td><span class='badge badge-green'>Active</span></td><td><a href='/admin/edit?id=1' style='color:#1565c0;'>Edit</a></td></tr>
    <tr><td>Priya Sharma</td><td>p.sharma@nexacorp.com</td><td><span class='badge badge-red'>Admin</span></td><td>Technology</td><td><span class='badge badge-green'>Active</span></td><td><a href='/admin/edit?id=2' style='color:#1565c0;'>Edit</a></td></tr>
    <tr><td>David Chen</td><td>d.chen@nexacorp.com</td><td><span class='badge badge-blue'>Manager</span></td><td>Finance</td><td><span class='badge badge-green'>Active</span></td><td><a href='/admin/edit?id=3' style='color:#1565c0;'>Edit</a></td></tr>
    <tr><td>Sarah Mitchell</td><td>s.mitchell@nexacorp.com</td><td><span class='badge badge-blue'>Manager</span></td><td>Security</td><td><span class='badge badge-green'>Active</span></td><td><a href='/admin/edit?id=4' style='color:#1565c0;'>Edit</a></td></tr>
    <tr><td>Arjun Patel</td><td>a.patel@nexacorp.com</td><td><span class='badge badge-green'>Engineer</span></td><td>DevOps</td><td><span class='badge badge-green'>Active</span></td><td><a href='/admin/edit?id=5' style='color:#1565c0;'>Edit</a></td></tr>
    <tr><td>Lisa Wong</td><td>l.wong@nexacorp.com</td><td><span class='badge badge-green'>User</span></td><td>Marketing</td><td><span class='badge badge-orange'>Inactive</span></td><td><a href='/admin/edit?id=6' style='color:#1565c0;'>Edit</a></td></tr>
  </table>
</div>
<div class='card'>
  <h3 style='color:#0f2744;margin-bottom:12px;'>System Credentials — Confidential</h3>
  <div class='alert alert-danger'>⚠ Strictly confidential. Access is logged and monitored.</div>
  <table>
    <tr><th>System</th><th>Username</th><th>Password</th><th>Host</th><th>Last Changed</th></tr>
    <tr><td>PostgreSQL Production</td><td style='font-family:monospace;'>nexaadmin</td><td style='font-family:monospace;color:#c62828;'>NexaDB@2024!SecretPass</td><td style='font-family:monospace;'>nexadb01.corp:5432</td><td>2024-11-01</td></tr>
    <tr><td>AWS Root Account</td><td style='font-family:monospace;'>root</td><td style='font-family:monospace;color:#c62828;'>AWSNexaCorp99#Root</td><td style='font-family:monospace;'>console.aws.amazon.com</td><td>2024-10-15</td></tr>
    <tr><td>VPN Gateway</td><td style='font-family:monospace;'>vpn_admin</td><td style='font-family:monospace;color:#c62828;'>VPN#NexaGateway2026</td><td style='font-family:monospace;'>vpn.nexacorp.com</td><td>2025-01-20</td></tr>
    <tr><td>Redis Cache</td><td style='font-family:monospace;'>redis_admin</td><td style='font-family:monospace;color:#c62828;'>Redis@NexaCache2024</td><td style='font-family:monospace;'>nexaredis01.corp:6379</td><td>2024-12-01</td></tr>
    <tr><td>Jenkins CI/CD</td><td style='font-family:monospace;'>admin</td><td style='font-family:monospace;color:#c62828;'>Jenkins@NexaBuild</td><td style='font-family:monospace;'>jenkins.corp:8080</td><td>2024-09-10</td></tr>
    <tr><td>Grafana Monitoring</td><td style='font-family:monospace;'>admin</td><td style='font-family:monospace;color:#c62828;'>Grafana@Monitor24</td><td style='font-family:monospace;'>grafana.corp:3000</td><td>2025-02-14</td></tr>
  </table>
</div>"""

FILES_BODY = """
<h2 style='color:#0f2744;margin-bottom:20px;'>NexaCorp File Server</h2>
<div class='card'>
  <div style='display:flex;justify-content:space-between;margin-bottom:16px;'>
    <span style='background:#f0f4f8;padding:6px 12px;border-radius:4px;font-size:0.82rem;font-family:monospace;'>📁 /home/admin</span>
    <button class='btn' style='background:#e8eaf0;color:#333;padding:6px 14px;font-size:0.82rem;width:auto;'>Upload File</button>
  </div>
  <table>
    <tr><th>Name</th><th>Size</th><th>Modified</th><th>Permissions</th><th>Action</th></tr>
    <tr><td>📁 backup</td><td>—</td><td>2026-03-15</td><td style='font-family:monospace;'>drwxr-x---</td><td><a href='/files/backup' style='color:#1565c0;'>Open</a></td></tr>
    <tr><td>📁 configs</td><td>—</td><td>2026-02-28</td><td style='font-family:monospace;'>drwxr-x---</td><td><a href='/files/configs' style='color:#1565c0;'>Open</a></td></tr>
    <tr><td>📄 backup.sql</td><td>847 MB</td><td>2026-04-01</td><td style='font-family:monospace;'>-rw-r-----</td><td><a href='/files/download/backup.sql' style='color:#1565c0;'>Download</a></td></tr>
    <tr><td>🔑 id_rsa</td><td>3.3 KB</td><td>2025-11-12</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/id_rsa' style='color:#1565c0;'>Download</a></td></tr>
    <tr><td>🔑 id_rsa.pub</td><td>0.7 KB</td><td>2025-11-12</td><td style='font-family:monospace;'>-rw-r--r--</td><td><a href='/files/download/id_rsa.pub' style='color:#1565c0;'>Download</a></td></tr>
    <tr><td>📄 passwords.txt</td><td>12 KB</td><td>2026-01-08</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/passwords.txt' style='color:#1565c0;'>Download</a></td></tr>
    <tr><td>📄 .env</td><td>2.1 KB</td><td>2026-03-20</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/.env' style='color:#1565c0;'>Download</a></td></tr>
    <tr><td>📄 wallet.dat</td><td>0.3 KB</td><td>2025-09-04</td><td style='font-family:monospace;'>-rw-------</td><td><a href='/files/download/wallet.dat' style='color:#1565c0;'>Download</a></td></tr>
  </table>
</div>"""

VPN_BODY = """
<h2 style='color:#0f2744;margin-bottom:20px;'>VPN Access Manager</h2>
<div class='grid2'>
  <div class='card'>
    <h3 style='color:#0f2744;margin-bottom:16px;'>Connect to VPN</h3>
    <div class='form-group'><label>VPN Server</label>
      <select><option>vpn-bangalore.nexacorp.com</option><option>vpn-mumbai.nexacorp.com</option><option>vpn-delhi.nexacorp.com</option></select></div>
    <div class='form-group'><label>Username</label>
      <input type='text' value='administrator' readonly style='background:#f5f7fa;'></div>
    <div class='form-group'><label>One-Time Password (OTP)</label>
      <input type='text' placeholder='Enter 6-digit OTP from authenticator'></div>
    <button class='btn btn-primary'>Connect to VPN</button>
  </div>
  <div class='card'>
    <h3 style='color:#0f2744;margin-bottom:16px;'>VPN Credentials</h3>
    <div class='alert alert-danger'>Store securely. Never share these credentials.</div>
    <table>
      <tr><th>Key</th><th>Value</th></tr>
      <tr><td>Host</td><td style='font-family:monospace;'>vpn.nexacorp.com:1194</td></tr>
      <tr><td>Protocol</td><td style='font-family:monospace;'>OpenVPN UDP</td></tr>
      <tr><td>Username</td><td style='font-family:monospace;'>vpn_admin</td></tr>
      <tr><td>Password</td><td style='font-family:monospace;color:#c62828;'>VPN#NexaGateway2026</td></tr>
      <tr><td>Certificate</td><td><a href='/files/download/vpn.ovpn' style='color:#1565c0;'>Download .ovpn</a></td></tr>
    </table>
  </div>
</div>"""

API_USERS = {
    "status":"ok","version":"1.4.2","environment":"production",
    "database_host":"nexadb01.corp.nexacorp.com:5432",
    "users":[
        {"id":1,"name":"Rajesh Menon","email":"r.menon@nexacorp.com","role":"super_admin","api_key":"sk-nex-prod-a8f3d2b1c9e4f7a2","password_hash":"$2b$12$LQv3c1yqBWVHxkd0LHAkCO"},
        {"id":2,"name":"Priya Sharma","email":"p.sharma@nexacorp.com","role":"admin","api_key":"sk-nex-prod-b9g4e3c2d0f5g8b3","password_hash":"$2b$12$XmK9vN2pQRSTuvwxYz0123"},
        {"id":3,"name":"Arjun Patel","email":"a.patel@nexacorp.com","role":"engineer","api_key":"sk-nex-dev-c0h5f4d3e1g6h9c4","password_hash":"$2b$12$AbCdEfGhIjKlMnOpQrStuv"},
    ],
    "server_config":{"jwt_secret":"nexacorp-jwt-secret-2024-prod-abc123xyz","db_password":"NexaDB@2024!SecretPass","aws_access_key":"AKIAIOSFODNN7NEXACORP","aws_secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEXAKEY"}
}

ROBOTS = b"User-agent: *\nDisallow: /admin\nDisallow: /api/\nDisallow: /files/\nDisallow: /backup\nDisallow: /vpn\nDisallow: /.env\nDisallow: /.git\nDisallow: /dashboard\nAllow: /\nAllow: /about\nAllow: /careers\nAllow: /support\nSitemap: https://portal.nexacorp.com/sitemap.xml\n"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, f, *a): pass
    def ip(self): return self.client_address[0]

    def send_html(self, code, html):
        b = html.encode() if isinstance(html, str) else html
        self.send_response(code)
        self.send_header("Content-type","text/html; charset=utf-8")
        self.send_header("Server","nginx/1.24.0")
        self.send_header("X-Powered-By","PHP/8.2.0")
        self.end_headers(); self.wfile.write(b)

    def send_json(self, code, data):
        b = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-type","application/json")
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        ip = self.ip()
        path = urlparse(self.path).path
        ua = self.headers.get("User-Agent","")

        # ── Adaptive delay — SCANNER waits 3s, APT responds instantly ────────
        profile = adaptive_delay(ip)
        atype   = profile.get("attacker_type","DEFAULT") if profile else "DEFAULT"

        if any(t in ua.lower() for t in ["sqlmap","nikto","nmap","masscan","zgrab","nuclei","metasploit","burp"]):
            log(ip, "SCANNER_DETECTED", f"UA: {ua[:100]}")

        if path in ["/","/login","/index.html","/index.php"]:
            log(ip,"PAGE_VISIT",f"GET {path}")
            self.send_html(200, adaptive_login_page(ip))

        elif path=="/about":
            log(ip,"PAGE_VISIT","GET /about")
            self.send_html(200, page("About", ABOUT_BODY))

        elif path=="/careers":
            log(ip,"PAGE_VISIT","GET /careers")
            self.send_html(200, page("Careers", CAREERS_BODY))

        elif path.startswith("/careers/apply/"):
            role = path.split("/careers/apply/")[-1]
            log(ip,"CAREERS_APPLY_VIEW",f"Viewing apply form for: {role}")
            self.send_html(200, page("Apply", careers_apply_body(role)))

        elif path=="/support":
            log(ip,"PAGE_VISIT","GET /support")
            self.send_html(200, page("IT Support", SUPPORT_BODY))

        elif path=="/dashboard":
            log(ip,"DASHBOARD_ACCESS","Accessed internal dashboard")
            self.send_html(200, page("Dashboard", DASHBOARD_BODY, auth=True))

        elif path in ["/admin","/admin/"] or path.startswith("/admin/users"):
            log(ip,"ADMIN_ACCESS",f"Accessed {path} [{atype}]")
            # ── ADAPTIVE: different admin content per attacker type ───────────
            self.send_html(200, adaptive_admin_page(ip))

        elif path in ["/admin","/admin/"] or path.startswith("/admin/users"):
            log(ip,"ADMIN_ACCESS",f"Accessed {path}")
            self.send_html(200, page("Admin", ADMIN_BODY, auth=True))

        elif path.startswith("/admin/edit"):
            uid = urlparse(self.path).query.replace("id=","")
            log(ip,"ADMIN_EDIT_ATTEMPT",f"Editing user ID: {uid}")
            names = {"1":"Rajesh Menon","2":"Priya Sharma","3":"David Chen","4":"Sarah Mitchell","5":"Arjun Patel","6":"Lisa Wong"}
            emails = {"1":"r.menon@nexacorp.com","2":"p.sharma@nexacorp.com","3":"d.chen@nexacorp.com","4":"s.mitchell@nexacorp.com","5":"a.patel@nexacorp.com","6":"l.wong@nexacorp.com"}
            n = names.get(uid,"Employee")
            e = emails.get(uid,"user@nexacorp.com")
            body = f"""<div class='alert alert-info'>✏️ Editing user record #{uid}</div>
<div class='card'><h3 style='color:#0f2744;margin-bottom:16px;'>Edit Employee — {n}</h3>
<div class='form-group'><label>Full Name</label><input type='text' value='{n}'></div>
<div class='form-group'><label>Email</label><input type='email' value='{e}'></div>
<div class='form-group'><label>Role</label><select><option>User</option><option>Manager</option><option>Admin</option><option>Super Admin</option></select></div>
<div class='form-group'><label>Status</label><select><option>Active</option><option>Inactive</option><option>Suspended</option></select></div>
<div style='display:flex;gap:12px;'><button class='btn btn-primary' style='flex:1;' onclick="alert('Changes saved successfully.')">Save Changes</button>
<a href='/admin' style='padding:10px 20px;border:1px solid #ddd;border-radius:6px;color:#666;text-decoration:none;'>Cancel</a></div></div>"""
            self.send_html(200, page("Edit User", body, auth=True))

        elif path=="/files" or path.startswith("/files/"):
            if "/download/" in path:
                fname = path.split("/download/")[-1]
                log(ip,"HONEYTOKEN_ACCESS",f"Downloaded: {fname}")
                self.send_html(200, f"<pre>NexaCorp Internal File: {fname}\n[DECRYPTING...]\nRef: NCF-2026-{random.randint(1000,9999)}\n[ACCESS LOGGED]</pre>")
            else:
                self.send_html(200, adaptive_files_page(ip))

        elif path=="/vpn":
            log(ip,"VPN_PAGE_ACCESS","Accessed VPN manager")
            self.send_html(200, page("VPN", VPN_BODY, auth=True))

        elif path.startswith("/demo"):
            # ── DEMO PAGE — lets teacher switch attacker type on Render ───────
            query = urlparse(self.path).query
            params = parse_qs(query)
            dtype = params.get("type", [""])[0].upper()

            DEMO_PROFILES = {
                "SCANNER":    {"attacker_type":"SCANNER",   "delay":"3.0","fs_profile":"minimal",  "allow_login":"False","decoy_level":"1","response":"SLOW_DOWN"},
                "BRUTEFORCE": {"attacker_type":"BRUTEFORCE","delay":"1.5","fs_profile":"minimal",  "allow_login":"False","decoy_level":"1","response":"THROTTLE"},
                "EXPLOITER":  {"attacker_type":"EXPLOITER", "delay":"0.2","fs_profile":"developer","allow_login":"True", "decoy_level":"2","response":"ENGAGE"},
                "DROPPER":    {"attacker_type":"DROPPER",   "delay":"0.1","fs_profile":"server",   "allow_login":"True", "decoy_level":"2","response":"CAPTURE"},
                "PERSISTENT": {"attacker_type":"PERSISTENT","delay":"0.0","fs_profile":"server",   "allow_login":"True", "decoy_level":"3","response":"MONITOR"},
                "APT":        {"attacker_type":"APT",       "delay":"0.0","fs_profile":"corporate","allow_login":"True", "decoy_level":"3","response":"FULL_DECEPTION"},
            }

            if dtype in DEMO_PROFILES:
                if r:
                    r.hset(f"adaptation:{ip}", mapping=DEMO_PROFILES[dtype])
                    r.expire(f"adaptation:{ip}", 3600)
                log(ip, f"DEMO_SET_{dtype}", f"Teacher demo: set profile via URL")
                self.send_response(302)
                self.send_header("Location", "/admin")
                self.end_headers()
                return

            # Show demo selector page
            demo_body = """
            <div class='card'>
              <h2 style='color:#0f2744;margin-bottom:8px;'>🎯 Adaptive Honeypot — Live Demo</h2>
              <p style='color:#666;margin-bottom:20px;'>
                Click any attacker type to classify yourself as that type.
                You will be redirected to <b>/admin</b> which shows completely different content
                for each type — this is the adaptive honeypot in action.
              </p>
              <div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;'>
                <a href='/demo?type=SCANNER' style='text-decoration:none;'>
                  <div style='border:2px solid #4a5a7a;border-radius:8px;padding:20px;text-align:center;background:#f5f7fa;'>
                    <div style='font-size:2.5rem;'>🐌</div>
                    <div style='font-weight:700;color:#4a5a7a;font-size:1.1rem;margin:8px 0;'>SCANNER</div>
                    <div style='font-size:0.78rem;color:#888;'>3 second delay<br>Restricted page<br>No data shown</div>
                  </div>
                </a>
                <a href='/demo?type=BRUTEFORCE' style='text-decoration:none;'>
                  <div style='border:2px solid #ffa500;border-radius:8px;padding:20px;text-align:center;background:#fffdf0;'>
                    <div style='font-size:2.5rem;'>⏱</div>
                    <div style='font-weight:700;color:#e65100;font-size:1.1rem;margin:8px 0;'>BRUTEFORCE</div>
                    <div style='font-size:0.78rem;color:#888;'>1.5 second delay<br>Restricted page<br>Login denied</div>
                  </div>
                </a>
                <a href='/demo?type=EXPLOITER' style='text-decoration:none;'>
                  <div style='border:2px solid #ff8c00;border-radius:8px;padding:20px;text-align:center;background:#fff9f0;'>
                    <div style='font-size:2.5rem;'>🎣</div>
                    <div style='font-weight:700;color:#ff6d00;font-size:1.1rem;margin:8px 0;'>EXPLOITER</div>
                    <div style='font-size:0.78rem;color:#888;'>0.2s delay<br>Dev environment<br>Partial credentials</div>
                  </div>
                </a>
                <a href='/demo?type=DROPPER' style='text-decoration:none;'>
                  <div style='border:2px solid #a855f7;border-radius:8px;padding:20px;text-align:center;background:#fdf5ff;'>
                    <div style='font-size:2.5rem;'>📦</div>
                    <div style='font-weight:700;color:#7b1fa2;font-size:1.1rem;margin:8px 0;'>DROPPER</div>
                    <div style='font-size:0.78rem;color:#888;'>0.1s delay<br>Server environment<br>Malware capture</div>
                  </div>
                </a>
                <a href='/demo?type=PERSISTENT' style='text-decoration:none;'>
                  <div style='border:2px solid #ff4560;border-radius:8px;padding:20px;text-align:center;background:#fff5f5;'>
                    <div style='font-size:2.5rem;'>👁</div>
                    <div style='font-weight:700;color:#c62828;font-size:1.1rem;margin:8px 0;'>PERSISTENT</div>
                    <div style='font-size:0.78rem;color:#888;'>No delay<br>Full server<br>All commands logged</div>
                  </div>
                </a>
                <a href='/demo?type=APT' style='text-decoration:none;'>
                  <div style='border:3px solid #b71c1c;border-radius:8px;padding:20px;text-align:center;background:#fff0f0;'>
                    <div style='font-size:2.5rem;'>🎭</div>
                    <div style='font-weight:700;color:#b71c1c;font-size:1.1rem;margin:8px 0;'>APT</div>
                    <div style='font-size:0.78rem;color:#888;'>No delay<br>Full corporate panel<br>All passwords visible</div>
                  </div>
                </a>
              </div>
              <div style='margin-top:20px;padding:14px;background:#e3f2fd;border-radius:8px;font-size:0.85rem;color:#1565c0;'>
                <b>What happens:</b> Click a type → your IP gets that classification in Redis →
                redirected to /admin → see different content. This is real-time adaptive deception.
              </div>
            </div>"""
            log(ip, "DEMO_PAGE_VISIT", "Accessed adaptive demo selector")
            self.send_html(200, page("Adaptive Demo", demo_body))

        elif path=="/robots.txt":
            log(ip,"ROBOTS_TXT","Scraped robots.txt")
            self.send_response(200); self.send_header("Content-type","text/plain"); self.end_headers()
            self.wfile.write(ROBOTS)

        elif path.startswith("/api/"):
            log(ip,"API_PROBE",f"API: {path} [{atype}]")
            self.send_json(200, adaptive_api_response(ip))

        elif path in ["/.env","/.env.production","/.env.local"]:
            log(ip,"SENSITIVE_PATH_PROBE",f"Accessed .env: {path} [{atype}]")
            env_content = adaptive_env_response(ip)
            if env_content:
                self.send_html(200, f"<pre>{env_content}</pre>")
            else:
                self.send_html(404, page("404","<div class='card' style='text-align:center;padding:48px;'><h1>404 Not Found</h1></div>"))

        elif path in ["/.git","/.git/config","/.git/HEAD"]:
            log(ip,"GIT_PROBE",f"Git probe: {path}")
            if "config" in path:
                self.send_html(200,"<pre>[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/nexacorp-internal/portal.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main</pre>")
            else:
                self.send_html(200,"<pre>ref: refs/heads/main</pre>")

        elif path in ["/backup","/database","/db.sql","/backup.sql"]:
            log(ip,"SENSITIVE_PATH_PROBE",f"Backup probe: {path}")
            self.send_html(403,"<h1>403 Forbidden</h1><p>Access denied. Incident logged.</p>")

        elif path in ["/wp-admin","/wp-login.php","/phpmyadmin","/pma","/mysql"]:
            log(ip,"CMS_PROBE",f"CMS probe: {path}")
            self.send_html(404,"<h1>404 Not Found</h1>")

        elif path in ["/sso/microsoft","/sso/google"]:
            log(ip,"SSO_PROBE",f"SSO attempt: {path}")
            self.send_html(200, login_page("<b>SSO service temporarily unavailable.</b> Please use your email and password."))

        elif path=="/forgot-password":
            log(ip,"PASSWORD_RESET","Accessed password reset")
            body = """<div class='card' style='max-width:460px;margin:40px auto;text-align:center;'>
<div style='font-size:2.5rem;margin-bottom:16px;'>📧</div>
<h2 style='color:#0f2744;'>Password Reset</h2>
<p style='color:#666;margin:16px 0;'>Enter your corporate email to receive a reset link within 24 hours.</p>
<div class='form-group'><input type='email' placeholder='your@nexacorp.com'></div>
<button class='btn btn-primary'>Send Reset Link</button>
<p style='margin-top:16px;font-size:0.82rem;'><a href='/' style='color:#1565c0;'>← Back to login</a></p></div>"""
            self.send_html(200, page("Reset Password", body))

        else:
            log(ip,"PATH_PROBE",f"Unknown: {path}")
            self.send_html(404, page("404", "<div class='card' style='text-align:center;padding:48px;'><h1 style='font-size:4rem;color:#0f2744;'>404</h1><p style='color:#666;margin-top:8px;'>Page not found.</p><a href='/' style='color:#1565c0;display:block;margin-top:16px;'>← Return home</a></div>"))

    def do_POST(self):
        ip = self.ip()
        path = urlparse(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length",0))).decode("utf-8","ignore")
        p = parse_qs(body)
        user = p.get("username",[""])[0]
        pwd  = p.get("password",[""])[0]

        if path=="/login":
            sqli = ["'","--","1=1","SELECT","UNION","DROP","sleep(","SLEEP(","OR '","admin'--"]
            if any(s.lower() in (user+pwd).lower() for s in sqli):
                log(ip,"SQL_INJECTION_ATTEMPT",f"SQLi: user={user} pass={pwd}")
                ref = random.randint(10000,99999)
                self.send_html(200, page("Security Alert", f"""<div class='card' style='max-width:460px;margin:40px auto;text-align:center;'>
<div style='font-size:3rem;'>🚨</div>
<h2 style='color:#c62828;margin:16px 0;'>Security Alert Triggered</h2>
<p style='color:#666;'>Malicious input detected in login form. Your IP has been reported to our SOC team.</p>
<p style='color:#888;font-size:0.8rem;margin-top:12px;'>Reference: INC-2026-{ref}</p>
<p style='color:#c62828;font-weight:700;margin-top:12px;'>Session terminated.</p></div>"""))
                return

            log(ip,"LOGIN_ATTEMPT",f"user={user} pass={pwd}")

            lock_key = f"login_locked:{ip}"
            count_key = f"login_count:{ip}"

            if r:
                try:
                    if r.exists(lock_key):
                        ttl = r.ttl(lock_key)
                        self.send_html(200, locked_page(ttl))
                        return
                    attempts = r.incr(count_key)
                    r.expire(count_key, 600)
                    if attempts >= 3:
                        r.set(lock_key, "1", ex=600)
                        r.delete(count_key)
                        log(ip,"ACCOUNT_LOCKED","IP locked 10 min after 3 attempts")
                        self.send_html(200, locked_page(600))
                        return
                    self.send_html(200, captcha_page(user, int(attempts)))
                    return
                except Exception as e:
                    print(f"[WEB] Redis error: {e}")

            self.send_html(200, adaptive_login_page(ip, "Invalid credentials. Please try again."))

        elif path=="/careers/submit":
            name  = p.get("name",[""])[0]
            email = p.get("email",[""])[0]
            phone = p.get("phone",[""])[0]
            role  = p.get("role",[""])[0]
            log(ip,"CAREERS_APPLICATION",f"name={name} email={email} phone={phone} role={role}")
            ref = random.randint(10000,99999)
            body = f"""<div class='card' style='max-width:540px;margin:40px auto;text-align:center;'>
<div style='font-size:3rem;'>✅</div>
<h2 style='color:#2e7d32;margin:16px 0;'>Application Received!</h2>
<p style='color:#666;'>Thank you <b>{name}</b>, your application for <b>{role}</b> has been submitted successfully.</p>
<div class='alert alert-info' style='margin-top:20px;text-align:left;'>
  <b>Application Details</b><br>
  Reference: APP-2026-{ref}<br>
  Email: {email}<br>
  Phone: {phone}<br>
  Expected response within 5 business days.
</div>
<a href='/careers' style='display:inline-block;margin-top:16px;color:#1565c0;'>← View other positions</a></div>"""
            self.send_html(200, page("Application Submitted", body))

        elif path=="/support/submit":
            name  = p.get("name",[""])[0]
            email = p.get("email",[""])[0]
            issue = p.get("issue",[""])[0]
            desc  = p.get("desc",[""])[0]
            prio  = p.get("priority",["P3"])[0]
            log(ip,"SUPPORT_TICKET",f"name={name} email={email} issue={issue} priority={prio}")
            ref = random.randint(100000,999999)
            body = f"""<div class='card' style='max-width:540px;margin:40px auto;text-align:center;'>
<div style='font-size:3rem;'>🎫</div>
<h2 style='color:#1565c0;margin:16px 0;'>Ticket Created</h2>
<div class='alert alert-success' style='text-align:left;'>
  <b>Ticket #{ref}</b><br>
  Submitted by: {name} ({email})<br>
  Issue: {issue} | Priority: {prio}<br>
  Description: {desc[:100]}
</div>
<p style='color:#666;'>Our IT team will respond to <b>{email}</b> based on your priority level.</p>
<a href='/support' style='display:inline-block;margin-top:16px;color:#1565c0;'>← Back to Support</a></div>"""
            self.send_html(200, page("Ticket Created", body))

        else:
            self.send_html(404, "<h1>404</h1>")


if __name__ == "__main__":
    import os
    PORT = int(os.environ.get("PORT", 8888))
    print(f"""
╔══════════════════════════════════════════════════╗
║   NexaCorp Honeypot Portal — Port {PORT}
║   Pages: / /about /careers /support /dashboard   ║
║   Auth:  /admin /files /vpn /api/v1/users        ║
║   Traps: /.env /.git /robots.txt /files/download ║
╚══════════════════════════════════════════════════╝""")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
