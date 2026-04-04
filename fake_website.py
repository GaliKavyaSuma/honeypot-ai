#!/usr/bin/env python3
"""
HoneypotAI — Deceptive Web Honeypot "NexaCorp Employee Portal"
Convincing multi-page fake company intranet.
Run: python3 fake_website.py
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import json, datetime, redis, hashlib, time

def connect_redis():
    """Connect to Redis — tries Docker mapped port 6380 first, then system 6379."""
    import redis as redis_lib
    for port in [6380, 6379]:
        try:
            r = redis_lib.Redis(host='127.0.0.1', port=port, db=0,
                               decode_responses=True, socket_timeout=2)
            r.ping()
            print(f"[WEB] Connected to Redis on port {port}")
            return r
        except Exception:
            continue
    print("[WEB] WARNING: Redis not available. Events will not be logged.")
    return None

r = connect_redis()

def log(ip, etype, data=""):
    ev = {"timestamp": datetime.datetime.utcnow().isoformat(),
          "ip": ip, "port": 8888, "service": "WEB_HONEYPOT",
          "event_type": etype, "data": str(data)[:500]}
    if r:
        try:
            r.lpush("honeypot:events", json.dumps(ev))
            r.ltrim("honeypot:events", 0, 99999)
        except Exception:
            pass
    print(f"[WEB] {ip} — {etype}: {data[:80]}")

# ── HTML Templates ────────────────────────────────────────────────────────────

BASE_CSS = """
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;min-height:100vh;}
.navbar{background:#1e3a5f;padding:12px 32px;display:flex;justify-content:space-between;align-items:center;}
.navbar .brand{color:white;font-size:1.2rem;font-weight:700;letter-spacing:1px;}
.navbar .nav-links a{color:#adc8e8;text-decoration:none;margin-left:24px;font-size:0.9rem;}
.navbar .nav-links a:hover{color:white;}
.container{max-width:1100px;margin:40px auto;padding:0 20px;}
.card{background:white;border-radius:10px;padding:32px;box-shadow:0 2px 12px rgba(0,0,0,0.08);margin-bottom:24px;}
.btn{padding:11px 28px;border:none;border-radius:6px;cursor:pointer;font-size:0.95rem;font-weight:600;}
.btn-primary{background:#1e3a5f;color:white;}
.btn-primary:hover{background:#163050;}
.btn-secondary{background:#e9ecef;color:#333;}
input,select{width:100%;padding:11px 14px;border:1px solid #ddd;border-radius:6px;font-size:0.95rem;margin-bottom:16px;outline:none;}
input:focus{border-color:#1e3a5f;box-shadow:0 0 0 3px rgba(30,58,95,0.1);}
label{display:block;font-size:0.85rem;color:#555;font-weight:600;margin-bottom:5px;}
.alert{padding:12px 16px;border-radius:6px;margin-bottom:16px;font-size:0.88rem;}
.alert-danger{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;}
.alert-info{background:#eff6ff;border:1px solid #bfdbfe;color:#1d4ed8;}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.75rem;font-weight:700;}
.badge-admin{background:#fef2f2;color:#dc2626;}
.badge-user{background:#f0fdf4;color:#16a34a;}
.badge-manager{background:#eff6ff;color:#1d4ed8;}
footer{background:#1e3a5f;color:#adc8e8;text-align:center;padding:20px;font-size:0.82rem;margin-top:48px;}
</style>"""

LOGIN_PAGE = BASE_CSS + """
<!-- NexaCorp Portal v2.4.1 | DB: nexadb01.internal:5432 | admin pwd hash: $2b$12$nexacorp2024secret -->
<body style='background:#1e3a5f;display:flex;align-items:center;justify-content:center;min-height:100vh;'>
<div style='background:white;border-radius:12px;padding:48px 40px;width:420px;box-shadow:0 24px 64px rgba(0,0,0,0.4);'>
  <div style='text-align:center;margin-bottom:32px;'>
    <div style='font-size:2.8rem;'>🏢</div>
    <div style='font-size:1.5rem;font-weight:700;color:#1e3a5f;margin-top:8px;'>NexaCorp</div>
    <div style='font-size:0.8rem;color:#888;letter-spacing:2px;margin-top:4px;'>EMPLOYEE PORTAL</div>
    <div style='background:#f0fdf4;border:1px solid #bbf7d0;color:#16a34a;padding:4px 12px;
         border-radius:20px;font-size:0.72rem;font-weight:700;display:inline-block;margin-top:8px;'>
      🔒 256-BIT SSL SECURED
    </div>
  </div>
  {ERROR}
  <form method='POST' action='/login'>
    <label>Corporate Email Address</label>
    <input type='email' name='username' placeholder='firstname.lastname@nexacorp.com' required>
    <label>Password</label>
    <input type='password' name='password' placeholder='••••••••••' required>
    <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;'>
      <label style='display:flex;align-items:center;gap:6px;margin-bottom:0;font-weight:400;'>
        <input type='checkbox' style='width:auto;margin-bottom:0;'> Remember this device
      </label>
      <a href='/forgot-password' style='font-size:0.82rem;color:#1e3a5f;'>Forgot password?</a>
    </div>
    <button type='submit' class='btn btn-primary' style='width:100%;padding:13px;font-size:1rem;'>
      Sign In →
    </button>
  </form>
  <hr style='margin:24px 0;border:none;border-top:1px solid #eee;'>
  <div style='text-align:center;font-size:0.82rem;color:#666;'>
    Sign in with <a href='/sso/microsoft' style='color:#1e3a5f;font-weight:600;'>Microsoft SSO</a>
    &nbsp;|&nbsp;
    <a href='/sso/google' style='color:#1e3a5f;font-weight:600;'>Google SSO</a>
  </div>
  <div style='text-align:center;font-size:0.75rem;color:#aaa;margin-top:20px;'>
    NexaCorp Inc. · IT Helpdesk: +91-80-4521-8800 · support@nexacorp.com<br>
    © 2026 NexaCorp. Unauthorized access is prohibited and monitored.
  </div>
</div>
</body>"""

WRONG_PASSWORD_PAGE = BASE_CSS + """
<body style='background:#1e3a5f;display:flex;align-items:center;justify-content:center;min-height:100vh;'>
<div style='background:white;border-radius:12px;padding:48px 40px;width:420px;box-shadow:0 24px 64px rgba(0,0,0,0.4);'>
  <div style='text-align:center;margin-bottom:24px;'>
    <div style='font-size:2.8rem;'>🏢</div>
    <div style='font-size:1.5rem;font-weight:700;color:#1e3a5f;margin-top:8px;'>NexaCorp</div>
  </div>
  <div class='alert alert-danger'>
    ⚠ Invalid credentials. Your account will be locked after 3 failed attempts.<br>
    <small>Attempt {ATTEMPTS}/3 recorded. IP logged for security audit.</small>
  </div>
  <form method='POST' action='/login'>
    <label>Corporate Email Address</label>
    <input type='email' name='username' value='{USERNAME}' required>
    <label>Password</label>
    <input type='password' name='password' placeholder='••••••••••' required>
    <div style='margin-bottom:20px;'>
      <div style='font-size:0.82rem;color:#666;margin-bottom:8px;'>Security verification:</div>
      <div style='background:#f8f9fa;border:1px solid #ddd;border-radius:6px;padding:16px;
           display:flex;justify-content:space-between;align-items:center;'>
        <span style='font-size:1.2rem;font-weight:700;letter-spacing:4px;color:#333;
              font-family:monospace;text-decoration:line-through;filter:blur(0.5px);'>
          NX{CAPTCHA}
        </span>
        <span style='font-size:0.75rem;color:#888;'>Type the code above</span>
      </div>
      <input type='text' name='captcha' placeholder='Enter security code' style='margin-top:8px;'>
    </div>
    <button type='submit' class='btn btn-primary' style='width:100%;padding:13px;'>Sign In →</button>
  </form>
</div></body>"""

ABOUT_PAGE = BASE_CSS + """
<body>
<nav class='navbar'>
  <div class='brand'>NexaCorp</div>
  <div class='nav-links'>
    <a href='/'>Home</a><a href='/about'>About</a>
    <a href='/careers'>Careers</a><a href='/contact'>Contact</a>
  </div>
</nav>
<div class='container'>
  <div class='card'>
    <h1 style='color:#1e3a5f;margin-bottom:8px;'>About NexaCorp</h1>
    <p style='color:#666;margin-bottom:24px;'>Enterprise Technology Solutions Since 2009</p>
    <p style='color:#444;line-height:1.7;margin-bottom:16px;'>NexaCorp is a leading enterprise technology company specializing in cloud infrastructure, AI solutions, and cybersecurity services. Headquartered in Bangalore, India, we serve 200+ enterprise clients across 18 countries.</p>
    <div style='display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-top:24px;'>
      <div style='text-align:center;padding:20px;background:#f8f9fa;border-radius:8px;'><div style='font-size:2rem;font-weight:700;color:#1e3a5f;'>200+</div><div style='color:#666;font-size:0.85rem;'>Enterprise Clients</div></div>
      <div style='text-align:center;padding:20px;background:#f8f9fa;border-radius:8px;'><div style='font-size:2rem;font-weight:700;color:#1e3a5f;'>4,500</div><div style='color:#666;font-size:0.85rem;'>Employees</div></div>
      <div style='text-align:center;padding:20px;background:#f8f9fa;border-radius:8px;'><div style='font-size:2rem;font-weight:700;color:#1e3a5f;'>18</div><div style='color:#666;font-size:0.85rem;'>Countries</div></div>
    </div>
  </div>
  <div class='card'>
    <h2 style='color:#1e3a5f;margin-bottom:20px;'>Leadership Team</h2>
    <div style='display:grid;grid-template-columns:repeat(2,1fr);gap:16px;'>
      <div style='display:flex;gap:12px;align-items:center;padding:16px;background:#f8f9fa;border-radius:8px;'><div style='width:48px;height:48px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>RM</div><div><div style='font-weight:700;color:#1e3a5f;'>Rajesh Menon</div><div style='font-size:0.82rem;color:#888;'>Chief Executive Officer</div><div style='font-size:0.78rem;color:#aaa;'>r.menon@nexacorp.com</div></div></div>
      <div style='display:flex;gap:12px;align-items:center;padding:16px;background:#f8f9fa;border-radius:8px;'><div style='width:48px;height:48px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>PS</div><div><div style='font-weight:700;color:#1e3a5f;'>Priya Sharma</div><div style='font-size:0.82rem;color:#888;'>Chief Technology Officer</div><div style='font-size:0.78rem;color:#aaa;'>p.sharma@nexacorp.com</div></div></div>
      <div style='display:flex;gap:12px;align-items:center;padding:16px;background:#f8f9fa;border-radius:8px;'><div style='width:48px;height:48px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>DC</div><div><div style='font-weight:700;color:#1e3a5f;'>David Chen</div><div style='font-size:0.82rem;color:#888;'>Chief Financial Officer</div><div style='font-size:0.78rem;color:#aaa;'>d.chen@nexacorp.com</div></div></div>
      <div style='display:flex;gap:12px;align-items:center;padding:16px;background:#f8f9fa;border-radius:8px;'><div style='width:48px;height:48px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;flex-shrink:0;'>SM</div><div><div style='font-weight:700;color:#1e3a5f;'>Sarah Mitchell</div><div style='font-size:0.82rem;color:#888;'>Head of Security</div><div style='font-size:0.78rem;color:#aaa;'>s.mitchell@nexacorp.com</div></div></div>
    </div>
  </div>
</div>
<footer>2026 NexaCorp Inc. All rights reserved.</footer>
</body>"""

ADMIN_PAGE = BASE_CSS + """
<!-- INTERNAL USE ONLY - DO NOT EXPOSE -->
<!-- DB connection: postgresql://nexaadmin:NexaDB@2024!@nexadb01.internal:5432/nexacorp_prod -->
<!-- Redis: redis://:NexaRedis@2024@redis01.internal:6379 -->
<!-- AWS Access Key: AKIAIOSFODNN7EXAMPLE | Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY -->
<body>
<nav class='navbar'>
  <div class='brand'>🏢 NexaCorp Admin Panel</div>
  <div class='nav-links'>
    <a href='/admin'>Dashboard</a>
    <a href='/admin/users'>Users</a>
    <a href='/admin/servers'>Servers</a>
    <a href='/logout' style='color:#ff8080;'>Logout</a>
  </div>
</nav>
<div class='container'>
  <div class='alert alert-info'>👋 Welcome back, administrator. Last login: Today 09:14 AM from 10.0.1.5</div>
  <div style='display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;'>
    {''.join([f"<div class='card' style='padding:20px;text-align:center;'><div style='font-size:1.8rem;font-weight:700;color:#1e3a5f;'>{v}</div><div style='color:#888;font-size:0.82rem;'>{l}</div></div>"
    for v,l in [("4,521","Total Users"),("23","Active Servers"),("₹2.4Cr","Monthly Revenue"),("99.7%","Uptime")]])}
  </div>
  <div class='card'>
    <h2 style='color:#1e3a5f;margin-bottom:16px;'>👥 Employee Directory</h2>
    <table style='width:100%;border-collapse:collapse;font-size:0.88rem;'>
      <tr style='background:#f8f9fa;'><th style='padding:10px;text-align:left;border-bottom:2px solid #dee2e6;'>Name</th>
      <th style='padding:10px;text-align:left;border-bottom:2px solid #dee2e6;'>Email</th>
      <th style='padding:10px;text-align:left;border-bottom:2px solid #dee2e6;'>Role</th>
      <th style='padding:10px;text-align:left;border-bottom:2px solid #dee2e6;'>Department</th></tr>
      {''.join([f"<tr><td style='padding:10px;border-bottom:1px solid #dee2e6;'>{n}</td><td style='padding:10px;border-bottom:1px solid #dee2e6;color:#1e3a5f;'>{e}</td><td style='padding:10px;border-bottom:1px solid #dee2e6;'><span class='badge badge-{r.lower()}'>{r}</span></td><td style='padding:10px;border-bottom:1px solid #dee2e6;color:#888;'>{d}</td></tr>"
      for n,e,r,d in [
        ("Rajesh Menon","r.menon@nexacorp.com","Admin","Executive"),
        ("Priya Sharma","p.sharma@nexacorp.com","Admin","Technology"),
        ("David Chen","d.chen@nexacorp.com","Manager","Finance"),
        ("Sarah Mitchell","s.mitchell@nexacorp.com","Manager","Security"),
        ("Arjun Patel","a.patel@nexacorp.com","User","Engineering"),
        ("Lisa Wong","l.wong@nexacorp.com","User","Marketing"),
      ]])}
    </table>
  </div>
  <div class='card'>
    <h2 style='color:#1e3a5f;margin-bottom:16px;'>🔑 System Credentials (Confidential)</h2>
    <table style='width:100%;border-collapse:collapse;font-size:0.88rem;'>
      <tr style='background:#fef2f2;'><th style='padding:10px;text-align:left;'>System</th>
      <th style='padding:10px;text-align:left;'>Username</th>
      <th style='padding:10px;text-align:left;'>Password</th>
      <th style='padding:10px;text-align:left;'>Last Changed</th></tr>
      {''.join([f"<tr><td style='padding:10px;border-bottom:1px solid #dee2e6;'>{s}</td><td style='padding:10px;border-bottom:1px solid #dee2e6;font-family:monospace;'>{u}</td><td style='padding:10px;border-bottom:1px solid #dee2e6;font-family:monospace;color:#dc2626;'>{p}</td><td style='padding:10px;border-bottom:1px solid #dee2e6;color:#888;'>{d}</td></tr>"
      for s,u,p,d in [
        ("Production DB","nexaadmin","NexaDB@2024!","2024-11-01"),
        ("AWS Console","aws_root","AWSNexaCorp99#","2024-10-15"),
        ("VPN Gateway","vpn_admin","VPN#Secure2026","2025-01-20"),
        ("Redis Cache","redis_admin","Redis@NexaCache","2024-12-01"),
        ("Jenkins CI","jenkins","Jenkins@Build2024","2024-09-10"),
      ]])}
    </table>
  </div>
</div></body>"""

API_RESPONSE = {
    "status": "ok", "version": "1.0.3", "environment": "production",
    "database": "nexadb01.internal:5432",
    "users": [
        {"id":1,"name":"Rajesh Menon","email":"r.menon@nexacorp.com","role":"admin","password_hash":"$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TiGc2L"},
        {"id":2,"name":"Priya Sharma","email":"p.sharma@nexacorp.com","role":"admin","password_hash":"$2b$12$KIXHqVm2EXAMPLEHASH123456789"},
        {"id":3,"name":"Arjun Patel","email":"a.patel@nexacorp.com","role":"user","api_key":"sk-nexacorp-prod-a8f3d2b1c9e4"},
    ],
    "server_config": {"secret_key":"nexacorp-jwt-secret-2024","debug":False,"db_password":"NexaDB@2024!"}
}

ROBOTS = b"User-agent: *\nDisallow: /admin\nDisallow: /admin/users\nDisallow: /api/\nDisallow: /backup\nDisallow: /config\nDisallow: /.env\nDisallow: /db\nAllow: /\n"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def ip(self): return self.client_address[0]

    def send_html(self, code, html):
        self.send_response(code)
        self.send_header("Content-type","text/html; charset=utf-8")
        self.send_header("Server","Apache/2.4.54 (Ubuntu)")
        self.send_header("X-Powered-By","PHP/8.1.12")
        self.end_headers()
        self.wfile.write(html.encode())

    def send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-type","application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        ip  = self.ip()
        path = urlparse(self.path).path

        if path in ["/", "/login", "/index.html"]:
            log(ip, "PAGE_VISIT", f"GET {path}")
            self.send_html(200, LOGIN_PAGE.replace("{ERROR}",""))

        elif path == "/about":
            log(ip, "PAGE_VISIT", "GET /about")
            self.send_html(200, ABOUT_PAGE)

        elif path.startswith("/admin"):
            log(ip, "ADMIN_ACCESS", f"Accessed {path}")
            self.send_html(200, ADMIN_PAGE)

        elif path == "/robots.txt":
            log(ip, "ROBOTS_TXT", "Scraped robots.txt")
            self.send_response(200)
            self.send_header("Content-type","text/plain")
            self.end_headers()
            self.wfile.write(ROBOTS)

        elif path.startswith("/api/"):
            log(ip, "API_PROBE", f"Probed API: {path}")
            if "users" in path or "config" in path or "v1" in path:
                self.send_json(200, API_RESPONSE)
            else:
                self.send_json(404, {"error":"endpoint not found"})

        elif path in ["/.env", "/config.php", "/backup", "/db", "/.git", "/wp-admin",
                      "/phpmyadmin", "/mysql", "/.ssh", "/id_rsa", "/passwords.txt"]:
            log(ip, "SENSITIVE_PATH_PROBE", f"Probed: {path}")
            self.send_html(403, "<h1>403 Forbidden</h1>")

        elif path in ["/sso/microsoft", "/sso/google"]:
            log(ip, "SSO_PROBE", f"Attempted SSO: {path}")
            self.send_html(200, LOGIN_PAGE.replace("{ERROR}",
                "<div class='alert-info' style='background:#eff6ff;border:1px solid #bfdbfe;color:#1d4ed8;padding:10px;border-radius:6px;margin-bottom:16px;font-size:0.85rem;'>SSO service temporarily unavailable. Please use your email and password.</div>"))

        elif path == "/forgot-password":
            log(ip, "FORGOT_PASSWORD", "Accessed password reset")
            self.send_html(200, BASE_CSS + "<body style='background:#1e3a5f;display:flex;align-items:center;justify-content:center;min-height:100vh;'><div style='background:white;border-radius:12px;padding:40px;width:420px;text-align:center;'><div style='font-size:2.5rem;margin-bottom:16px;'>📧</div><h2 style='color:#1e3a5f;'>Password Reset</h2><p style='color:#666;margin:16px 0;'>Enter your corporate email and we will send a reset link.</p><input type='email' placeholder='your@nexacorp.com' style='margin-bottom:16px;'><button class='btn btn-primary' style='width:100%;'>Send Reset Link</button><p style='margin-top:16px;font-size:0.8rem;color:#aaa;'><a href='/' style='color:#1e3a5f;'>← Back to login</a></p></div></body>")

        else:
            log(ip, "PATH_PROBE", f"Unknown path: {path}")
            self.send_html(404, BASE_CSS + "<body style='display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f0f2f5;'><div style='text-align:center;'><h1 style='font-size:4rem;color:#1e3a5f;'>404</h1><p style='color:#666;'>Page not found.</p><a href='/' style='color:#1e3a5f;'>← Return home</a></div></body>")

    def do_POST(self):
        ip   = self.ip()
        path = urlparse(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length",0))).decode("utf-8","ignore")
        p    = parse_qs(body)
        user = p.get("username",[""])[0]
        pwd  = p.get("password",[""])[0]

        if path == "/login":
            log(ip, "LOGIN_ATTEMPT", f"user={user} pass={pwd}")

            # Track attempt count per IP
            key = f"login_attempts:{ip}"
            attempts = r.incr(key)
            r.expire(key, 300)

            import random, string
            captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

            page = WRONG_PASSWORD_PAGE
            page = page.replace("{ATTEMPTS}", str(min(attempts, 3)))
            page = page.replace("{USERNAME}", user)
            page = page.replace("{CAPTCHA}", captcha)
            self.send_html(200, page)

if __name__ == "__main__":
    PORT = 8888
    print(f"""
╔══════════════════════════════════════════════════╗
║   HoneypotAI — Deceptive Web Portal Running      ║
║                                                  ║
║   URL: http://0.0.0.0:{PORT}                      ║
║   Pages: / /about /admin /api/v1/users           ║
║   Logging all interactions to Redis              ║
╚══════════════════════════════════════════════════╝
    """)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
