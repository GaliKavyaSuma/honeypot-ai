# HoneypotAI — Permanent Public Deployment Guide

## Option A: Streamlit Cloud (Recommended — Free, Permanent)

### Step 1 — Push to GitHub
1. Go to https://github.com and create a free account
2. Click "New repository" → name it `honeypot-ai` → Public → Create
3. On your Windows laptop, open PowerShell:

```powershell
# Install git if not already
winget install Git.Git

# Go to your project folder
cd C:\Users\kavya\Desktop\final_proj\honeypot-project

# Push to GitHub
git init
git add .
git commit -m "HoneypotAI Final Year Project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/honeypot-ai.git
git push -u origin main
```

### Step 2 — Deploy on Streamlit Cloud
1. Go to https://streamlit.io/cloud
2. Sign in with GitHub
3. Click "New app"
4. Select repo: `honeypot-ai`
5. Main file: `app.py`
6. Click Deploy

Your permanent URL: `https://YOUR-USERNAME-honeypot-ai.streamlit.app`

This URL never expires. Share with your teacher.

---

## Option B: Keep VM + DuckDNS (Permanent IP)

DuckDNS gives you a free permanent domain that always points to your VM.

### Step 1 — Get DuckDNS domain
1. Go to https://www.duckdns.org
2. Sign in with Google
3. Create domain: `honeypotai-kavya` → gives you `honeypotai-kavya.duckdns.org`
4. Note your token

### Step 2 — Install on VM
```bash
# Auto-update your IP every 5 minutes
mkdir -p ~/duckdns
cat > ~/duckdns/duck.sh << 'EOF'
echo url="https://www.duckdns.org/update?domains=honeypotai-kavya&token=YOUR_TOKEN&ip=" | curl -k -o ~/duckdns/duck.log -K -
EOF
chmod +x ~/duckdns/duck.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * ~/duckdns/duck.sh") | crontab -
```

### Step 3 — Router port forwarding
In your home router settings (usually 192.168.1.1):
- Forward port 9001 → your laptop's IP → port 9001
- Forward port 2222 → your laptop's IP → port 2222
- Forward port 8888 → your laptop's IP → port 8888

Then: `https://honeypotai-kavya.duckdns.org:9001` works permanently.

---

## For Real Public Attackers

The fastest way to get real internet attackers:

1. Post your SSH honeypot address on Shodan-indexed services
2. Or simply wait — automated scanners scan all public IPs within hours

Once you have the public IP/domain exposed on port 2222, run:
```bash
# Collect real attack data
cd /home/kavya/honeypot-project
python3 collect_real_data.py --geoip

# Restart dashboard to show real data
sudo docker-compose restart honeypot-dashboard
```
