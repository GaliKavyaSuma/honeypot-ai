#!/bin/bash
# ============================================================
# HoneypotAI — Master Start Script
# Kills everything cleanly then starts fresh
# Usage: bash start.sh
# ============================================================

echo "=== HoneypotAI Starting Up ==="
echo ""

# Kill any existing processes on our ports
echo "[1/5] Cleaning up old processes..."
sudo fuser -k 8888/tcp 2>/dev/null && echo "  Freed port 8888" || true
sudo fuser -k 9001/tcp 2>/dev/null && echo "  Freed port 9001" || true
pkill -f fake_website.py 2>/dev/null && echo "  Killed old fake_website" || true
pkill -f cowrie_tailer.py 2>/dev/null && echo "  Killed old cowrie_tailer" || true
pkill -f streamlit 2>/dev/null && echo "  Killed old streamlit" || true
pkill -f cloudflared 2>/dev/null && echo "  Killed old cloudflared" || true
sleep 2

# Start Docker containers
echo "[2/5] Starting Docker containers..."
sudo docker-compose down 2>/dev/null || true
sudo docker-compose up -d
sleep 5
sudo docker ps --format "  {{.Names}}: {{.Status}}"

# Start fake website
echo "[3/5] Starting NexaCorp fake website on port 8888..."
nohup python3 fake_website.py > /tmp/fakeweb.log 2>&1 &
sleep 2
if sudo fuser 8888/tcp > /dev/null 2>&1; then
    echo "  Website: RUNNING on port 8888"
else
    echo "  Website: FAILED - check /tmp/fakeweb.log"
fi

# Start cowrie tailer
echo "[4/5] Starting Cowrie log tailer..."
nohup python3 cowrie_tailer.py > /tmp/tailer.log 2>&1 &
sleep 2
if pgrep -f cowrie_tailer > /dev/null; then
    echo "  Tailer: RUNNING"
else
    echo "  Tailer: FAILED - check /tmp/tailer.log"
fi

# Start Cloudflare tunnel
echo "[5/5] Starting Cloudflare tunnels..."
nohup cloudflared tunnel --url http://localhost:9001 > /tmp/cf-dashboard.log 2>&1 &
nohup cloudflared tunnel --url http://localhost:8888 > /tmp/cf-website.log 2>&1 &
nohup cloudflared tunnel --url tcp://localhost:2222  > /tmp/cf-ssh.log 2>&1 &
sleep 8

DASH_URL=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' /tmp/cf-dashboard.log 2>/dev/null | head -1)
WEB_URL=$(grep  -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' /tmp/cf-website.log  2>/dev/null | head -1)

echo ""
echo "======================================================"
echo "  HoneypotAI is RUNNING!"
echo "======================================================"
echo ""
echo "  LOCAL:"
echo "    Dashboard:  http://127.0.0.1:9001"
echo "    Website:    http://127.0.0.1:8888"
echo ""
echo "  PUBLIC (share these):"
if [ -n "$DASH_URL" ]; then
    echo "    Dashboard:  $DASH_URL  ← Give to teacher"
fi
if [ -n "$WEB_URL" ]; then
    echo "    NexaCorp:   $WEB_URL   ← Attackers land here"
fi
echo ""
echo "  Logs:"
echo "    tail -f /tmp/fakeweb.log"
echo "    tail -f /tmp/tailer.log"
echo "    sudo docker logs honeypot-dashboard -f"
echo "======================================================"
