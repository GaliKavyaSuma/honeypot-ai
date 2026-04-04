#!/bin/bash
# ============================================================
# HoneypotAI — Cloudflare Tunnel Setup
# Gives your teacher a FREE public URL — no account needed
# No bandwidth limits, no warning pages, works forever
# ============================================================

echo "=== Setting up Cloudflare Tunnel ==="
echo ""

# Install cloudflared if not present
if ! command -v cloudflared &>/dev/null; then
    echo "[1/2] Downloading cloudflared..."
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared-linux-amd64.deb
    rm cloudflared-linux-amd64.deb
    echo "      cloudflared installed"
else
    echo "[1/2] cloudflared already installed"
fi

# Start tunnel for dashboard
echo ""
echo "[2/2] Starting public tunnel for HoneypotAI Dashboard..."
echo "      This gives you a public URL your teacher can open anywhere."
echo ""

# Run in background and capture URL
nohup cloudflared tunnel --url http://localhost:9001 \
    --logfile /tmp/cloudflared.log 2>&1 &

sleep 4

# Extract the public URL from logs
URL=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' /tmp/cloudflared.log 2>/dev/null | head -1)

echo "======================================================"
echo ""
if [ -n "$URL" ]; then
    echo "  ✅ Your public dashboard URL:"
    echo ""
    echo "     $URL"
    echo ""
    echo "  Share this with your teacher — opens in any browser,"
    echo "  on any device, anywhere in the world."
else
    echo "  Tunnel starting... check URL with:"
    echo "  grep trycloudflare.com /tmp/cloudflared.log"
fi

echo ""
echo "  To stop: pkill cloudflared"
echo "======================================================"
