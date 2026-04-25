#!/bin/bash
# ============================================================
# HoneypotAI — Auto-Start Setup
# Run once: sudo bash setup_autostart.sh
# After this, everything starts automatically on VM reboot
# ============================================================

set -e
PROJECT_DIR="/home/kavya/honeypot-project"
USER="kavya"

echo "=== HoneypotAI Auto-Start Setup ==="
echo ""

# ── 1. Fake Website Service ───────────────────────────────────────────────────
echo "[1/3] Setting up NexaCorp fake website service..."
cat > /etc/systemd/system/honeypot-web.service << EOF
[Unit]
Description=HoneypotAI Fake Website (NexaCorp Portal)
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/python3 $PROJECT_DIR/fake_website.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
echo "   Created honeypot-web.service"

# ── 2. Cowrie Tailer Service ──────────────────────────────────────────────────
echo "[2/3] Setting up Cowrie tailer service..."
cat > /etc/systemd/system/honeypot-tailer.service << EOF
[Unit]
Description=HoneypotAI Cowrie Log Tailer
After=network.target cowrie.service
Wants=cowrie.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/python3 $PROJECT_DIR/cowrie_tailer.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
echo "   Created honeypot-tailer.service"

# ── 3. Docker Compose Service ─────────────────────────────────────────────────
echo "[3/3] Setting up Docker Compose auto-start..."
cat > /etc/systemd/system/honeypot-docker.service << EOF
[Unit]
Description=HoneypotAI Docker Containers
After=docker.service network.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=$USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
echo "   Created honeypot-docker.service"

# ── Enable and start all services ────────────────────────────────────────────
echo ""
echo "Enabling all services..."
systemctl daemon-reload
systemctl enable honeypot-web.service
systemctl enable honeypot-tailer.service
systemctl enable honeypot-docker.service

systemctl start honeypot-docker.service
sleep 5
systemctl start honeypot-web.service
systemctl start honeypot-tailer.service

echo ""
echo "=== Auto-start setup complete! ==="
echo ""
echo "Status check:"
systemctl is-active honeypot-docker.service  && echo "  Docker:  RUNNING" || echo "  Docker:  FAILED"
systemctl is-active honeypot-web.service     && echo "  Website: RUNNING" || echo "  Website: FAILED"
systemctl is-active honeypot-tailer.service  && echo "  Tailer:  RUNNING" || echo "  Tailer:  FAILED"
echo ""
echo "Now if your VM reboots, everything starts automatically."
echo "Check logs with: sudo journalctl -u honeypot-web -f"
