#!/bin/sh
# Makes Tapo Watch start at boot and restart if it stops (systemd).
DIR=$(cd "$(dirname "$0")/.." && pwd)
sudo tee /etc/systemd/system/tapo-watch.service >/dev/null <<UNIT
[Unit]
Description=Tapo Watch
After=network-online.target
Wants=network-online.target

[Service]
User=$USER
WorkingDirectory=$DIR
ExecStart=$(command -v python3) $DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now tapo-watch
echo "Done. Check it with: systemctl status tapo-watch"
