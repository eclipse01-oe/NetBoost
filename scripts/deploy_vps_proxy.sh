#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY="${NETBOOST_SSH_KEY:-$HOME/Downloads/netboost_vps_ssh.key}"
HOST="${NETBOOST_SSH_HOST:-opc@10.8.0.1}"

if [[ ! -f "$KEY" ]]; then
  echo "SSH key not found: $KEY" >&2
  echo "Set NETBOOST_SSH_KEY=/path/to/your/key and rerun." >&2
  exit 1
fi
if [[ ! -f "$ROOT/app/vps/main.py" ]]; then
  echo "Could not find app/vps/main.py relative to $ROOT" >&2
  exit 1
fi

SSH_ARGS=(-i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=8)
echo "Deploying the relay to $HOST. This expects WireGuard to be up so 10.8.0.1 is reachable."
scp "${SSH_ARGS[@]}" "$ROOT/app/vps/main.py" "$HOST:/tmp/netboost-vps-proxy.py"
ssh "${SSH_ARGS[@]}" "$HOST" 'bash -s' <<'REMOTE'
set -euo pipefail
sudo install -d -o opc -g opc -m 0755 /opt/netboost-vps-proxy
sudo install -o opc -g opc -m 0755 /tmp/netboost-vps-proxy.py /opt/netboost-vps-proxy/main.py
sudo rm -f /tmp/netboost-vps-proxy.py
sudo tee /etc/systemd/system/netboost-vps-proxy.service >/dev/null <<'UNIT'
[Unit]
Description=NetBoost WireGuard-only TCP relay
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=opc
Group=opc
ExecStart=/usr/bin/python3 /opt/netboost-vps-proxy/main.py --host 10.8.0.1 --port 8765
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
UNIT
RULE='rule family="ipv4" source address="10.8.0.2/32" port port="8765" protocol="tcp" accept'
sudo firewall-cmd --permanent --zone=public --add-rich-rule="$RULE" || true
sudo firewall-cmd --zone=public --add-rich-rule="$RULE" || true
sudo systemctl daemon-reload
sudo systemctl enable --now netboost-vps-proxy.service
sudo systemctl --no-pager --full status netboost-vps-proxy.service
REMOTE

echo
 echo "VPS relay deployed. It binds to 10.8.0.1 only and the firewall rule permits source 10.8.0.2."
