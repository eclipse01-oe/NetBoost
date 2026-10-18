#!/usr/bin/env bash
set -euo pipefail

CONFIG="/etc/wireguard/wg0.conf"
if [[ ! -f "$CONFIG" ]]; then
  echo "WireGuard config not found: $CONFIG" >&2
  exit 1
fi
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${CONFIG}.backup-netboost-${STAMP}"
sudo cp -a "$CONFIG" "$BACKUP"
sudo python3 - "$CONFIG" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
section = ""
changed = False
for index, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        section = stripped.lower()
        continue
    if section == "[peer]" and stripped.lower().startswith("allowedips") and "=" in line:
        key, value = line.split("=", 1)
        entries = [entry.strip() for entry in value.split(",") if entry.strip()]
        if "10.8.0.0/24" not in entries or "0.0.0.0/0" in entries or "::/0" in entries:
            indent = line[:len(line) - len(line.lstrip())]
            lines[index] = f"{indent}{key.strip()} = 10.8.0.0/24"
            changed = True
        break
else:
    raise SystemExit("No AllowedIPs entry found under a [Peer] section; no change made.")
if changed:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Changed client AllowedIPs to 10.8.0.0/24.")
else:
    print("Client AllowedIPs already use 10.8.0.0/24; no change was needed.")
PY

echo
 echo "Backup saved to: $BACKUP"
 echo "IMPORTANT: this script only changes the local CLIENT config. Run the following on your Ubuntu laptop, not on the VPS:"
 echo "  sudo wg-quick down wg0"
 echo "  sudo wg-quick up wg0"
 echo "Then verify these routes:"
 echo "  ip -4 route get 1.1.1.1"
 echo "  ip -4 route get 10.8.0.1"
 echo "The first should use Wi-Fi/Ethernet (not wg0); the second should use wg0."
 echo "If wg0 will not come back up, restore the backup shown above and run 'sudo wg-quick up wg0'."
