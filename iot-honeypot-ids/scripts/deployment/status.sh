#!/usr/bin/env bash
# Status across PC1 + Pi (best-effort — assumes SSH access to the Pi).
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "=== PC1 status ==="
(cd dashboard && docker compose ps)

echo
echo "=== Pi status (via SSH, if configured) ==="
PI_SSH_USER="${PI_SSH_USER:-}"
PI_IP="${PI_IP:-}"
KNOWN_HOSTS="${PI_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"

# NOT_CONFIGURED when env missing — do NOT silently fall back to defaults.
if [ -z "$PI_IP" ] || [ -z "$PI_SSH_USER" ]; then
  echo "(PI_IP / PI_SSH_USER not set in .env — Pi status: NOT_CONFIGURED)"
  exit 0
fi

if ! command -v ssh >/dev/null; then
  echo "(ssh binary not installed on this host — Pi status: SSH_NOT_INSTALLED)"
  exit 0
fi

# Use accept-new so the FIRST connection adds the key to known_hosts. Subsequent
# mismatches STILL fail (mitigates MITM). Strictly safer than StrictHostKeyChecking=no.
# Override via PI_STRICT_HOST_KEY_CHECKING=yes for fully strict mode.
STRICT="${PI_STRICT_HOST_KEY_CHECKING:-accept-new}"

ssh -o ConnectTimeout=5 \
    -o StrictHostKeyChecking="$STRICT" \
    -o UserKnownHostsFile="$KNOWN_HOSTS" \
    -o PasswordAuthentication=no \
    -o BatchMode=yes \
    "${PI_SSH_USER}@${PI_IP}" \
    "cd ~/iot-honeypot-ids/pi && ./scripts/status.sh" 2>&1 || {
  echo "(SSH to ${PI_SSH_USER}@${PI_IP} failed — see stderr above for reason)"
  exit 1
}

