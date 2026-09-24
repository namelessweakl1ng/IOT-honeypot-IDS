# Reconnaissance scripts — banner grab + nmap-style probe (without nmap).

# Simple TCP banner grab via bash /dev/tcp
banner_grab() {
  local host="$1"; local port="$2"
  timeout 3 bash -c "exec 3<>/dev/tcp/${host}/${port}; head -c 64 <&3" 2>/dev/null || true
}
