# Enumeration scripts — endpoint / payload lists shared by HTTP and SSH scenarios.

# Common paths to probe on a "camera" / DVR device
CAMERA_PATHS=(
  / /login /admin /config /system /status /network /users /device
  /firmware /snapshot /video /api/ /api/v1 /api/info
)

# Path traversal probes
TRAVERSAL_PATHS=(
  "/../../../etc/passwd"
  "/admin/../../etc/shadow"
  "/cgi-bin/cat?file=../../etc/passwd"
  "/%2e%2e/%2e%2e/etc/passwd"
)

# Command injection probes
INJECTION_PATHS=(
  "/api/exec?cmd=id"
  "/api/shell?c=whoami"
  "/api/run?cmd=uname%20-a"
  "/cgi-bin/cmd?exec=ls"
)

# Sensitive file probes
SENSITIVE_PATHS=(
  "/.git/config"
  "/.env"
  "/backup.zip"
  "/.ssh/id_rsa"
  "/wp-admin/"
  "/server-status"
)
