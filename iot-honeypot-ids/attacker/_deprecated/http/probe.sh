# HTTP enumeration scripts — used by http-enumeration scenario.

# Simple cURL probe with method + path; prints status code.
probe() {
  local method="$1"; local path="$2"; shift 2
  curl -s -o /dev/null -w "%{http_code}" -X "$method" \
    "http://${TARGET}:${CAMERA_HTTP_PORT:-8080}${path}" "$@"
}
