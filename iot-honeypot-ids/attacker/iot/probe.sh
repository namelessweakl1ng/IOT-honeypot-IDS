# IoT scenario scripts — used by iot-probe scenario.

# Send a single line over the IoT TCP service and print the response.
iot_probe_once() {
  local line="$1"
  python3 -c "
import socket
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('${TARGET}', ${IOT_SERVICE_PORT:-9000}))
    print('banner:', s.recv(1024).decode(errors='ignore').strip())
    s.sendall(b'${line}\n')
    print('reply: ', s.recv(1024).decode(errors='ignore').strip())
    s.close()
except Exception as e:
    print('error:', e)
"
}
