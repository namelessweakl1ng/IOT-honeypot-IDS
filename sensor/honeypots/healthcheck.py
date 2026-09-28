"""Non-invasive health probe: inspect the kernel's listening-socket table."""
import os
import sys


port = int(os.environ["PORT"])
wanted = f"{port:04X}"
for table in ("/proc/net/tcp", "/proc/net/tcp6"):
    try:
        with open(table, encoding="ascii") as sockets:
            if any(line.split()[1].rsplit(":", 1)[-1] == wanted and line.split()[3] == "0A" for line in list(sockets)[1:]):
                sys.exit(0)
    except FileNotFoundError:
        pass
sys.exit(1)
