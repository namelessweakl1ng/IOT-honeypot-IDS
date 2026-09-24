"""
Optional local collector — buffers telemetry when PC1 (Logstash) is unreachable.

This is intentionally tiny. It is NOT a replacement for Filebeat; it is a
safety net so that if Filebeat cannot reach PC1 for a long time, the Pi
does not run out of disk or silently lose data.

Usage: enable the `collector` profile in docker-compose:
    docker compose --profile collector up -d collector
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
CENTRAL_SERVER_IP = os.environ.get("CENTRAL_SERVER_IP", "")
LOGSTASH_BEATS_PORT = int(os.environ.get("LOGSTASH_BEATS_PORT", "5044"))
SPOOL_DIR = Path(os.environ.get("SPOOL_DIR", "/data"))

LOG_DIRS = {
    "cowrie": Path("/logs/cowrie/log/cowrie"),
    "camera": Path("/logs/camera"),
    "iot": Path("/logs/iot"),
}
LOG_FILES = {
    "cowrie": "cowrie.json",
    "camera": "camera.jsonl",
    "iot": "iot.jsonl",
}

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)
log = logging.getLogger("collector")


def _is_central_reachable() -> bool:
    """Quick TCP probe — if PC1 Logstash is listening we are good."""
    import socket

    try:
        with socket.create_connection(
            (CENTRAL_SERVER_IP, LOGSTASH_BEATS_PORT), timeout=2
        ) as _:
            return True
    except OSError:
        return False


def _scan_one(name: str, log_dir: Path, fname: str, cursor: int) -> int:
    """Read new bytes from one log file and write to spool. Return new cursor."""
    path = log_dir / fname
    if not path.exists():
        return cursor
    try:
        size = path.stat().st_size
    except OSError:
        return cursor
    if size < cursor:
        # log rotation / restart — restart from 0
        cursor = 0
    if size == cursor:
        return cursor
    with open(path, "rb") as fh:
        fh.seek(cursor)
        new_bytes = fh.read(size - cursor)
    if not new_bytes:
        return size
    spool_path = SPOOL_DIR / f"{name}-{int(time.time() * 1000)}.jsonl"
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)
    with open(spool_path, "wb") as out:
        out.write(new_bytes)
    log.info("buffered %d bytes from %s -> %s", len(new_bytes), name, spool_path.name)
    return size


def main() -> None:
    log.info(
        "collector starting; central=%s:%d spool=%s",
        CENTRAL_SERVER_IP, LOGSTASH_BEATS_PORT, SPOOL_DIR,
    )
    if not CENTRAL_SERVER_IP:
        log.error("CENTRAL_SERVER_IP not set — collector exiting")
        return

    cursors = {name: 0 for name in LOG_DIRS}
    poll_interval = 10  # seconds
    reachable_check_interval = 30
    last_reachable_check = 0

    while True:
        now = time.time()
        if now - last_reachable_check > reachable_check_interval:
            reachable = _is_central_reachable()
            last_reachable_check = now
            if reachable and any((SPOOL_DIR).glob("*.jsonl")):
                # Filebeat will eventually drain its own spool to PC1; we just
                # log the situation here so the operator sees the buffer.
                log.warning(
                    "central reachable but spool has %d buffered files",
                    len(list(SPOOL_DIR.glob("*.jsonl"))),
                )

        # Always read new bytes into our spool so Filebeat can ship them.
        for name, log_dir in LOG_DIRS.items():
            try:
                cursors[name] = _scan_one(
                    name, log_dir, LOG_FILES[name], cursors[name]
                )
            except Exception as exc:
                log.error("error scanning %s: %s", name, exc)

        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
