"""Offline, read-only comparison of deterministically mappable sensor JSONL IDs."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from .http import request_json

PRESENCE_BATCH_SIZE = 250


def mapped_event_id(record: dict) -> str | None:
    if record.get("event_id"):
        return str(record["event_id"])
    if all(record.get(field) is not None for field in ("eventid", "session", "timestamp")):
        return f"{record['eventid']}-{record['session']}-{record['timestamp']}"
    return None


def load_ids(paths: list[Path], start: datetime | None = None, end: datetime | None = None) -> dict:
    total, in_window, filtered, identifiers, unmappable = 0, 0, 0, [], 0
    for path in paths:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            total += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                in_window += 1
                unmappable += 1
                continue
            timestamp = record.get("timestamp")
            try:
                occurred = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if timestamp else None
            except (TypeError, ValueError):
                occurred = None
            if (start or end) and occurred is None:
                in_window += 1
                unmappable += 1
                continue
            if (start and (not occurred or occurred < start)) or (end and (not occurred or occurred > end)):
                filtered += 1
                continue
            in_window += 1
            identifier = mapped_event_id(record)
            if identifier is None:
                unmappable += 1
            else:
                identifiers.append(identifier)
    return {
        "sensor_events_total": total,
        "sensor_events_in_window": in_window,
        "filtered_out_events": filtered,
        "event_ids": list(dict.fromkeys(identifiers)),
        "unmappable_events": unmappable,
    }


def fetch_present_event_ids(api_url: str, identifiers: list[str], batch_size: int = PRESENCE_BATCH_SIZE) -> set[str]:
    present: set[str] = set()
    for offset in range(0, len(identifiers), batch_size):
        batch = identifiers[offset : offset + batch_size]
        response = request_json(f"{api_url.rstrip('/')}/evaluation/event-presence", "POST", {"event_ids": batch})
        present.update(response.get("present_event_ids", []))
    return present


def compare(paths: list[Path], api_url: str, start: datetime | None = None, end: datetime | None = None) -> dict:
    loaded = load_ids(paths, start, end)
    identifiers = loaded.pop("event_ids")
    present = fetch_present_event_ids(api_url, identifiers)
    missing = sorted(set(identifiers) - present)
    return {
        "status": "MEASURED",
        **loaded,
        "mappable_events": len(identifiers),
        "indexed_events": len(present),
        "matched_events": len(present),
        "missing_event_ids": missing,
        "completeness_percent": len(present) / len(identifiers) * 100 if identifiers else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Compare sensor JSONL event IDs with indexed events")
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--start", type=datetime.fromisoformat)
    parser.add_argument("--end", type=datetime.fromisoformat)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(compare(args.logs, args.api_url, args.start, args.end), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
