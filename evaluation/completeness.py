"""Offline, read-only comparison of deterministically mappable sensor JSONL IDs."""

import argparse
import json
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote

from .http import request_json


def mapped_event_id(record: dict) -> str | None:
    if record.get("event_id"):
        return str(record["event_id"])
    if all(record.get(field) is not None for field in ("eventid", "session", "timestamp")):
        return f"{record['eventid']}-{record['session']}-{record['timestamp']}"
    return None


def load_ids(paths: list[Path], start: datetime | None = None, end: datetime | None = None) -> tuple[int, list[str], int]:
    sensor_events, identifiers, unmappable = 0, [], 0
    for path in paths:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            sensor_events += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                unmappable += 1
                continue
            timestamp = record.get("timestamp")
            try:
                occurred = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if timestamp else None
            except (TypeError, ValueError):
                occurred = None
            if (start and (not occurred or occurred < start)) or (end and (not occurred or occurred > end)):
                unmappable += 1
                continue
            identifier = mapped_event_id(record)
            if identifier is None:
                unmappable += 1
            else:
                identifiers.append(identifier)
    return sensor_events, list(dict.fromkeys(identifiers)), unmappable


def compare(paths: list[Path], api_url: str, start: datetime | None = None, end: datetime | None = None) -> dict:
    sensor_events, identifiers, unmappable = load_ids(paths, start, end)
    matched = []
    for identifier in identifiers:
        try:
            request_json(f"{api_url.rstrip('/')}/events/{quote(identifier, safe='')}")
            matched.append(identifier)
        except HTTPError as exc:
            if exc.code != 404:
                raise
    missing = sorted(set(identifiers) - set(matched))
    return {
        "status": "MEASURED",
        "sensor_events": sensor_events,
        "mappable_events": len(identifiers),
        "unmappable_events": unmappable,
        "indexed_events": len(matched),
        "matched_events": len(matched),
        "missing_event_ids": missing,
        "completeness_percent": len(matched) / len(identifiers) * 100 if identifiers else None,
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
