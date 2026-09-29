"""Explicit cleanup of historical loopback-derived data (dry-run by default)."""
import argparse
import asyncio
from typing import Any
from ..elastic import store

TARGET_INDICES = ("trapsig-sessions", "trapsig-detections")
INTERNAL_QUERY: dict[str, Any] = {"bool": {"should": [
    {"range": {"source_ip": {"gte": "127.0.0.0", "lte": "127.255.255.255"}}},
    {"term": {"source_ip": "::1"}},
], "minimum_should_match": 1}}

async def cleanup(confirm: bool = False, elastic_store: Any = store) -> dict[str, int]:
    counts: dict[str, int] = {}
    for index in TARGET_INDICES:
        try: counts[index] = await elastic_store.count(index, INTERNAL_QUERY)
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404: counts[index] = 0
            else: raise
    action = "deleting" if confirm else "would delete"
    for index, count in counts.items(): print(f"{action} {count} documents from {index}")
    if confirm:
        for index in TARGET_INDICES:
            await elastic_store.client.delete_by_query(index=index, query=INTERNAL_QUERY, refresh=True)
    return counts

async def _main(confirm: bool) -> None:
    try: await cleanup(confirm)
    finally: await store.close()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true", help="perform deletion (default is dry-run)")
    args = parser.parse_args()
    asyncio.run(_main(args.confirm))

if __name__ == "__main__": main()
