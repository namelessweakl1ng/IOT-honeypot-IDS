"""Explicit cleanup of historical loopback-derived data (dry-run by default)."""

import argparse
import asyncio
from typing import Any

from ..elastic import store
from ..services.telemetry import is_loopback

TARGET_INDICES = ("trapsig-sessions", "trapsig-detections")
PAGE_SIZE = 500


async def _internal_ids(index: str, elastic_store: Any) -> list[str]:
    """Classify _source in Python, independent of historical ES field mappings."""
    found: list[str] = []
    search_after = None
    while True:
        kwargs = {
            "index": index,
            "query": {"match_all": {}},
            "source": ["source_ip"],
            "size": PAGE_SIZE,
            "sort": [{"_shard_doc": "asc"}],
        }
        if search_after is not None:
            kwargs["search_after"] = search_after
        try:
            result = await elastic_store.client.search(**kwargs)
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return []
            raise
        hits = result.get("hits", {}).get("hits", [])
        for hit in hits:
            if is_loopback(hit.get("_source", {}).get("source_ip")):
                found.append(str(hit["_id"]))
        if len(hits) < PAGE_SIZE:
            break
        search_after = hits[-1]["sort"]
    return found


async def cleanup(confirm: bool = False, elastic_store: Any = store) -> dict[str, int]:
    matches = {index: await _internal_ids(index, elastic_store) for index in TARGET_INDICES}
    action = "deleting" if confirm else "would delete"
    for index, ids in matches.items():
        print(f"{action} {len(ids)} documents from {index}")
    if confirm:
        for index, ids in matches.items():
            for document_id in ids:
                await elastic_store.client.delete(index=index, id=document_id)
        if any(matches.values()):
            await elastic_store.client.indices.refresh(index=",".join(TARGET_INDICES))
    return {index: len(ids) for index, ids in matches.items()}


async def _main(confirm: bool) -> None:
    try:
        await cleanup(confirm)
    finally:
        await store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true", help="perform deletion (default is dry-run)")
    args = parser.parse_args()
    asyncio.run(_main(args.confirm))


if __name__ == "__main__":
    main()
