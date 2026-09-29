from typing import Any

from elasticsearch import AsyncElasticsearch, NotFoundError

from .config import get_settings


class ElasticStore:
    def __init__(self) -> None:
        settings = get_settings()
        kwargs = {"basic_auth": ("elastic", settings.elastic_password)} if settings.elastic_password else {}
        self.client = AsyncElasticsearch(settings.elasticsearch_url, **kwargs)

    async def health(self) -> dict[str, Any]:
        return dict(await self.client.cluster.health())

    async def search(
        self,
        index: str,
        query: dict[str, Any] | None = None,
        size: int = 100,
        sort_field: str = "@timestamp",
        missing_index_is_empty: bool = False,
    ) -> list[dict[str, Any]]:
        try:
            result = await self.client.search(
                index=index,
                query=query or {"match_all": {}},
                size=size,
                sort=[{sort_field: "desc"}],
            )
        except NotFoundError:
            if missing_index_is_empty:
                return []
            raise
        return [{**hit["_source"], "_id": hit["_id"]} for hit in result["hits"]["hits"]]

    async def count(
        self,
        index: str,
        query: dict[str, Any] | None = None,
        missing_index_is_empty: bool = False,
    ) -> int:
        try:
            result = await self.client.count(index=index, query=query or {"match_all": {}})
        except NotFoundError:
            if missing_index_is_empty:
                return 0
            raise
        return int(result["count"])

    async def search_all(
        self,
        index: str,
        query: dict[str, Any] | None = None,
        *,
        sort: list[dict[str, Any]] | None = None,
        page_size: int = 500,
        missing_index_is_empty: bool = False,
    ) -> list[dict[str, Any]]:
        """Return all matches from a consistent PIT without sorting on text IDs."""
        keep_alive = "1m"
        # _shard_doc is the PIT-specific, mapping-independent tiebreaker
        # recommended by Elasticsearch for search_after traversal.
        ordering = [*(sort or [{"@timestamp": "asc"}]), {"_shard_doc": "asc"}]
        documents: list[dict[str, Any]] = []
        after: list[Any] | None = None
        pit_id: str | None = None
        try:
            pit = await self.client.open_point_in_time(index=index, keep_alive=keep_alive)
            pit_id = pit["id"]
            while True:
                arguments: dict[str, Any] = {
                    "pit": {"id": pit_id, "keep_alive": keep_alive},
                    "query": query or {"match_all": {}},
                    "size": page_size,
                    "sort": ordering,
                    "track_total_hits": False,
                }
                if after is not None:
                    arguments["search_after"] = after
                result = await self.client.search(**arguments)
                # Elasticsearch can rotate PIT IDs; always continue and close
                # with the newest identifier returned by a page.
                pit_id = result.get("pit_id", pit_id)
                hits = result["hits"]["hits"]
                documents.extend({**hit["_source"], "_id": hit["_id"]} for hit in hits)
                if len(hits) < page_size:
                    return documents
                after = hits[-1]["sort"]
        except NotFoundError:
            if missing_index_is_empty:
                return []
            raise
        finally:
            if pit_id is not None:
                await self.client.close_point_in_time(id=pit_id)

    async def aggregate(
        self,
        index: str,
        query: dict[str, Any],
        aggregations: dict[str, Any],
        *,
        size: int = 0,
        sort: list[dict[str, str]] | None = None,
        missing_index_is_empty: bool = False,
    ) -> dict[str, Any]:
        """Run a typed analytics search without hiding non-404 failures."""
        try:
            return dict(
                await self.client.search(
                    index=index,
                    query=query,
                    aggs=aggregations,
                    size=size,
                    sort=sort,
                    track_total_hits=True,
                )
            )
        except NotFoundError:
            if missing_index_is_empty:
                return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}
            raise

    async def honeypot_counts(self) -> dict[str, int]:
        result = await self.client.search(
            index="trapsig-events-*",
            size=0,
            aggs={"honeypots": {"terms": {"field": "honeypot.id", "size": 20}}},
        )
        return {bucket["key"]: int(bucket["doc_count"]) for bucket in result["aggregations"]["honeypots"]["buckets"]}

    async def get(self, index: str, document_id: str) -> dict[str, Any] | None:
        try:
            result = await self.client.get(index=index, id=document_id)
            return {**result["_source"], "_id": result["_id"]}
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return None
            raise

    async def save(self, index: str, document_id: str, document: dict[str, Any]) -> dict[str, Any]:
        await self.client.index(index=index, id=document_id, document=document, refresh="wait_for")
        return document

    async def close(self) -> None:
        await self.client.close()


store = ElasticStore()
