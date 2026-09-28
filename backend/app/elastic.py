from typing import Any
from elasticsearch import AsyncElasticsearch
from .config import get_settings

class ElasticStore:
    def __init__(self) -> None:
        settings = get_settings()
        kwargs = {"basic_auth": ("elastic", settings.elastic_password)} if settings.elastic_password else {}
        self.client = AsyncElasticsearch(settings.elasticsearch_url, **kwargs)

    async def health(self) -> dict[str, Any]:
        return dict(await self.client.cluster.health())

    async def search(self, index: str, query: dict[str, Any] | None = None, size: int = 100) -> list[dict[str, Any]]:
        result = await self.client.search(index=index, query=query or {"match_all": {}}, size=size, sort=[{"@timestamp": "desc"}])
        return [{**hit["_source"], "_id": hit["_id"]} for hit in result["hits"]["hits"]]

    async def get(self, index: str, document_id: str) -> dict[str, Any] | None:
        try:
            result = await self.client.get(index=index, id=document_id)
            return {**result["_source"], "_id": result["_id"]}
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404: return None
            raise

    async def save(self, index: str, document_id: str, document: dict[str, Any]) -> dict[str, Any]:
        await self.client.index(index=index, id=document_id, document=document, refresh="wait_for")
        return document

    async def close(self) -> None: await self.client.close()

store = ElasticStore()
