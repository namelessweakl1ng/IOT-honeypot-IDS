import asyncio
from backend.app.services.processor import EventProcessor
from tests.ingestion.test_pipeline_contracts import cowrie


class Store:
    def __init__(self):
        self.documents = {}
    async def search(self, index, query=None, size=100):
        return [cowrie(str(i), second=i) for i in range(5)]
    async def save(self, index, document_id, document):
        self.documents[(index, document_id)] = document
        return document


def test_processor_materializes_and_idempotently_upserts():
    asyncio.run(run_processor_test())


async def run_processor_test():
    store = Store()
    processor = EventProcessor(store)
    first = await processor.process_once()
    count = len(store.documents)
    second = await processor.process_once()
    assert first == second == {"sessions": 1, "detections": 1}
    assert len(store.documents) == count
    assert any(index == "trapsig-sessions" for index, _ in store.documents)
    assert any(index == "trapsig-detections" for index, _ in store.documents)
