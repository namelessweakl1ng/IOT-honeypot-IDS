from fastapi import HTTPException
from ..elastic import store
async def one(index: str, document_id: str):
    document=await store.get(index,document_id)
    if document is None: raise HTTPException(404,"document not found")
    return document
