from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.schemas.rag import (
    ApproachRecommendationRequest,
    ApproachRecommendationResponse,
    DocumentCollectionCreate,
    DocumentCollectionOut,
    DocumentOut,
    RAGChatRequest,
    RAGChatResponse,
    RAGQueryRequest,
    RAGQueryResponse,
    RAGSourceChunk,
)
from app.schemas.pagination import Page
from app.services.rag_service import RAGService
from app.services.approach_recommender import recommend_approach
from app.services.audit_service import AuditService
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()


@router.post("/recommend-approach", response_model=ApproachRecommendationResponse)
async def recommend_approach_endpoint(
    data: ApproachRecommendationRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Simple Mode wizard step (screen 6, right after data parsing): the
    system decides RAG vs fine-tuning on its own from the task type and
    data shape, per the plan's design principle - the person never sees
    this as a choice, only the "Continue" button.
    """
    result = recommend_approach(data.task_type, data.has_documents, data.qa_pair_count)
    return ApproachRecommendationResponse(approach=result.approach, reason=result.reason)


@router.post("/collections/", response_model=DocumentCollectionOut)
async def create_collection(
    data: DocumentCollectionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    collection = await service.create_collection(
        current_user.org_id, current_user.id, data.name, data.description, data.system_prompt
    )
    await AuditService(db).log(
        current_user.org_id, current_user.id, "document_collection", collection.id, "created",
        {"name": collection.name, "embedding_provider": collection.embedding_provider},
    )
    return collection


@router.get("/collections/", response_model=Page[DocumentCollectionOut])
async def list_collections(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    items, total = await service.list_collections(
        current_user.org_id, skip=pagination.skip, limit=pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.get("/collections/{collection_id}", response_model=DocumentCollectionOut)
async def get_collection(
    collection_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    return await service.get_collection(collection_id, current_user.org_id)


@router.delete("/collections/{collection_id}")
async def delete_collection(
    collection_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    await service.delete_collection(collection_id, current_user.org_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "document_collection", collection_id, "deleted", None,
    )
    return {"status": "deleted"}


@router.post("/collections/{collection_id}/documents", response_model=DocumentOut)
async def upload_document(
    collection_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    document = await service.add_document(
        collection_id, current_user.org_id, current_user.id, file
    )
    await AuditService(db).log(
        current_user.org_id, current_user.id, "rag_document", document.id, "created",
        {"filename": document.filename, "status": document.status},
    )
    return document


@router.get("/collections/{collection_id}/documents", response_model=list[DocumentOut])
async def list_documents(
    collection_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    # Ensures the collection exists (and belongs to this org) before
    # listing, so a bad collection_id 404s instead of silently returning [].
    await service.get_collection(collection_id, current_user.org_id)
    return await service.list_documents(collection_id, current_user.org_id)


@router.delete("/collections/{collection_id}/documents/{document_id}")
async def delete_document(
    collection_id: int,
    document_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    await service.delete_document(document_id, collection_id, current_user.org_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "rag_document", document_id, "deleted", None,
    )
    return {"status": "deleted"}


@router.post("/collections/{collection_id}/query", response_model=RAGQueryResponse)
async def query_collection(
    collection_id: int,
    data: RAGQueryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieval only, no LLM call - useful for debugging what a
    collection would surface for a given question."""
    service = RAGService(db)
    import time as _time
    from app.services.rag_query_log import log_rag_query
    _started = _time.monotonic()
    matches = await service.query(collection_id, current_user.org_id, data.question, data.top_k)
    await log_rag_query(db, current_user.org_id, collection_id, current_user.id, "query", data.question,
                        matches, _started, top_k=data.top_k)
    return RAGQueryResponse(
        matches=[
            RAGSourceChunk(
                chunk_id=m.chunk_id, document_id=m.document_id, text=m.text, score=m.score
            )
            for m in matches
        ]
    )


@router.post("/collections/{collection_id}/chat", response_model=RAGChatResponse)
async def chat_with_collection(
    collection_id: int,
    data: RAGChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = RAGService(db)
    few_shot = (
        [(ex.question, ex.answer) for ex in data.few_shot_examples]
        if data.few_shot_examples
        else None
    )
    import time as _time
    from app.services.rag_query_log import log_rag_query
    _started = _time.monotonic()
    answer, matches = await service.chat(
        collection_id,
        current_user.org_id,
        data.message,
        data.provider_id,
        data.top_k,
        few_shot_examples=few_shot,
    )
    await log_rag_query(db, current_user.org_id, collection_id, current_user.id, "chat", data.message,
                        matches, _started, top_k=data.top_k, provider_id=data.provider_id)
    return RAGChatResponse(
        answer=answer,
        sources=[
            RAGSourceChunk(
                chunk_id=m.chunk_id, document_id=m.document_id, text=m.text, score=m.score
            )
            for m in matches
        ],
    )
