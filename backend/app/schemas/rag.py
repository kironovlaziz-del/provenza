from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class DocumentCollectionCreate(BaseModel):
    name: str
    description: Optional[str] = None


class DocumentCollectionOut(BaseModel):
    id: int
    org_id: int
    name: str
    description: Optional[str]
    embedding_provider: str
    document_count: int
    chunk_count: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class DocumentOut(BaseModel):
    id: int
    org_id: int
    collection_id: int
    filename: str
    file_type: str
    size_bytes: Optional[int]
    status: str
    error_message: Optional[str]
    chunk_count: int
    trust_status: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class QAPair(BaseModel):
    question: str
    answer: str


class RAGChatRequest(BaseModel):
    message: str
    provider_id: int
    top_k: int = 4
    # Populated only for the "rag_few_shot" approach (see
    # approach_recommender.py) - a handful of the org's own Q&A examples,
    # included directly in the prompt so a small example set still shapes
    # tone/phrasing even though it's too small to fine-tune on.
    few_shot_examples: Optional[List[QAPair]] = None


class RAGSourceChunk(BaseModel):
    chunk_id: int
    document_id: int
    text: str
    score: float


class RAGChatResponse(BaseModel):
    answer: str
    sources: List[RAGSourceChunk]


class RAGQueryRequest(BaseModel):
    question: str
    top_k: int = 4


class RAGQueryResponse(BaseModel):
    matches: List[RAGSourceChunk]


class ApproachRecommendationRequest(BaseModel):
    task_type: str  # support_qa, style_writing, classification, other
    has_documents: bool = False
    qa_pair_count: int = 0


class ApproachRecommendationResponse(BaseModel):
    approach: str
    reason: str
