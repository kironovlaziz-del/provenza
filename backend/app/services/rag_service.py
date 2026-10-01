"""
RAG (Retrieval-Augmented Generation) engine.

Pipeline: upload a document -> extract text -> chunk -> embed -> store.
At query time: embed the question -> cosine-similarity search over the
collection's chunks -> feed the top matches to an LLM as context.

Embedding providers
--------------------
Two interchangeable providers, selected automatically (see
get_embedding_provider()):

- "tfidf" (always available): scikit-learn's TfidfVectorizer, already a
  hard dependency of this project. Works out of the box on any box,
  no GPU, no ~2GB torch install. Quality is "classic IR", good enough
  for FAQ-style matching. Because the vectorizer's vocabulary/IDF
  weights are fit on the collection's own corpus, it is NOT stateless:
  the fitted vectorizer must be persisted (DocumentCollection.vectorizer_path)
  and reloaded for every query, and re-fit (over the WHOLE corpus) every
  time a document is added or removed, so all chunks in a collection stay
  in the same vector space.
- "sentence_transformer" (optional upgrade): only used if the optional ML
  stack (see requirements-ml.txt) happens to be installed. Pretrained,
  stateless - no fitting or persistence needed. Lazily imported so a box
  without the optional stack never even attempts to import torch, same
  pattern as app/services/transformer_models.py and compute_detector.py.

A collection always keeps using whichever provider it was built with
(DocumentCollection.embedding_provider) even if the box's available
providers change later - mixing vector spaces silently would produce
meaningless similarity scores.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import numpy as np

logger = logging.getLogger("rag_service")


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------

SUPPORTED_FILE_TYPES = {"pdf", "docx", "txt"}


def extract_text(file_path: str, file_type: str) -> str:
    if file_type == "pdf":
        return _extract_pdf(file_path)
    if file_type == "docx":
        return _extract_docx(file_path)
    if file_type == "txt":
        return Path(file_path).read_text(encoding="utf-8", errors="replace")
    raise ValueError(f"Unsupported file type for text extraction: {file_type}")


def _extract_pdf(file_path: str) -> str:
    from pypdf import PdfReader

    reader = PdfReader(file_path)
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n\n".join(pages)


def _extract_docx(file_path: str) -> str:
    import docx

    doc = docx.Document(file_path)
    return "\n\n".join(p.text for p in doc.paragraphs if p.text.strip())


# ---------------------------------------------------------------------------
# Chunking - word-count based sliding window. Word count rather than a
# token count avoids pulling in a tokenizer dependency; it is an
# approximation, which is fine since chunk size here only needs to be
# "roughly a paragraph or two", not an exact token budget.
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_WORDS = 220
DEFAULT_CHUNK_OVERLAP_WORDS = 40


def chunk_text(
    text: str,
    chunk_words: int = DEFAULT_CHUNK_WORDS,
    overlap_words: int = DEFAULT_CHUNK_OVERLAP_WORDS,
) -> List[str]:
    # Collapse excess whitespace so word-splitting is meaningful, and drop
    # blank chunks that would otherwise arise from extraction artifacts.
    normalized = re.sub(r"\s+", " ", text).strip()
    if not normalized:
        return []

    words = normalized.split(" ")
    if len(words) <= chunk_words:
        return [normalized]

    chunks = []
    step = max(chunk_words - overlap_words, 1)
    for start in range(0, len(words), step):
        chunk_words_slice = words[start : start + chunk_words]
        if not chunk_words_slice:
            break
        chunks.append(" ".join(chunk_words_slice))
        if start + chunk_words >= len(words):
            break
    return chunks


# ---------------------------------------------------------------------------
# Embedding providers
# ---------------------------------------------------------------------------

class EmbeddingProvider:
    name: str = "base"

    def embed_corpus(self, texts: List[str], persist_path: Optional[str]) -> List[List[float]]:
        raise NotImplementedError

    def embed_query(self, text: str, persist_path: Optional[str]) -> List[float]:
        raise NotImplementedError


class TfidfEmbeddingProvider(EmbeddingProvider):
    name = "tfidf"

    def embed_corpus(self, texts: List[str], persist_path: Optional[str]) -> List[List[float]]:
        from sklearn.feature_extraction.text import TfidfVectorizer

        if not texts:
            return []
        # Character n-grams (within word boundaries) rather than whole-word
        # tokens: this project's users are largely Russian/Uzbek-speaking
        # (see the Simple Mode wizard's own examples), and those are
        # morphologically rich languages - inflected word forms are
        # different word forms that a word-level TF-IDF (with no
        # stemmer/lemmatizer) would treat as entirely unrelated tokens,
        # silently returning zero matches for a question phrased in a
        # different grammatical case than the source document. Character
        # n-grams share overlapping substrings between such word forms
        # and work reasonably well across languages/scripts without
        # needing a language-specific stemming dependency.
        vectorizer = TfidfVectorizer(
            max_features=50000, analyzer="char_wb", ngram_range=(3, 5)
        )
        matrix = vectorizer.fit_transform(texts)
        if persist_path:
            Path(persist_path).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(vectorizer, persist_path)
        return matrix.toarray().tolist()

    def embed_query(self, text: str, persist_path: Optional[str]) -> List[float]:
        if not persist_path or not Path(persist_path).exists():
            raise RuntimeError(
                "No fitted TF-IDF vectorizer found for this collection - "
                "add at least one document before querying it."
            )
        vectorizer = joblib.load(persist_path)
        vector = vectorizer.transform([text])
        return vector.toarray()[0].tolist()


class SentenceTransformerEmbeddingProvider(EmbeddingProvider):
    name = "sentence_transformer"

    _model = None  # loaded lazily and cached for the life of the process

    def _get_model(self):
        if SentenceTransformerEmbeddingProvider._model is None:
            from sentence_transformers import SentenceTransformer

            SentenceTransformerEmbeddingProvider._model = SentenceTransformer(
                "all-MiniLM-L6-v2"
            )
        return SentenceTransformerEmbeddingProvider._model

    def embed_corpus(self, texts: List[str], persist_path: Optional[str]) -> List[List[float]]:
        if not texts:
            return []
        model = self._get_model()
        return model.encode(texts, convert_to_numpy=True).tolist()

    def embed_query(self, text: str, persist_path: Optional[str]) -> List[float]:
        model = self._get_model()
        return model.encode([text], convert_to_numpy=True)[0].tolist()


def neural_embeddings_available() -> bool:
    """
    True only if the optional ML stack AND sentence-transformers are both
    importable. Mirrors the lazy-detection pattern in compute_detector.py
    and transformer_models.py: never import torch at module load time,
    only when actually asked whether it's there.
    """
    if "sentence_transformers" in sys.modules and sys.modules["sentence_transformers"] is None:
        return False
    try:
        import sentence_transformers  # noqa: F401
        import torch  # noqa: F401

        return True
    except ImportError:
        return False


def get_embedding_provider(preferred: Optional[str] = None) -> EmbeddingProvider:
    """
    preferred: pass an existing collection's embedding_provider to keep
    using the same provider it was built with, regardless of what else is
    available on this box now. Pass None to pick the best available
    provider for a brand-new collection.
    """
    if preferred == "sentence_transformer":
        return SentenceTransformerEmbeddingProvider()
    if preferred == "tfidf":
        return TfidfEmbeddingProvider()
    if preferred is not None:
        raise ValueError(f"Unknown embedding provider: {preferred}")

    if neural_embeddings_available():
        return SentenceTransformerEmbeddingProvider()
    return TfidfEmbeddingProvider()


# ---------------------------------------------------------------------------
# Similarity search - brute-force cosine similarity (see DocumentChunk's
# docstring for the scale reasoning).
# ---------------------------------------------------------------------------

@dataclass
class ScoredChunk:
    chunk_id: int
    document_id: int
    text: str
    score: float


def top_k_by_cosine_similarity(
    query_vector: List[float],
    candidates: List[Tuple[int, int, str, List[float]]],
    k: int,
) -> List[ScoredChunk]:
    """candidates: list of (chunk_id, document_id, text, embedding)."""
    if not candidates:
        return []

    query = np.array(query_vector, dtype=np.float64)
    query_norm = np.linalg.norm(query)
    if query_norm == 0:
        return []

    matrix = np.array([c[3] for c in candidates], dtype=np.float64)
    norms = np.linalg.norm(matrix, axis=1)
    # Avoid division by zero for any all-zero embedding rows (e.g. a chunk
    # of pure stop-words under TF-IDF) - they simply score 0 similarity
    # rather than producing NaN.
    safe_norms = np.where(norms == 0, 1, norms)
    similarities = (matrix @ query) / (safe_norms * query_norm)
    similarities = np.where(norms == 0, 0, similarities)

    top_indices = np.argsort(-similarities)[:k]
    return [
        ScoredChunk(
            chunk_id=candidates[i][0],
            document_id=candidates[i][1],
            text=candidates[i][2],
            score=float(similarities[i]),
        )
        for i in top_indices
    ]


# ---------------------------------------------------------------------------
# RAGService - DB orchestration: ingestion pipeline + retrieval + chat.
# ---------------------------------------------------------------------------

from fastapi import HTTPException, UploadFile, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt_secret
from app.models.ai_provider import AIProvider
from app.models.document_chunk import DocumentChunk
from app.models.document_collection import DocumentCollection
from app.models.rag_document import Document
from app.services import provider_adapters

MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB - RAG documents are processed
# synchronously (extraction + chunking + embedding all happen inline in
# the request, for the "instant magic" UX the wizard wants rather than a
# spinner-and-poll flow), so this cap keeps worst-case request time bounded.

DEFAULT_TOP_K = 4


def _safe_filename(filename: str) -> str:
    name = os.path.basename(filename or "document")
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return name or "document"


class RAGService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # -- collections ---------------------------------------------------

    async def create_collection(
        self,
        org_id: int,
        created_by: int,
        name: str,
        description: Optional[str],
        system_prompt: Optional[str] = None,
    ) -> DocumentCollection:
        collection = DocumentCollection(
            org_id=org_id,
            name=name,
            description=description,
            embedding_provider=get_embedding_provider().name,
            system_prompt=system_prompt,
        )
        self.db.add(collection)
        await self.db.commit()
        await self.db.refresh(collection)
        return collection

    async def list_collections(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> Tuple[List[DocumentCollection], int]:
        base = select(DocumentCollection).where(DocumentCollection.org_id == org_id)
        total = await self.db.scalar(select(func.count()).select_from(base.subquery()))
        result = await self.db.execute(
            base.order_by(DocumentCollection.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def get_collection(self, collection_id: int, org_id: int) -> DocumentCollection:
        result = await self.db.execute(
            select(DocumentCollection).where(
                DocumentCollection.id == collection_id, DocumentCollection.org_id == org_id
            )
        )
        collection = result.scalar_one_or_none()
        if not collection:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Document collection not found"
            )
        return collection

    async def delete_collection(self, collection_id: int, org_id: int) -> None:
        collection = await self.get_collection(collection_id, org_id)
        docs = await self.list_documents(collection_id, org_id)
        for doc in docs:
            try:
                os.remove(doc.file_path)
            except OSError:
                pass  # already gone - fine, we're deleting anyway
        if collection.vectorizer_path:
            try:
                os.remove(collection.vectorizer_path)
            except OSError:
                pass
        await self.db.delete(collection)  # cascades to documents/chunks via FK ondelete below
        await self.db.commit()

    # -- documents -------------------------------------------------------

    def _org_collection_dir(self, org_id: int, collection_id: int) -> Path:
        path = Path(settings.RAG_DOCUMENTS_DIR) / str(org_id) / str(collection_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    async def list_documents(self, collection_id: int, org_id: int) -> List[Document]:
        result = await self.db.execute(
            select(Document)
            .where(Document.collection_id == collection_id, Document.org_id == org_id)
            .order_by(Document.created_at.desc())
        )
        return list(result.scalars().all())

    async def _all_chunks(self, collection_id: int) -> List[DocumentChunk]:
        result = await self.db.execute(
            select(DocumentChunk)
            .where(DocumentChunk.collection_id == collection_id)
            .order_by(DocumentChunk.document_id, DocumentChunk.chunk_index)
        )
        return list(result.scalars().all())

    async def add_document(
        self, collection_id: int, org_id: int, uploaded_by: int, file: UploadFile
    ) -> Document:
        collection = await self.get_collection(collection_id, org_id)

        safe_name = _safe_filename(file.filename or "document")
        ext = Path(safe_name).suffix.lower().lstrip(".")
        if ext not in SUPPORTED_FILE_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type '.{ext}'. Allowed: "
                f"{', '.join(sorted(SUPPORTED_FILE_TYPES))}",
            )

        dest_dir = self._org_collection_dir(org_id, collection_id)
        stored_name = f"{uuid.uuid4().hex}_{safe_name}"
        dest_path = dest_dir / stored_name

        size_bytes = 0
        with open(dest_path, "wb") as out_file:
            while True:
                block = await file.read(1024 * 1024)
                if not block:
                    break
                size_bytes += len(block)
                if size_bytes > MAX_UPLOAD_BYTES:
                    out_file.close()
                    os.remove(dest_path)
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit "
                        "for a single document.",
                    )
                out_file.write(block)

        return await self._ingest_saved_file(
            collection, org_id, uploaded_by, dest_path, ext, size_bytes, safe_name
        )

    async def add_qa_pairs_as_document(
        self,
        collection_id: int,
        org_id: int,
        uploaded_by: int,
        pairs: List[Tuple[str, str]],
        filename: str = "wizard_qa_pairs.txt",
    ) -> Document:
        """
        Simple Mode wizard's "rag_few_shot" approach (see
        approach_recommender.py): the person's own Q&A pairs get indexed
        as a document too, not just kept as ad-hoc few-shot examples -
        this makes them retrievable like any other knowledge (a future
        question similar to one of these pairs will actually surface the
        matching pair via normal search), on top of whatever few-shot
        prompting the caller layers in separately.
        """
        collection = await self.get_collection(collection_id, org_id)
        text = "\n\n".join(f"Q: {q}\nA: {a}" for q, a in pairs)

        dest_dir = self._org_collection_dir(org_id, collection_id)
        safe_name = _safe_filename(filename)
        stored_name = f"{uuid.uuid4().hex}_{safe_name}"
        dest_path = dest_dir / stored_name
        dest_path.write_text(text, encoding="utf-8")
        size_bytes = dest_path.stat().st_size

        return await self._ingest_saved_file(
            collection, org_id, uploaded_by, dest_path, "txt", size_bytes, safe_name
        )

    async def _ingest_saved_file(
        self,
        collection: DocumentCollection,
        org_id: int,
        uploaded_by: int,
        dest_path: Path,
        ext: str,
        size_bytes: int,
        filename: str,
    ) -> Document:
        collection_id = collection.id
        document = Document(
            org_id=org_id,
            collection_id=collection_id,
            filename=filename,
            file_path=str(dest_path),
            file_type=ext,
            size_bytes=size_bytes,
            status="processing",
            uploaded_by=uploaded_by,
        )
        self.db.add(document)
        await self.db.commit()
        await self.db.refresh(document)

        # Extraction/chunking/embedding failures are recorded on the
        # document (status="failed") rather than raised as a 500 - the
        # upload itself succeeded, and the wizard UX wants to show
        # "couldn't read this file" gracefully, not a server error page.
        #
        # The document row above is committed BEFORE this block runs
        # (not just flushed) specifically so that if something below
        # fails and we roll back, we are only rolling back the
        # in-progress chunk inserts / collection counter updates - never
        # the document row itself, which must stay addressable so we can
        # attach the failure status to it afterwards.
        try:
            text = extract_text(str(dest_path), ext)
            new_chunk_texts = chunk_text(text)
            if not new_chunk_texts:
                raise ValueError(
                    "No extractable text found in this file "
                    "(it may be a scanned/image-only document)."
                )

            provider = get_embedding_provider(preferred=collection.embedding_provider)

            if provider.name == "tfidf":
                await self._add_document_tfidf(collection, document, new_chunk_texts, provider)
            else:
                await self._add_document_stateless(
                    collection, document, new_chunk_texts, provider
                )

            # ASI06: scan the new chunks; poisoned ones are quarantined in enforce mode
            from app.services.memory_guard import MemoryGuard
            await MemoryGuard(self.db).scan_document(org_id, document)

            document.status = "ready"
            document.chunk_count = len(new_chunk_texts)
            collection.document_count = (collection.document_count or 0) + 1
            collection.chunk_count = len(await self._all_chunks(collection_id))
            await self.db.commit()
            await self.db.refresh(document)
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see comment above
            await self.db.rollback()
            document.status = "failed"
            document.error_message = str(exc)[:2000]
            self.db.add(document)
            await self.db.commit()
            await self.db.refresh(document)
            logger.warning("RAG document ingestion failed for %s: %s", dest_path, exc)

        return document

    async def _add_document_tfidf(
        self,
        collection: DocumentCollection,
        document: Document,
        new_chunk_texts: List[str],
        provider: EmbeddingProvider,
    ) -> None:
        """TF-IDF's vocabulary is corpus-wide, so adding a document means
        refitting over every chunk in the collection (old + new) and
        rewriting every existing chunk's embedding, not just adding new
        rows - otherwise old and new chunks would live in incomparable
        vector spaces."""
        existing_chunks = await self._all_chunks(collection.id)
        all_texts = [c.text for c in existing_chunks] + new_chunk_texts

        vectorizer_path = collection.vectorizer_path or str(
            Path(settings.RAG_VECTORIZERS_DIR) / f"collection_{collection.id}.joblib"
        )
        vectors = provider.embed_corpus(all_texts, persist_path=vectorizer_path)

        for chunk_row, vector in zip(existing_chunks, vectors[: len(existing_chunks)]):
            chunk_row.embedding = vector

        new_vectors = vectors[len(existing_chunks) :]
        for i, (text, vector) in enumerate(zip(new_chunk_texts, new_vectors)):
            self.db.add(
                DocumentChunk(
                    org_id=document.org_id,
                    collection_id=collection.id,
                    document_id=document.id,
                    chunk_index=i,
                    text=text,
                    embedding=vector,
                )
            )

        collection.vectorizer_path = vectorizer_path
        collection.embedding_provider = provider.name

    async def _add_document_stateless(
        self,
        collection: DocumentCollection,
        document: Document,
        new_chunk_texts: List[str],
        provider: EmbeddingProvider,
    ) -> None:
        """Neural embedders are pretrained and stateless: no refit, no
        persisted vectorizer, existing chunks are untouched."""
        vectors = provider.embed_corpus(new_chunk_texts, persist_path=None)
        for i, (text, vector) in enumerate(zip(new_chunk_texts, vectors)):
            self.db.add(
                DocumentChunk(
                    org_id=document.org_id,
                    collection_id=collection.id,
                    document_id=document.id,
                    chunk_index=i,
                    text=text,
                    embedding=vector,
                )
            )
        collection.embedding_provider = provider.name

    async def delete_document(self, document_id: int, collection_id: int, org_id: int) -> None:
        result = await self.db.execute(
            select(Document).where(
                Document.id == document_id,
                Document.collection_id == collection_id,
                Document.org_id == org_id,
            )
        )
        document = result.scalar_one_or_none()
        if not document:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

        collection = await self.get_collection(collection_id, org_id)

        try:
            os.remove(document.file_path)
        except OSError:
            pass

        await self.db.delete(document)
        await self.db.flush()

        # Same reasoning as ingestion: removing a document changes the
        # TF-IDF corpus, so the remaining chunks must be re-embedded in
        # the same pass, not left stale.
        if collection.embedding_provider == "tfidf":
            remaining_chunks = await self._all_chunks(collection_id)
            if remaining_chunks:
                provider = get_embedding_provider(preferred="tfidf")
                vectors = provider.embed_corpus(
                    [c.text for c in remaining_chunks], persist_path=collection.vectorizer_path
                )
                for chunk_row, vector in zip(remaining_chunks, vectors):
                    chunk_row.embedding = vector
            elif collection.vectorizer_path:
                try:
                    os.remove(collection.vectorizer_path)
                except OSError:
                    pass
                collection.vectorizer_path = None

        collection.document_count = max((collection.document_count or 1) - 1, 0)
        collection.chunk_count = len(await self._all_chunks(collection_id))
        await self.db.commit()

    # -- retrieval + chat --------------------------------------------------

    async def query(
        self, collection_id: int, org_id: int, question: str, top_k: int = DEFAULT_TOP_K
    ) -> List[ScoredChunk]:
        collection = await self.get_collection(collection_id, org_id)
        # AI Inventory: a retired knowledge base no longer answers
        from app.services.inventory_service import ensure_collection_not_retired
        await ensure_collection_not_retired(self.db, org_id, collection_id)
        # ASI06: quarantined / revoked chunks never reach a prompt. Filtered here,
        # not in _all_chunks: TF-IDF refits must still see the whole corpus.
        chunks = [c for c in await self._all_chunks(collection_id)
                  if (getattr(c, "trust_status", None) or "trusted") == "trusted"]
        if not chunks:
            return []

        provider = get_embedding_provider(preferred=collection.embedding_provider)
        query_vector = provider.embed_query(question, persist_path=collection.vectorizer_path)

        candidates = [(c.id, c.document_id, c.text, c.embedding) for c in chunks]
        return top_k_by_cosine_similarity(query_vector, candidates, top_k)

    async def chat(
        self,
        collection_id: int,
        org_id: int,
        question: str,
        provider_id: int,
        top_k: int = DEFAULT_TOP_K,
        few_shot_examples: Optional[List[Tuple[str, str]]] = None,
    ) -> Tuple[str, List[ScoredChunk]]:
        collection = await self.get_collection(collection_id, org_id)
        matches = await self.query(collection_id, org_id, question, top_k)

        result = await self.db.execute(
            select(AIProvider).where(AIProvider.id == provider_id, AIProvider.org_id == org_id)
        )
        provider_row = result.scalar_one_or_none()
        if not provider_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

        # The collection's own personality (Simple Mode wizard screen 7,
        # persisted at creation time) always applies; few_shot_examples is
        # an additional, caller-supplied layer on top (used by the wizard's
        # "rag_few_shot" approach), not a replacement for it.
        personality_block = f"{collection.system_prompt}\n\n" if collection.system_prompt else ""

        few_shot_block = ""
        if few_shot_examples:
            examples_text = "\n\n".join(
                f"Q: {q}\nA: {a}" for q, a in few_shot_examples
            )
            few_shot_block = (
                "Here are examples of how questions like this have been "
                f"answered before - match this tone and phrasing:\n\n{examples_text}\n\n"
            )

        if matches:
            context = "\n\n---\n\n".join(m.text for m in matches)
            prompt = (
                f"{personality_block}"
                f"{few_shot_block}"
                "Answer the question using ONLY the context below. If the "
                "context does not contain the answer, say you don't know "
                "rather than guessing.\n\n"
                f"Context:\n{context}\n\nQuestion: {question}\nAnswer:"
            )
        else:
            # Nothing indexed yet, or no relevant chunk - still answer, but
            # make the model's lack of grounding explicit rather than
            # silently sending a context-free prompt that looks the same
            # as a grounded one.
            prompt = (
                f"{personality_block}"
                f"{few_shot_block}"
                "No relevant documents were found in the knowledge base for "
                f"this question. Say so plainly, then answer briefly if you "
                f"can from general knowledge.\n\nQuestion: {question}\nAnswer:"
            )

        api_key = decrypt_secret(provider_row.api_key_encrypted) if provider_row.api_key_encrypted else None
        answer, _raw = await provider_adapters.call_provider(
            provider_row.type, api_key, provider_row.base_url, provider_row.default_model, prompt
        )
        return answer, matches

