from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import FileResponse, StreamingResponse
from starlette.background import BackgroundTask
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from pathlib import Path
import jwt
from jwt import PyJWTError as JWTError
import os
import asyncio
import json
import re
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone

from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.core.config import settings
from app.schemas.training_job import (
    TrainingJobCreate,
    TrainingJobOut,
    PredictRequest,
    PredictResponse,
)
from app.schemas.pagination import Page
from app.services import ml_algorithms
from app.services.training_service import TrainingService
from app.services.audit_service import AuditService
from app.models.user import User
from app.models.training_job import TrainingJob
from app.api.deps import get_current_user

router = APIRouter()

@router.get("/algorithms")
async def list_algorithms(task_type: str | None = None):
    """
    Registry of sklearn algorithms available for the Training Service.
    The frontend uses this to render the algorithm dropdown and the
    hyperparameter form dynamically, so adding a new algorithm on the
    backend does not require a frontend rebuild.
    """
    return {"algorithms": ml_algorithms.list_algorithms(task_type)}


# Short-lived token used for <a href> downloads - an <a> tag cannot send
# an Authorization header, so we sign a one-shot URL instead.
DOWNLOAD_TOKEN_TTL_SECONDS = 120


def _make_download_token(job_id: int, org_id: int) -> str:
    payload = {
        "sub": f"download:{job_id}",
        "org": org_id,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=DOWNLOAD_TOKEN_TTL_SECONDS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _verify_download_token(token: str, job_id: int) -> int:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired download token.",
        )
    if payload.get("sub") != f"download:{job_id}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Download token does not match this job.",
        )
    return int(payload["org"])


@router.get("/{job_id}/stream")
async def stream_training_progress(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Server-Sent Events stream of training progress for a specific job.

    First frame is a snapshot of the current state pulled from the DB
    (so a client that opens the stream after the job started does not
    wait for the next tick). Subsequent frames are pushed by the Celery
    worker via Redis pub/sub.

    Closes automatically once the job reaches a terminal status.
    """
    # Validate ownership and capture the initial snapshot.
    service = TrainingService(db)
    job = await service.get_job(job_id, current_user.org_id)

    initial = {
        "pct": job.progress_pct,
        "stage": job.progress_stage,
        "status": job.status,
    }
    terminal = {"completed", "failed", "cancelled"}

    async def event_stream():
        # Frame 1: current state.
        yield f"data: {json.dumps(initial)}\n\n"

        if initial["status"] in terminal:
            yield f"event: end\ndata: {json.dumps({'status': initial['status']})}\n\n"
            return

        from app.core import events

        # Heartbeat every 15s so proxies don't drop the connection.
        try:
            iterator = events.subscribe_progress(job_id).__aiter__()
            while True:
                try:
                    payload = await asyncio.wait_for(
                        iterator.__anext__(), timeout=15.0
                    )
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                except StopAsyncIteration:
                    break

                yield f"data: {json.dumps(payload)}\n\n"

                if payload.get("status") in terminal:
                    yield f"event: end\ndata: {json.dumps({'status': payload['status']})}\n\n"
                    break
        finally:
            try:
                await iterator.aclose()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disables nginx buffering
            "Connection": "keep-alive",
        },
    )


@router.post("/", response_model=TrainingJobOut)
async def create_training_job(
    data: TrainingJobCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = TrainingService(db)
    job = await service.create_job(current_user.org_id, current_user.id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "training_job", job.id, "created",
        {"name": job.name, "algorithm": job.algorithm, "dataset_id": job.dataset_id},
    )
    return job


@router.get("/", response_model=Page[TrainingJobOut])
async def list_training_jobs(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = TrainingService(db)
    items, total = await service.list_jobs(
        current_user.org_id, skip=pagination.skip, limit=pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.get("/{job_id}", response_model=TrainingJobOut)
async def get_training_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = TrainingService(db)
    return await service.get_job(job_id, current_user.org_id)


@router.post("/{job_id}/cancel", response_model=TrainingJobOut)
async def cancel_training_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = TrainingService(db)
    job = await service.cancel_job(job_id, current_user.org_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "training_job", job.id, "cancelled", None,
    )
    return job


@router.post("/{job_id}/retry", response_model=TrainingJobOut)
async def retry_training_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = TrainingService(db)
    job = await service.retry_job(job_id, current_user.org_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "training_job", job.id, "retried", None,
    )
    return job


@router.post("/{job_id}/predict", response_model=PredictResponse)
async def predict(
    job_id: int,
    data: PredictRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = TrainingService(db)
    prediction = await service.predict(job_id, current_user.org_id, data.features)
    return PredictResponse(prediction=prediction)


@router.post("/{job_id}/download-token")
async def issue_download_token(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Issue a short-lived, single-purpose JWT that can be used in an <a href>
    to stream the model file without buffering it in browser memory.
    """
    service = TrainingService(db)
    await service.get_job(job_id, current_user.org_id)  # 404 if not ours
    token = _make_download_token(job_id, current_user.org_id)
    return {"token": token, "expires_in": DOWNLOAD_TOKEN_TTL_SECONDS}


@router.get("/{job_id}/download")
async def download_model(
    job_id: int,
    token: str = Query(..., description="Short-lived download token from /download-token"),
    db: AsyncSession = Depends(get_db),
):
    """
    Streaming download endpoint. The token in the query string replaces
    the Authorization header so a plain <a href> works, and the file is
    served by Starlette's FileResponse in chunks - no full-file buffering.
    """
    org_id = _verify_download_token(token, job_id)

    result = await db.execute(
        select_training_job(job_id, org_id)
    )
    job = result.scalar_one_or_none()
    if not job or job.status != "completed" or not job.model_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This training job has no completed model to download.",
        )

    model_path = Path(job.model_path)
    if not model_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Model artifact is missing on disk.",
        )

    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", job.name) or f"job_{job.id}"

    await AuditService(db).log(
        org_id, None, "training_job", job.id, "downloaded", None,
    )

    if model_path.is_file():
        return FileResponse(
            path=str(model_path),
            filename=f"{safe_name}.joblib",
            media_type="application/octet-stream",
        )

    tmp_fd, tmp_path_str = tempfile.mkstemp(suffix=".zip")
    os.close(tmp_fd)
    tmp_path = Path(tmp_path_str)
    with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in model_path.rglob("*"):
            if file.is_file() and "_trainer_tmp" not in file.parts:
                zf.write(file, arcname=file.relative_to(model_path))

    return FileResponse(
        path=str(tmp_path),
        filename=f"{safe_name}.zip",
        media_type="application/zip",
        background=BackgroundTask(lambda: tmp_path.unlink(missing_ok=True)),
    )


# Local helper to keep the import list clean and avoid a top-level circular
def select_training_job(job_id: int, org_id: int):
    from sqlalchemy import select

    return select(TrainingJob).where(
        TrainingJob.id == job_id, TrainingJob.org_id == org_id
    )
