import os
import uuid
from datetime import datetime

import aiofiles
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import AnalysisJob, JobStatus, User
from app.schemas.schemas import JobResponse

router = APIRouter(prefix="/upload", tags=["Upload"], dependencies=[Depends(get_current_user)])


@router.post("-log", response_model=JobResponse)
async def upload_log(
    file: UploadFile = File(...),
    log_type: str = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Upload a log file for analysis. Supports .log, .txt, .json, .jsonl, .csv files."""
    allowed_extensions = {".log", ".txt", ".json", ".jsonl", ".csv", ".gz"}
    ext = os.path.splitext(file.filename)[1].lower() if file.filename else ""
    if ext not in allowed_extensions and not file.filename.endswith(".log"):
        raise HTTPException(400, f"Unsupported file type: {ext}. Allowed: {', '.join(allowed_extensions)}")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(413, f"File too large. Maximum: {settings.MAX_UPLOAD_SIZE_MB} MB")

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    file_id = str(uuid.uuid4())
    safe_name = f"{file_id}_{file.filename}"
    file_path = os.path.join(settings.UPLOAD_DIR, safe_name)

    async with aiofiles.open(file_path, "wb") as f:
        await f.write(content)

    job = AnalysisJob(
        id=uuid.uuid4(),
        created_by_user_id=current_user.id,
        filename=file.filename,
        file_path=file_path,
        file_size=len(content),
        log_type=log_type,
        status=JobStatus.PENDING,
        created_at=datetime.utcnow(),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Dispatch background task
    try:
        from app.workers.tasks import analyze_log_file
        analyze_log_file.delay(str(job.id), file_path, log_type)
    except Exception:
        # If Celery/Redis not available, run inline (dev mode)
        job.status = JobStatus.PENDING
        job.error_message = "Background worker not available. Processing will start when workers are online."
        await db.commit()

    return JobResponse(
        id=job.id,
        filename=job.filename,
        file_size=job.file_size,
        log_type=job.log_type,
        status=job.status,
        progress=job.progress,
        total_lines=job.total_lines,
        parsed_lines=job.parsed_lines,
        created_at=job.created_at,
    )
