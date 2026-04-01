"""Synchronous analysis endpoint for development/demo when Celery is not available.
Optimized for large files: streaming parse, batch DB inserts, sampled detection."""
import os
import uuid
from datetime import datetime

import aiofiles
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from sqlalchemy import text

from app.core.config import settings
from app.core.database import get_db
from app.models.models import AnalysisJob, LogEntry, Alert, JobStatus, User
from app.schemas.schemas import JobResponse
from app.services.parsers.engine import LogParsingEngine
from app.services.parsers.aws_waf_csv_parser import AwsWafCsvParser
from app.services.detectors.engine import DetectionEngine
from app.services.ai_analyzer import AIAnalyzer

router = APIRouter(prefix="/dev", tags=["Development"], dependencies=[Depends(get_current_user)])

BATCH_SIZE = 2000
MAX_LINES_FOR_DETECTION = 200_000


@router.post("/analyze", response_model=JobResponse)
async def analyze_sync(
    file: UploadFile = File(...),
    log_type: str = Form(None),
    skip_ai: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Synchronous analysis — parses, detects, and optionally runs AI analysis inline.
    Handles large files with batch inserts and streaming."""

    # --- Save file to disk (stream to avoid memory overload) ---
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    file_id = str(uuid.uuid4())
    safe_name = f"{file_id}_{file.filename}"
    file_path = os.path.join(settings.UPLOAD_DIR, safe_name)

    file_size = 0
    async with aiofiles.open(file_path, "wb") as f:
        while chunk := await file.read(1024 * 1024):  # 1MB chunks
            await f.write(chunk)
            file_size += len(chunk)

    job = AnalysisJob(
        id=uuid.uuid4(),
        created_by_user_id=current_user.id,
        filename=file.filename,
        file_path=file_path,
        file_size=file_size,
        log_type=log_type,
        status=JobStatus.PARSING,
        created_at=datetime.utcnow(),
    )
    db.add(job)
    await db.commit()

    try:
        # --- Phase 1: Parse (streaming, line by line) ---
        parser_engine = LogParsingEngine()

        # Read sample to detect parser
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            sample_lines = [f.readline() for _ in range(200)]
        sample_lines = [l for l in sample_lines if l.strip()]

        parser = parser_engine.detect_parser(sample_lines, hint=log_type)
        detected_type = parser_engine.get_log_type_name(parser)

        total_lines = 0
        parsed_lines = 0
        all_entries_for_detection = []
        batch = []

        def flush_batch():
            nonlocal batch
            if batch:
                db.add_all(batch)
                batch = []

        def append_parsed_entry(entry):
            nonlocal parsed_lines
            if entry.event_type != "unparsed":
                parsed_lines += 1
            if len(all_entries_for_detection) < MAX_LINES_FOR_DETECTION:
                all_entries_for_detection.append(entry)
            batch.append(LogEntry(
                id=uuid.uuid4(),
                job_id=job.id,
                line_number=entry.line_number,
                timestamp=entry.timestamp,
                source_ip=entry.source_ip,
                destination_ip=entry.destination_ip,
                username=entry.username,
                endpoint=entry.endpoint,
                method=entry.method,
                status_code=entry.status_code,
                response_size=entry.response_size,
                user_agent=entry.user_agent,
                event_type=entry.event_type,
                message=entry.message,
                raw_line=entry.raw_line[:2000] if entry.raw_line else None,
                extra_fields=entry.extra_fields,
            ))
            if len(batch) >= BATCH_SIZE:
                flush_batch()

        if isinstance(parser, AwsWafCsvParser):
            csv_entries = parser.parse_csv_file(file_path)
            total_lines = len(csv_entries)
            parsed_lines = sum(1 for e in csv_entries if e.event_type != "unparsed")
            for entry in csv_entries:
                append_parsed_entry(entry)
            flush_batch()
        else:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_number, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    total_lines += 1
                    entry = parser.parse_line(line, line_number)
                    if not entry:
                        continue
                    append_parsed_entry(entry)
            flush_batch()

        job.log_type = detected_type
        job.total_lines = total_lines
        job.parsed_lines = parsed_lines
        job.status = JobStatus.DETECTING
        job.progress = 50.0
        await db.commit()

        # --- Phase 2: Detection ---
        detection_engine = DetectionEngine()
        detections = detection_engine.run_all(all_entries_for_detection)

        for det in detections:
            alert = Alert(
                id=uuid.uuid4(),
                job_id=job.id,
                alert_type=det.alert_type,
                severity=det.severity,
                title=det.title,
                description=det.description,
                source_ip=det.source_ip,
                target_account=det.target_account,
                evidence=det.evidence,
                recommended_actions=det.recommended_actions,
            )
            db.add(alert)
        await db.commit()

        job.progress = 75.0
        await db.commit()

        # --- Phase 3: AI Analysis (optional) ---
        if not skip_ai:
            try:
                job.status = JobStatus.ANALYZING
                await db.commit()
                analyzer = AIAnalyzer()
                ai_result = await analyzer.generate_summary(
                    all_entries_for_detection, detections, detected_type
                )
                job.ai_summary = (
                    ai_result.get("executive_summary", "")
                    + "\n\n"
                    + ai_result.get("technical_summary", "")
                )
                risk = ai_result.get("risk_level", "medium").lower()
                risk_map = {
                    "critical": "critical", "high": "high",
                    "medium": "medium", "low": "low", "info": "info",
                }
                job.ai_risk_level = risk_map.get(risk, "medium")
                job.ai_recommendations = ai_result.get("recommended_actions", [])
            except Exception as e:
                job.ai_summary = f"AI analysis skipped: {str(e)}"

        job.status = JobStatus.COMPLETED
        job.progress = 100.0
        job.completed_at = datetime.utcnow()
        await db.commit()
        await db.refresh(job)

        alert_count = len(detections)

        return JobResponse(
            id=job.id,
            filename=job.filename,
            file_size=job.file_size,
            log_type=job.log_type,
            status=job.status,
            progress=job.progress,
            total_lines=job.total_lines,
            parsed_lines=job.parsed_lines,
            ai_summary=job.ai_summary,
            ai_risk_level=job.ai_risk_level,
            ai_recommendations=job.ai_recommendations,
            created_at=job.created_at,
            completed_at=job.completed_at,
            alert_count=alert_count,
        )

    except Exception as e:
        job.status = JobStatus.FAILED
        job.error_message = str(e)[:2000]
        await db.commit()
        raise HTTPException(500, detail=f"Analysis failed: {str(e)[:500]}")
