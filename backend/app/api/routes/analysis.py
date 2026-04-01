from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.deps import get_current_user
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import AnalysisJob, LogEntry, Alert, User, UserRole
from app.schemas.schemas import (
    JobResponse, JobListResponse,
    LogEntryResponse, LogEntryListResponse,
    AlertResponse, AlertListResponse,
    TimelineEvent, TimelineResponse,
    DashboardStats,
)
from app.services.dashboard_service import get_dashboard_stats

router = APIRouter(tags=["Analysis"], dependencies=[Depends(get_current_user)])


def _job_scope_query(current_user: User):
    query = select(AnalysisJob)
    if current_user.role != UserRole.ADMIN:
        query = query.where(AnalysisJob.created_by_user_id == current_user.id)
    return query


@router.get("/analysis/{job_id}", response_model=JobResponse)
async def get_analysis(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get analysis job status and results."""
    result = await db.execute(_job_scope_query(current_user).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, "Analysis job not found")

    alert_count_q = await db.execute(
        select(func.count(Alert.id)).where(Alert.job_id == job_id)
    )

    return JobResponse(
        id=job.id,
        filename=job.filename,
        file_size=job.file_size,
        log_type=job.log_type,
        status=job.status,
        progress=job.progress,
        total_lines=job.total_lines,
        parsed_lines=job.parsed_lines,
        error_message=job.error_message,
        ai_summary=job.ai_summary,
        ai_risk_level=job.ai_risk_level,
        ai_recommendations=job.ai_recommendations,
        created_at=job.created_at,
        updated_at=job.updated_at,
        completed_at=job.completed_at,
        alert_count=alert_count_q.scalar() or 0,
    )


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all analysis jobs."""
    offset = (page - 1) * page_size

    scoped_jobs = _job_scope_query(current_user).subquery()
    total_q = await db.execute(select(func.count()).select_from(scoped_jobs))
    total = total_q.scalar() or 0

    result = await db.execute(
        _job_scope_query(current_user)
        .order_by(AnalysisJob.created_at.desc())
        .offset(offset).limit(page_size)
    )
    jobs = result.scalars().all()

    return JobListResponse(
        jobs=[
            JobResponse(
                id=j.id, filename=j.filename, file_size=j.file_size,
                log_type=j.log_type, status=j.status, progress=j.progress,
                total_lines=j.total_lines, parsed_lines=j.parsed_lines,
                error_message=j.error_message, ai_summary=j.ai_summary,
                ai_risk_level=j.ai_risk_level, ai_recommendations=j.ai_recommendations,
                created_at=j.created_at, updated_at=j.updated_at, completed_at=j.completed_at,
            )
            for j in jobs
        ],
        total=total,
    )


@router.get("/logs/{job_id}", response_model=LogEntryListResponse)
async def get_log_entries(
    job_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    event_type: str = Query(None),
    source_ip: str = Query(None),
    username: str = Query(None),
    search: str = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get parsed log entries for a job with filtering and pagination."""
    job_check = await db.execute(_job_scope_query(current_user).where(AnalysisJob.id == job_id))
    if not job_check.scalar_one_or_none():
        raise HTTPException(404, "Analysis job not found")

    query = select(LogEntry).where(LogEntry.job_id == job_id)
    count_query = select(func.count(LogEntry.id)).where(LogEntry.job_id == job_id)

    if event_type:
        query = query.where(LogEntry.event_type == event_type)
        count_query = count_query.where(LogEntry.event_type == event_type)
    if source_ip:
        query = query.where(LogEntry.source_ip == source_ip)
        count_query = count_query.where(LogEntry.source_ip == source_ip)
    if username:
        query = query.where(LogEntry.username == username)
        count_query = count_query.where(LogEntry.username == username)
    if search:
        search_filter = LogEntry.message.ilike(f"%{search}%")
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    total_q = await db.execute(count_query)
    total = total_q.scalar() or 0

    offset = (page - 1) * page_size
    result = await db.execute(
        query.order_by(LogEntry.line_number).offset(offset).limit(page_size)
    )
    entries = result.scalars().all()

    return LogEntryListResponse(
        entries=[LogEntryResponse.model_validate(e) for e in entries],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/alerts", response_model=AlertListResponse)
async def get_all_alerts(
    job_id: UUID = Query(None),
    severity: str = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get security alerts, optionally filtered by job and severity."""
    query = select(Alert).join(AnalysisJob, AnalysisJob.id == Alert.job_id)
    count_query = select(func.count(Alert.id)).join(AnalysisJob, AnalysisJob.id == Alert.job_id)
    if current_user.role != UserRole.ADMIN:
        query = query.where(AnalysisJob.created_by_user_id == current_user.id)
        count_query = count_query.where(AnalysisJob.created_by_user_id == current_user.id)

    if job_id:
        query = query.where(Alert.job_id == job_id)
        count_query = count_query.where(Alert.job_id == job_id)
    if severity:
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)

    total_q = await db.execute(count_query)
    total = total_q.scalar() or 0

    result = await db.execute(query.order_by(Alert.created_at.desc()))
    alerts = result.scalars().all()

    return AlertListResponse(
        alerts=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
    )


@router.get("/alerts/{job_id}", response_model=AlertListResponse)
async def get_job_alerts(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all alerts for a specific analysis job."""
    job_check = await db.execute(_job_scope_query(current_user).where(AnalysisJob.id == job_id))
    if not job_check.scalar_one_or_none():
        raise HTTPException(404, "Analysis job not found")

    result = await db.execute(
        select(Alert).where(Alert.job_id == job_id).order_by(Alert.created_at.desc())
    )
    alerts = result.scalars().all()

    return AlertListResponse(
        alerts=[AlertResponse.model_validate(a) for a in alerts],
        total=len(alerts),
    )


@router.get("/timeline/{job_id}", response_model=TimelineResponse)
async def get_timeline(
    job_id: UUID,
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a timeline of events for a job."""
    job_check = await db.execute(_job_scope_query(current_user).where(AnalysisJob.id == job_id))
    if not job_check.scalar_one_or_none():
        raise HTTPException(404, "Analysis job not found")

    notable_types = [
        "login_failed", "login_success", "invalid_user", "session_opened",
        "sudo_command", "unauthorized", "forbidden", "server_error",
        "firewall_block", "firewall_allow",
    ]

    result = await db.execute(
        select(LogEntry)
        .where(LogEntry.job_id == job_id, LogEntry.timestamp.isnot(None))
        .where(LogEntry.event_type.in_(notable_types))
        .order_by(LogEntry.timestamp)
        .limit(limit)
    )
    entries = result.scalars().all()

    # Also include alerts as timeline events
    alert_result = await db.execute(
        select(Alert).where(Alert.job_id == job_id)
    )
    alerts = alert_result.scalars().all()

    events = []
    for e in entries:
        sev = None
        if e.event_type in ("login_failed", "invalid_user"):
            sev = "low"
        elif e.event_type in ("unauthorized", "forbidden", "firewall_block"):
            sev = "medium"
        elif e.event_type == "server_error":
            sev = "high"

        events.append(TimelineEvent(
            timestamp=e.timestamp,
            event_type=e.event_type,
            source_ip=e.source_ip,
            username=e.username,
            description=e.message or f"{e.event_type} event",
            severity=sev,
        ))

    for a in alerts:
        events.append(TimelineEvent(
            timestamp=a.created_at,
            event_type=f"alert_{a.alert_type.value}",
            source_ip=a.source_ip,
            username=a.target_account,
            description=a.title,
            severity=a.severity.value,
        ))

    events.sort(key=lambda e: e.timestamp)

    return TimelineResponse(events=events[:limit], total=len(events))


@router.get("/dashboard/{job_id}", response_model=DashboardStats)
async def get_dashboard(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get dashboard statistics for a job."""
    result = await db.execute(_job_scope_query(current_user).where(AnalysisJob.id == job_id))
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Job not found")

    return await get_dashboard_stats(db, job_id)
