from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.core.deps import get_current_user
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import AnalysisJob, LogEntry, Alert, InvestigationChat, User, UserRole
from app.schemas.schemas import AskAIRequest, AskAIResponse
from app.services.ai_analyzer import AIAnalyzer
from app.services.parsers.base import ParsedLogEntry
from app.services.detectors.base import DetectionResult

router = APIRouter(prefix="/investigate", tags=["Investigation"], dependencies=[Depends(get_current_user)])


@router.post("/ask-ai", response_model=AskAIResponse)
async def ask_ai(
    request: AskAIRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ask the AI investigation assistant a question about the logs."""
    job_query = select(AnalysisJob).where(AnalysisJob.id == request.job_id)
    if current_user.role != UserRole.ADMIN:
        job_query = job_query.where(AnalysisJob.created_by_user_id == current_user.id)
    result = await db.execute(job_query)
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, "Analysis job not found")

    if job.status.value not in ("completed", "analyzing"):
        raise HTTPException(400, f"Analysis not yet complete. Current status: {job.status.value}")

    # Fetch log entries and alerts
    entries_q = await db.execute(
        select(LogEntry).where(LogEntry.job_id == request.job_id).limit(5000)
    )
    db_entries = entries_q.scalars().all()

    alerts_q = await db.execute(
        select(Alert).where(Alert.job_id == request.job_id)
    )
    db_alerts = alerts_q.scalars().all()

    parsed_entries = [
        ParsedLogEntry(
            line_number=e.line_number or 0,
            timestamp=e.timestamp,
            source_ip=e.source_ip,
            username=e.username,
            endpoint=e.endpoint,
            method=e.method,
            status_code=e.status_code,
            response_size=e.response_size,
            event_type=e.event_type,
            message=e.message,
            raw_line=e.raw_line or "",
        )
        for e in db_entries
    ]

    detection_results = [
        DetectionResult(
            alert_type=a.alert_type,
            severity=a.severity,
            title=a.title,
            description=a.description or "",
            source_ip=a.source_ip,
            target_account=a.target_account,
            evidence=a.evidence or {},
            recommended_actions=a.recommended_actions or [],
        )
        for a in db_alerts
    ]

    # Get chat history
    chat_q = await db.execute(
        select(InvestigationChat)
        .where(InvestigationChat.job_id == request.job_id)
        .order_by(InvestigationChat.created_at)
    )
    chat_history = [
        {"role": c.role, "content": c.content}
        for c in chat_q.scalars().all()
    ]

    # Save user question
    user_msg = InvestigationChat(job_id=request.job_id, role="user", content=request.question)
    db.add(user_msg)

    # Call AI (degrade gracefully if provider/network is unavailable)
    analyzer = AIAnalyzer()
    try:
        answer = await analyzer.investigate(
            request.question, parsed_entries, detection_results, chat_history
        )
    except Exception:
        answer = (
            "AI provider is temporarily unavailable right now (network/proxy/API issue). "
            "Your log data and detections are still available in Dashboard, Alerts, and Timeline. "
            "Please try this question again in a minute."
        )

    # Save AI response
    ai_msg = InvestigationChat(job_id=request.job_id, role="assistant", content=answer)
    db.add(ai_msg)
    await db.commit()

    return AskAIResponse(answer=answer)


@router.get("/chat-history/{job_id}")
async def get_chat_history(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the investigation chat history for a job."""
    job_query = select(AnalysisJob).where(AnalysisJob.id == job_id)
    if current_user.role != UserRole.ADMIN:
        job_query = job_query.where(AnalysisJob.created_by_user_id == current_user.id)
    check = await db.execute(job_query)
    if not check.scalar_one_or_none():
        raise HTTPException(404, "Analysis job not found")

    result = await db.execute(
        select(InvestigationChat)
        .where(InvestigationChat.job_id == job_id)
        .order_by(InvestigationChat.created_at)
    )
    chats = result.scalars().all()

    return {
        "messages": [
            {"role": c.role, "content": c.content, "timestamp": str(c.created_at)}
            for c in chats
        ]
    }
