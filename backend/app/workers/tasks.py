import asyncio
import uuid
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.models import AnalysisJob, LogEntry, Alert, JobStatus
from app.services.parsers.engine import LogParsingEngine
from app.services.detectors.engine import DetectionEngine
from app.services.ai_analyzer import AIAnalyzer
from app.workers.celery_app import celery_app

sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_size=5)
SyncSession = sessionmaker(bind=sync_engine)


@celery_app.task(bind=True, name="analyze_log_file")
def analyze_log_file(self, job_id: str, file_path: str, log_type_hint: str = None):
    """Main background task: parse, detect, and analyze a log file."""
    db = SyncSession()
    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == uuid.UUID(job_id)).first()
        if not job:
            return {"error": "Job not found"}

        # Phase 1: Parsing
        job.status = JobStatus.PARSING
        job.progress = 10.0
        db.commit()

        parser_engine = LogParsingEngine()
        entries, log_type = parser_engine.parse_file(file_path, log_type_hint=log_type_hint)

        job.log_type = log_type
        job.total_lines = len(entries)
        job.parsed_lines = len([e for e in entries if e.event_type != "unparsed"])
        job.progress = 40.0
        db.commit()

        # Save parsed entries to database
        for entry in entries:
            log_entry = LogEntry(
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
                raw_line=entry.raw_line,
                extra_fields=entry.extra_fields,
            )
            db.add(log_entry)

        db.commit()
        job.progress = 50.0
        db.commit()

        # Phase 2: Detection
        job.status = JobStatus.DETECTING
        job.progress = 55.0
        db.commit()

        detection_engine = DetectionEngine()
        detection_results = detection_engine.run_all(entries)

        for det in detection_results:
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

        db.commit()
        job.progress = 70.0
        db.commit()

        # Phase 3: AI Analysis
        job.status = JobStatus.ANALYZING
        job.progress = 75.0
        db.commit()

        try:
            analyzer = AIAnalyzer()
            ai_result = asyncio.run(analyzer.generate_summary(entries, detection_results, log_type))

            job.ai_summary = ai_result.get("executive_summary", "") + "\n\n" + ai_result.get("technical_summary", "")
            risk = ai_result.get("risk_level", "medium").lower()
            risk_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
            job.ai_risk_level = risk_map.get(risk, "medium")
            job.ai_recommendations = ai_result.get("recommended_actions", [])
            job.metadata_ = {
                "key_findings": ai_result.get("key_findings", []),
                "mitre_techniques": ai_result.get("mitre_techniques", []),
                "indicators_of_compromise": ai_result.get("indicators_of_compromise", []),
                "attack_narrative": ai_result.get("attack_narrative", ""),
            }
        except Exception as e:
            job.ai_summary = f"AI analysis unavailable: {str(e)}"
            job.ai_risk_level = _infer_risk_from_alerts(detection_results)
            job.ai_recommendations = []
            for det in detection_results:
                job.ai_recommendations.extend(det.recommended_actions)

        job.progress = 100.0
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.utcnow()
        db.commit()

        return {
            "job_id": job_id,
            "status": "completed",
            "total_entries": len(entries),
            "alerts": len(detection_results),
            "log_type": log_type,
        }

    except Exception as e:
        if db:
            job = db.query(AnalysisJob).filter(AnalysisJob.id == uuid.UUID(job_id)).first()
            if job:
                job.status = JobStatus.FAILED
                job.error_message = str(e)
                db.commit()
        return {"error": str(e)}
    finally:
        db.close()


def _infer_risk_from_alerts(alerts: list) -> str:
    if not alerts:
        return "info"
    severity_values = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_sev = 0
    for a in alerts:
        sev = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
        max_sev = max(max_sev, severity_values.get(sev, 0))
    reverse_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    return reverse_map.get(max_sev, "medium")
