import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, String, Text, DateTime, Integer, Float,
    Enum, ForeignKey, JSON, Boolean, Index, TypeDecorator, CHAR,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class UUIDType(TypeDecorator):
    """Platform-agnostic UUID type: uses CHAR(36) on SQLite, native UUID on PostgreSQL."""
    impl = CHAR(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return str(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return uuid.UUID(value) if not isinstance(value, uuid.UUID) else value
        return value


class UserRole(str, PyEnum):
    ADMIN = "admin"
    USER = "user"


class JobStatus(str, PyEnum):
    PENDING = "pending"
    PARSING = "parsing"
    DETECTING = "detecting"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, PyEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, PyEnum):
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_LOGIN = "suspicious_login"
    DATA_EXFILTRATION = "data_exfiltration"
    API_ABUSE = "api_abuse"
    WEB_ATTACK = "web_attack"
    ANOMALY = "anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


class User(Base):
    __tablename__ = "users"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole, native_enum=False), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    created_by_user_id = Column(UUIDType, ForeignKey("users.id", ondelete="SET NULL"), index=True)
    filename = Column(String(500), nullable=False)
    file_path = Column(String(1000), nullable=False)
    file_size = Column(Integer)
    log_type = Column(String(100))
    status = Column(Enum(JobStatus, native_enum=False), default=JobStatus.PENDING, nullable=False)
    progress = Column(Float, default=0.0)
    total_lines = Column(Integer, default=0)
    parsed_lines = Column(Integer, default=0)
    error_message = Column(Text)
    ai_summary = Column(Text)
    ai_risk_level = Column(Enum(Severity, native_enum=False))
    ai_recommendations = Column(JSON)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime)

    log_entries = relationship("LogEntry", back_populates="job", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="job", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_jobs_status", "status"),
        Index("ix_jobs_owner_created", "created_by_user_id", "created_at"),
    )


class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    job_id = Column(UUIDType, ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False)
    line_number = Column(Integer)
    timestamp = Column(DateTime, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    username = Column(String(255), index=True)
    endpoint = Column(String(1000))
    method = Column(String(10))
    status_code = Column(Integer)
    response_size = Column(Integer)
    user_agent = Column(Text)
    event_type = Column(String(100), index=True)
    message = Column(Text)
    raw_line = Column(Text)
    extra_fields = Column(JSON, default=dict)

    job = relationship("AnalysisJob", back_populates="log_entries")

    __table_args__ = (
        Index("ix_log_entries_job_timestamp", "job_id", "timestamp"),
        Index("ix_log_entries_job_ip", "job_id", "source_ip"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    job_id = Column(UUIDType, ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False)
    alert_type = Column(Enum(AlertType, native_enum=False), nullable=False)
    severity = Column(Enum(Severity, native_enum=False), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    source_ip = Column(String(45))
    target_account = Column(String(255))
    evidence = Column(JSON, default=dict)
    recommended_actions = Column(JSON, default=list)
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    job = relationship("AnalysisJob", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_job_type", "job_id", "alert_type"),
    )


class InvestigationChat(Base):
    __tablename__ = "investigation_chats"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    job_id = Column(UUIDType, ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)  # user | assistant
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
