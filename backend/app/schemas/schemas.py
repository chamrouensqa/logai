from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.models import JobStatus, Severity, AlertType


# ─── Job Schemas ─────────────────────────────────────────

class JobCreate(BaseModel):
    filename: str
    log_type: Optional[str] = None


class JobResponse(BaseModel):
    id: UUID
    filename: str
    file_size: Optional[int] = None
    log_type: Optional[str] = None
    status: JobStatus
    progress: float
    total_lines: int
    parsed_lines: int
    error_message: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_risk_level: Optional[Severity] = None
    ai_recommendations: Optional[list] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    alert_count: Optional[int] = None

    model_config = {"from_attributes": True}


class JobListResponse(BaseModel):
    jobs: list[JobResponse]
    total: int


# ─── Log Entry Schemas ───────────────────────────────────

class LogEntryResponse(BaseModel):
    id: UUID
    line_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    event_type: Optional[str] = None
    message: Optional[str] = None
    raw_line: Optional[str] = None

    model_config = {"from_attributes": True}


class LogEntryListResponse(BaseModel):
    entries: list[LogEntryResponse]
    total: int
    page: int
    page_size: int


# ─── Alert Schemas ───────────────────────────────────────

class AlertResponse(BaseModel):
    id: UUID
    job_id: UUID
    alert_type: AlertType
    severity: Severity
    title: str
    description: Optional[str] = None
    source_ip: Optional[str] = None
    target_account: Optional[str] = None
    evidence: Optional[dict] = None
    recommended_actions: Optional[list] = None
    is_resolved: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    total: int


# ─── Timeline Schemas ────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    description: str
    severity: Optional[Severity] = None


class TimelineResponse(BaseModel):
    events: list[TimelineEvent]
    total: int


# ─── AI Investigation Schemas ────────────────────────────

class AskAIRequest(BaseModel):
    job_id: UUID
    question: str


class AskAIResponse(BaseModel):
    answer: str
    sources: Optional[list[dict]] = None


# ─── Dashboard Schemas ───────────────────────────────────

class DashboardStats(BaseModel):
    total_events: int = 0
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    unique_ips: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    error_rate: float = 0.0
    top_source_ips: list[dict] = Field(default_factory=list)
    top_endpoints: list[dict] = Field(default_factory=list)
    top_usernames: list[dict] = Field(default_factory=list)
    events_by_hour: list[dict] = Field(default_factory=list)
    alerts_by_type: list[dict] = Field(default_factory=list)
    severity_distribution: list[dict] = Field(default_factory=list)
    # AWS WAF / firewall-style logs (populated when event_type is waf_*)
    waf_has_data: bool = False
    waf_action_counts: list[dict] = Field(default_factory=list)  # {action: BLOCK|ALLOW|COUNT, count}
    waf_events_by_hour: list[dict] = Field(
        default_factory=list
    )  # {hour, total, blocked, allowed, counted}
    top_blocked_ips: list[dict] = Field(default_factory=list)  # {ip, count}
    top_blocked_endpoints: list[dict] = Field(default_factory=list)  # {endpoint, count}
    top_terminating_rules: list[dict] = Field(default_factory=list)  # {rule, count}


# ─── IP reputation (AbuseIPDB / VirusTotal) ──────────────

class AbuseIpDbReputation(BaseModel):
    abuse_confidence_score: int = 0
    total_reports: int = 0
    country_code: Optional[str] = None
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    last_reported_at: Optional[str] = None
    is_whitelisted: bool = False
    report_url: str = ""


class VirusTotalReputation(BaseModel):
    harmless: int = 0
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    timeout: int = 0
    reputation: Optional[int] = None
    country: Optional[str] = None
    as_owner: Optional[str] = None
    analysis_url: str = ""


class IpReputationResponse(BaseModel):
    ip: str
    cached: bool = False
    configured_abuseipdb: bool = False
    configured_virustotal: bool = False
    abuseipdb: Optional[AbuseIpDbReputation] = None
    virustotal: Optional[VirusTotalReputation] = None
    errors: list[str] = Field(default_factory=list)


# ─── Auth & users ────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class UserPublic(BaseModel):
    id: UUID
    username: str
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)
