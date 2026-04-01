from uuid import UUID

from sqlalchemy import select, func, case, distinct, text, Integer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import AnalysisJob, LogEntry, Alert, Severity
from app.schemas.schemas import DashboardStats


async def get_dashboard_stats(db: AsyncSession, job_id: UUID) -> DashboardStats:
    """Compute dashboard statistics for a given analysis job."""

    # Total events
    total_q = await db.execute(
        select(func.count(LogEntry.id)).where(LogEntry.job_id == job_id)
    )
    total_events = total_q.scalar() or 0

    # Alerts by severity
    alert_q = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.job_id == job_id)
        .group_by(Alert.severity)
    )
    severity_counts = {row[0]: row[1] for row in alert_q.all()}
    total_alerts = sum(severity_counts.values())

    # Unique IPs
    ip_q = await db.execute(
        select(func.count(distinct(LogEntry.source_ip))).where(
            LogEntry.job_id == job_id, LogEntry.source_ip.isnot(None)
        )
    )
    unique_ips = ip_q.scalar() or 0

    # Failed / successful logins
    login_q = await db.execute(
        select(
            func.sum(case((LogEntry.event_type == "login_failed", 1), else_=0)),
            func.sum(case((LogEntry.event_type == "login_success", 1), else_=0)),
        ).where(LogEntry.job_id == job_id)
    )
    row = login_q.one()
    failed_logins = row[0] or 0
    successful_logins = row[1] or 0

    # Error rate
    error_q = await db.execute(
        select(func.count(LogEntry.id)).where(
            LogEntry.job_id == job_id,
            LogEntry.status_code >= 400,
        )
    )
    error_count = error_q.scalar() or 0
    error_rate = (error_count / total_events * 100) if total_events > 0 else 0.0

    # Top source IPs
    top_ips_q = await db.execute(
        select(LogEntry.source_ip, func.count(LogEntry.id).label("cnt"))
        .where(LogEntry.job_id == job_id, LogEntry.source_ip.isnot(None))
        .group_by(LogEntry.source_ip)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
    )
    top_source_ips = [{"ip": r[0], "count": r[1]} for r in top_ips_q.all()]

    # Top endpoints
    top_eps_q = await db.execute(
        select(LogEntry.endpoint, func.count(LogEntry.id).label("cnt"))
        .where(LogEntry.job_id == job_id, LogEntry.endpoint.isnot(None))
        .group_by(LogEntry.endpoint)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
    )
    top_endpoints = [{"endpoint": r[0], "count": r[1]} for r in top_eps_q.all()]

    # Top usernames
    top_users_q = await db.execute(
        select(LogEntry.username, func.count(LogEntry.id).label("cnt"))
        .where(LogEntry.job_id == job_id, LogEntry.username.isnot(None))
        .group_by(LogEntry.username)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
    )
    top_usernames = [{"username": r[0], "count": r[1]} for r in top_users_q.all()]

    # Events by hour (SQLite uses strftime, PostgreSQL uses extract)
    is_sqlite = settings.DATABASE_URL.startswith("sqlite")
    if is_sqlite:
        hour_expr = func.cast(func.strftime("%H", LogEntry.timestamp), Integer).label("hour")
    else:
        hour_expr = func.extract("hour", LogEntry.timestamp).label("hour")

    hour_q = await db.execute(
        select(hour_expr, func.count(LogEntry.id))
        .where(LogEntry.job_id == job_id, LogEntry.timestamp.isnot(None))
        .group_by(hour_expr)
        .order_by(hour_expr)
    )
    events_by_hour = [{"hour": int(r[0]), "count": r[1]} for r in hour_q.all()]

    # ─── WAF-specific metrics (AWS WAF CSV, etc.) ─────────────────────────
    waf_action_q = await db.execute(
        select(LogEntry.event_type, func.count(LogEntry.id))
        .where(
            LogEntry.job_id == job_id,
            LogEntry.event_type.in_(("waf_block", "waf_allow", "waf_count")),
        )
        .group_by(LogEntry.event_type)
    )
    waf_action_map = {r[0]: r[1] for r in waf_action_q.all()}
    waf_has_data = sum(waf_action_map.values()) > 0
    label_for = {"waf_block": "BLOCK", "waf_allow": "ALLOW", "waf_count": "COUNT"}
    waf_action_counts = [
        {"action": label_for.get(et, et), "count": c}
        for et, c in sorted(waf_action_map.items(), key=lambda x: -x[1])
    ]

    blocked_sum = case((LogEntry.event_type == "waf_block", 1), else_=0)
    allowed_sum = case((LogEntry.event_type == "waf_allow", 1), else_=0)
    counted_sum = case((LogEntry.event_type == "waf_count", 1), else_=0)

    waf_hour_q = await db.execute(
        select(
            hour_expr,
            func.count(LogEntry.id),
            func.sum(blocked_sum),
            func.sum(allowed_sum),
            func.sum(counted_sum),
        )
        .where(
            LogEntry.job_id == job_id,
            LogEntry.timestamp.isnot(None),
            LogEntry.event_type.in_(("waf_block", "waf_allow", "waf_count")),
        )
        .group_by(hour_expr)
        .order_by(hour_expr)
    )
    waf_hour_rows = {h: {"hour": h, "total": 0, "blocked": 0, "allowed": 0, "counted": 0} for h in range(24)}
    for row in waf_hour_q.all():
        h = int(row[0])
        waf_hour_rows[h]["total"] = row[1]
        waf_hour_rows[h]["blocked"] = int(row[2] or 0)
        waf_hour_rows[h]["allowed"] = int(row[3] or 0)
        waf_hour_rows[h]["counted"] = int(row[4] or 0)
    waf_events_by_hour = [waf_hour_rows[h] for h in range(24)]

    top_blocked_ips_q = await db.execute(
        select(LogEntry.source_ip, func.count(LogEntry.id).label("cnt"))
        .where(
            LogEntry.job_id == job_id,
            LogEntry.event_type == "waf_block",
            LogEntry.source_ip.isnot(None),
        )
        .group_by(LogEntry.source_ip)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
    )
    top_blocked_ips = [{"ip": r[0], "count": r[1]} for r in top_blocked_ips_q.all()]

    top_blocked_eps_q = await db.execute(
        select(LogEntry.endpoint, func.count(LogEntry.id).label("cnt"))
        .where(
            LogEntry.job_id == job_id,
            LogEntry.event_type == "waf_block",
            LogEntry.endpoint.isnot(None),
        )
        .group_by(LogEntry.endpoint)
        .order_by(func.count(LogEntry.id).desc())
        .limit(10)
    )
    top_blocked_endpoints = [{"endpoint": r[0], "count": r[1]} for r in top_blocked_eps_q.all()]

    # terminating_rule_id from extra_fields JSON (AWS WAF CSV)
    if is_sqlite:
        rule_expr = func.json_extract(LogEntry.extra_fields, "$.terminating_rule")
    else:
        rule_expr = LogEntry.extra_fields["terminating_rule"].as_string()

    rule_q = await db.execute(
        select(rule_expr, func.count(LogEntry.id))
        .where(
            LogEntry.job_id == job_id,
            LogEntry.event_type.in_(("waf_block", "waf_allow", "waf_count")),
            rule_expr.isnot(None),
            rule_expr != "",
        )
        .group_by(rule_expr)
        .order_by(func.count(LogEntry.id).desc())
        .limit(15)
    )
    top_terminating_rules = [
        {"rule": r[0][-120:] if len(str(r[0])) > 120 else r[0], "count": r[1]}
        for r in rule_q.all()
        if r[0]
    ]

    # Alerts by type
    type_q = await db.execute(
        select(Alert.alert_type, func.count(Alert.id))
        .where(Alert.job_id == job_id)
        .group_by(Alert.alert_type)
    )
    alerts_by_type = [{"type": str(r[0].value), "count": r[1]} for r in type_q.all()]

    # Severity distribution
    severity_distribution = [
        {"severity": sev.value, "count": severity_counts.get(sev, 0)}
        for sev in Severity
    ]

    return DashboardStats(
        total_events=total_events,
        total_alerts=total_alerts,
        critical_alerts=severity_counts.get(Severity.CRITICAL, 0),
        high_alerts=severity_counts.get(Severity.HIGH, 0),
        medium_alerts=severity_counts.get(Severity.MEDIUM, 0),
        low_alerts=severity_counts.get(Severity.LOW, 0),
        unique_ips=unique_ips,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        error_rate=round(error_rate, 2),
        top_source_ips=top_source_ips,
        top_endpoints=top_endpoints,
        top_usernames=top_usernames,
        events_by_hour=events_by_hour,
        alerts_by_type=alerts_by_type,
        severity_distribution=severity_distribution,
        waf_has_data=waf_has_data,
        waf_action_counts=waf_action_counts,
        waf_events_by_hour=waf_events_by_hour,
        top_blocked_ips=top_blocked_ips,
        top_blocked_endpoints=top_blocked_endpoints,
        top_terminating_rules=top_terminating_rules,
    )
