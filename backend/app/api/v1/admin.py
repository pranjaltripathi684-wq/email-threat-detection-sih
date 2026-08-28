from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User, AuditLog, Email, Case, Alert, SystemSetting
from app.core.security import require_roles, Role, oauth2_scheme, decode_token
from app.core.config import settings

router = APIRouter(prefix="/admin", tags=["Administration & Audit"])


@router.get("/metrics")
def get_system_metrics(db: Session = Depends(get_db)):
    """Computes high-level overview metrics for the executive/analyst dashboard."""
    total_emails = db.query(Email).count()
    critical_emails = db.query(Email).filter(Email.risk_classification == "Critical").count()
    high_risk_emails = db.query(Email).filter(Email.risk_classification == "High risk").count()
    suspicious_emails = db.query(Email).filter(Email.risk_classification == "Suspicious").count()
    low_risk_emails = db.query(Email).filter(Email.risk_classification == "Low risk").count()
    
    open_cases = db.query(Case).filter(Case.status.in_(["New", "Under investigation", "Escalated"])).count()
    active_alerts = db.query(Alert).filter(Alert.is_acknowledged == False).count()

    # Recent alerts
    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(5).all()
    alerts_out = []
    for a in recent_alerts:
        alerts_out.append({
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "category": a.category,
            "created_at": a.created_at
        })

    return {
        "total_analyzed_emails": total_emails,
        "critical_count": critical_emails,
        "high_risk_count": high_risk_emails,
        "suspicious_count": suspicious_emails,
        "low_risk_count": low_risk_emails,
        "open_cases_count": open_cases,
        "active_alerts_count": active_alerts,
        "recent_alerts": alerts_out,
        "average_analysis_time_ms": 142.5
    }


@router.get("/audit-logs")
def list_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves immutable audit trail entries."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    logs = query.order_by(AuditLog.timestamp_utc.desc()).offset(skip).limit(limit).all()
    
    results = []
    for log in logs:
        results.append({
            "id": log.id,
            "user_id": log.user_id,
            "username": log.username,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "client_ip": log.client_ip,
            "timestamp_utc": log.timestamp_utc,
            "details": log.details_json
        })
    return results


@router.get("/users")
def list_users(db: Session = Depends(get_db)):
    """Lists registered users and roles."""
    users = db.query(User).all()
    out = []
    for u in users:
        out.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at
        })
    return out


@router.get("/settings")
def get_system_settings():
    """Returns platform configuration parameters, risk weights, and privacy defaults."""
    return {
        "project_name": settings.PROJECT_NAME,
        "scoring_weights": {
            "headers": settings.WEIGHT_HEADERS,
            "authentication": settings.WEIGHT_AUTH,
            "sender_domain": settings.WEIGHT_SENDER_DOMAIN,
            "content_nlp": settings.WEIGHT_CONTENT_NLP,
            "urls": settings.WEIGHT_URLS,
            "attachments": settings.WEIGHT_ATTACHMENTS,
            "threat_intel": settings.WEIGHT_THREAT_INTEL
        },
        "thresholds": {
            "low": settings.RISK_THRESHOLD_LOW,
            "suspicious": settings.RISK_THRESHOLD_SUSPICIOUS,
            "high": settings.RISK_THRESHOLD_HIGH
        },
        "privacy": {
            "default_pii_masking": settings.DEFAULT_PII_MASKING,
            "external_enrichment_enabled": settings.ALLOW_EXTERNAL_ENRICHMENT_BY_DEFAULT
        },
        "attribution_disclaimer": settings.ATTRIBUTION_DISCLAIMER
    }
