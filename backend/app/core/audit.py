import json
from typing import Optional, Any
from sqlalchemy.orm import Session
from app.db.models import AuditLog, utcnow


def log_audit_event(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Any] = None,
    client_ip: Optional[str] = "127.0.0.1",
    user_agent: Optional[str] = "Forensic-Client"
) -> AuditLog:
    """Records an immutable audit event in the database."""
    details_str = None
    if details is not None:
        if isinstance(details, (dict, list)):
            details_str = json.dumps(details, default=str)
        else:
            details_str = str(details)
            
    audit_entry = AuditLog(
        user_id=user_id,
        username=username or "System",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details_json=details_str,
        client_ip=client_ip,
        user_agent=user_agent,
        timestamp_utc=utcnow()
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry
