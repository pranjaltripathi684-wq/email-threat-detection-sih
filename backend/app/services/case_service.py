from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.db.models import Case, Email, AnalystNote, User, utcnow


def create_case(
    db: Session,
    title: str,
    description: str,
    severity: str = "Medium",
    assigned_analyst_id: Optional[int] = None,
    email_ids: Optional[List[int]] = None
) -> Case:
    """Creates a new incident investigation case."""
    case = Case(
        title=title,
        description=description,
        severity=severity,
        status="New",
        assigned_analyst_id=assigned_analyst_id,
        created_at=utcnow(),
        updated_at=utcnow()
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    if email_ids:
        for eid in email_ids:
            email = db.query(Email).filter(Email.id == eid).first()
            if email:
                email.case_id = case.id
        db.commit()

    return case


def add_note_to_case(
    db: Session,
    case_id: int,
    author_id: int,
    note_text: str,
    email_id: Optional[int] = None
) -> AnalystNote:
    """Adds a timestamped analyst observation note to a case."""
    note = AnalystNote(
        case_id=case_id,
        email_id=email_id,
        author_id=author_id,
        note_text=note_text,
        created_at=utcnow(),
        updated_at=utcnow()
    )
    db.add(note)
    
    # Update case timestamp
    case = db.query(Case).filter(Case.id == case_id).first()
    if case:
        case.updated_at = utcnow()

    db.commit()
    db.refresh(note)
    return note


def update_case_status(
    db: Session,
    case_id: int,
    status: str,
    severity: Optional[str] = None,
    assigned_analyst_id: Optional[int] = None
) -> Optional[Case]:
    """Updates case status, severity, or assignment."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return None
    
    case.status = status
    if severity:
        case.severity = severity
    if assigned_analyst_id is not None:
        case.assigned_analyst_id = assigned_analyst_id
    case.updated_at = utcnow()
    
    db.commit()
    db.refresh(case)
    return case
