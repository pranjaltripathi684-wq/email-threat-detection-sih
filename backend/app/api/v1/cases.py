from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Case, Email, AnalystNote, User
from app.core.security import oauth2_scheme, decode_token
from app.core.audit import log_audit_event
from app.services.case_service import create_case, add_note_to_case, update_case_status
from app.schemas.schemas import CaseCreate, CaseUpdate, NoteCreate, CaseResponse

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.post("", response_model=CaseResponse)
def create_new_case(
    case_in: CaseCreate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """Creates a new incident case and attaches specified emails."""
    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()
    analyst_id = case_in.assigned_analyst_id or (user.id if user else None)

    case = create_case(
        db=db,
        title=case_in.title,
        description=case_in.description,
        severity=case_in.severity or "Medium",
        assigned_analyst_id=analyst_id,
        email_ids=case_in.email_ids
    )

    log_audit_event(
        db=db,
        action="CREATE_CASE",
        user_id=user.id if user else 1,
        username=username,
        resource_type="Case",
        resource_id=str(case.id),
        details={"case_number": case.case_number, "severity": case.severity}
    )

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "assigned_analyst_id": case.assigned_analyst_id,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "email_count": len(case.emails)
    }


@router.get("", response_model=List[CaseResponse])
def list_cases(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Lists all cases with status filtering."""
    query = db.query(Case)
    if status:
        query = query.filter(Case.status == status)
    if severity:
        query = query.filter(Case.severity == severity)

    cases = query.order_by(Case.updated_at.desc()).all()
    results = []
    for c in cases:
        results.append({
            "id": c.id,
            "case_number": c.case_number,
            "title": c.title,
            "description": c.description,
            "severity": c.severity,
            "status": c.status,
            "assigned_analyst_id": c.assigned_analyst_id,
            "created_at": c.created_at,
            "updated_at": c.updated_at,
            "email_count": len(c.emails)
        })
    return results


@router.get("/{case_id}")
def get_case_details(case_id: int, db: Session = Depends(get_db)):
    """Fetches case details, linked emails, and timeline of notes."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    notes_out = []
    for n in case.notes:
        notes_out.append({
            "id": n.id,
            "note_text": n.note_text,
            "author_id": n.author_id,
            "author_name": n.author.username if n.author else "System",
            "email_id": n.email_id,
            "created_at": n.created_at
        })

    emails_out = []
    for e in case.emails:
        emails_out.append({
            "id": e.id,
            "subject": e.raw_subject,
            "from": e.raw_from,
            "risk_score": e.total_risk_score,
            "classification": e.risk_classification,
            "sha256": e.sha256_hash
        })

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "assigned_analyst_id": case.assigned_analyst_id,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "emails": emails_out,
        "notes": notes_out
    }


@router.patch("/{case_id}")
def update_case(
    case_id: int,
    update_in: CaseUpdate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """Updates case status, severity, or assigned analyst."""
    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()

    case = update_case_status(
        db=db,
        case_id=case_id,
        status=update_in.status,
        severity=update_in.severity,
        assigned_analyst_id=update_in.assigned_analyst_id
    )
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    log_audit_event(
        db=db,
        action="UPDATE_CASE",
        user_id=user.id if user else 1,
        username=username,
        resource_type="Case",
        resource_id=str(case.id),
        details={"status": case.status, "severity": case.severity}
    )

    return {"message": "Case updated successfully", "case_id": case.id, "status": case.status}


@router.post("/{case_id}/notes")
def add_case_note(
    case_id: int,
    note_in: NoteCreate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """Adds a new timestamped observation note to a case."""
    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()

    note = add_note_to_case(
        db=db,
        case_id=case_id,
        author_id=user.id if user else 1,
        note_text=note_in.note_text,
        email_id=note_in.email_id
    )

    log_audit_event(
        db=db,
        action="ADD_CASE_NOTE",
        user_id=user.id if user else 1,
        username=username,
        resource_type="Case",
        resource_id=str(case_id),
        details={"note_id": note.id}
    )

    return {"message": "Note added", "note_id": note.id, "created_at": note.created_at}
