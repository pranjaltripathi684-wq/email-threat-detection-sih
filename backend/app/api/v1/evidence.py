import os
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import EvidenceItem, CustodyEvent, Email, User, utcnow
from app.core.security import oauth2_scheme, decode_token
from app.core.audit import log_audit_event
from app.schemas.schemas import EvidenceItemResponse

router = APIRouter(prefix="/evidence", tags=["Evidence & Chain of Custody"])


@router.get("/{evidence_id}", response_model=EvidenceItemResponse)
def get_evidence_details(evidence_id: int, db: Session = Depends(get_db)):
    """Retrieves evidence metadata and complete chronological chain-of-custody log."""
    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")
    return evidence


@router.get("/by-email/{email_id}", response_model=EvidenceItemResponse)
def get_evidence_by_email(email_id: int, db: Session = Depends(get_db)):
    """Retrieves evidence item linked to an email."""
    evidence = db.query(EvidenceItem).filter(EvidenceItem.email_id == email_id).first()
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found for this email")
    return evidence


@router.post("/{evidence_id}/verify")
def verify_evidence_integrity(
    evidence_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Cryptographically verifies the physical stored evidence file against its recorded SHA-256 hash.
    Appends a verified audit event to the Chain of Custody record.
    """
    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()
    role = user.role if user else "Auditor"

    evidence = db.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")

    if not os.path.exists(evidence.storage_path):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Physical evidence file missing on disk")

    with open(evidence.storage_path, "rb") as f:
        file_bytes = f.read()

    calculated_hash = hashlib.sha256(file_bytes).hexdigest()
    is_match = (calculated_hash == evidence.original_sha256)
    status_str = "VERIFIED_MATCH" if is_match else "TAMPER_DETECTED"

    custody_event = CustodyEvent(
        evidence_id=evidence.id,
        action="Cryptographic Integrity Audit",
        performed_by_username=username,
        performed_by_role=role,
        timestamp_utc=utcnow(),
        source_location=evidence.storage_path,
        destination_location=evidence.storage_path,
        reason="Manual / Automated Evidence Hash Audit",
        pre_action_hash=evidence.original_sha256,
        post_action_hash=calculated_hash,
        verification_status=status_str
    )
    db.add(custody_event)
    db.commit()

    log_audit_event(
        db=db,
        action="EVIDENCE_INTEGRITY_VERIFICATION",
        user_id=user.id if user else 1,
        username=username,
        resource_type="EvidenceItem",
        resource_id=str(evidence.id),
        details={"status": status_str, "recorded_hash": evidence.original_sha256, "calculated_hash": calculated_hash}
    )

    return {
        "evidence_id": evidence.id,
        "evidence_uuid": evidence.evidence_uuid,
        "recorded_sha256": evidence.original_sha256,
        "calculated_sha256": calculated_hash,
        "integrity_verified": is_match,
        "verification_status": status_str,
        "timestamp_utc": custody_event.timestamp_utc
    }
