import os
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Tuple, Dict, Any
from sqlalchemy.orm import Session
from app.db.models import Email, EvidenceItem, CustodyEvent, utcnow
from app.core.config import settings

EVIDENCE_STORAGE_DIR = os.environ.get("EVIDENCE_STORAGE_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "storage", "evidence")
os.makedirs(EVIDENCE_STORAGE_DIR, exist_ok=True)


def calculate_sha256(data: bytes) -> str:
    """Calculates cryptographic SHA-256 hash of raw byte data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_md5(data: bytes) -> str:
    """Calculates MD5 hash for legacy reference."""
    hasher = hashlib.md5()
    hasher.update(data)
    return hasher.hexdigest()


def safe_ingest_email(
    db: Session,
    raw_bytes: bytes,
    filename: str,
    uploader_id: int,
    uploader_username: str,
    uploader_role: str,
    source_type: str = "upload",
    case_id: int = None
) -> Tuple[Email, EvidenceItem, CustodyEvent]:
    """
    Safely stores the immutable original evidence object, hashes it with SHA-256,
    and initializes the forensic chain of custody without executing any attachments.
    """
    if len(raw_bytes) > settings.MAX_EMAIL_SIZE_BYTES:
        raise ValueError(f"Email file size ({len(raw_bytes)} bytes) exceeds maximum allowable limit of {settings.MAX_EMAIL_SIZE_BYTES} bytes.")

    sha256_hash = calculate_sha256(raw_bytes)
    evidence_uuid = str(uuid.uuid4())
    
    # Store immutable copy on disk named by its SHA-256 hash
    safe_filename = f"{sha256_hash}.eml"
    storage_path = os.path.join(EVIDENCE_STORAGE_DIR, safe_filename)
    
    if not os.path.exists(storage_path):
        with open(storage_path, "wb") as f:
            f.write(raw_bytes)
            
    # Check if duplicate email already ingested
    existing_email = db.query(Email).filter(Email.sha256_hash == sha256_hash).first()
    if existing_email:
        # Create an audit custody record for re-access / duplicate verification
        evidence_item = db.query(EvidenceItem).filter(EvidenceItem.email_id == existing_email.id).first()
        custody_event = CustodyEvent(
            evidence_id=evidence_item.id if evidence_item else 1,
            action="Re-Ingestion / Duplicate Verification",
            performed_by_username=uploader_username,
            performed_by_role=uploader_role,
            timestamp_utc=utcnow(),
            source_location=filename,
            destination_location=storage_path,
            reason="Email already present in forensic repository. Integrity verified.",
            pre_action_hash=sha256_hash,
            post_action_hash=sha256_hash,
            verification_status="VERIFIED_MATCH"
        )
        db.add(custody_event)
        db.commit()
        db.refresh(custody_event)
        return existing_email, evidence_item, custody_event

    # Create new Email record
    email_record = Email(
        original_filename=filename,
        sha256_hash=sha256_hash,
        mime_type="message/rfc822",
        file_size=len(raw_bytes),
        upload_time=utcnow(),
        source_type=source_type,
        case_id=case_id,
        uploaded_by_id=uploader_id,
        evidence_status="Preserved"
    )
    db.add(email_record)
    db.commit()
    db.refresh(email_record)

    # Create Evidence Item
    evidence_item = EvidenceItem(
        email_id=email_record.id,
        evidence_uuid=evidence_uuid,
        original_sha256=sha256_hash,
        storage_path=storage_path,
        file_size_bytes=len(raw_bytes),
        collected_at=utcnow(),
        collected_by_id=uploader_id,
        is_immutable=True,
        legal_hold=False
    )
    db.add(evidence_item)
    db.commit()
    db.refresh(evidence_item)

    # Log initial Chain of Custody Ingestion Event
    custody_event = CustodyEvent(
        evidence_id=evidence_item.id,
        action="Acquisition and Initial Ingestion",
        performed_by_username=uploader_username,
        performed_by_role=uploader_role,
        timestamp_utc=utcnow(),
        source_location=filename,
        destination_location=storage_path,
        reason="Initial secure evidence acquisition and cryptographic hashing.",
        pre_action_hash=sha256_hash,
        post_action_hash=sha256_hash,
        verification_status="VERIFIED_MATCH"
    )
    db.add(custody_event)
    db.commit()
    db.refresh(custody_event)

    return email_record, evidence_item, custody_event
