import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Email, User, EvidenceItem, CustodyEvent
from app.core.security import oauth2_scheme, decode_token, mask_email
from app.core.audit import log_audit_event
from app.services.ingestion import safe_ingest_email
from app.services.pipeline import process_and_analyze_email
from app.services.report_service import generate_forensic_report
from app.schemas.schemas import EmailSummaryResponse, EmailDetailResponse, EmailRawPaste, HopResponse, UrlResponse, AttachmentResponse

router = APIRouter(prefix="/emails", tags=["Emails"])


@router.post("/upload", response_model=EmailDetailResponse)
async def upload_eml_file(
    file: UploadFile = File(...),
    case_id: Optional[int] = Form(None),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Safely ingests an RFC 5322 .eml file, computes SHA-256 evidence hash,
    and runs the forensic analysis pipeline.
    """
    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()
    user_id = user.id if user else 1
    role = user.role if user else "Analyst"

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

    email_record, evidence_item, custody_event = safe_ingest_email(
        db=db,
        raw_bytes=raw_bytes,
        filename=file.filename or "uploaded_email.eml",
        uploader_id=user_id,
        uploader_username=username,
        uploader_role=role,
        source_type="upload",
        case_id=case_id
    )

    # Process and analyze email
    email_record = process_and_analyze_email(db=db, email=email_record, raw_bytes=raw_bytes)

    log_audit_event(
        db=db,
        action="EMAIL_UPLOAD_AND_ANALYSIS",
        user_id=user_id,
        username=username,
        resource_type="Email",
        resource_id=str(email_record.id),
        details={"sha256": email_record.sha256_hash, "risk_score": email_record.total_risk_score}
    )

    return build_email_detail_response(email_record)


@router.post("/paste", response_model=EmailDetailResponse)
def paste_raw_email(
    paste_data: EmailRawPaste,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Ingests email from raw pasted headers and content, constructing an RFC 5322 byte payload.
    """
    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()
    user_id = user.id if user else 1
    role = user.role if user else "Analyst"

    # Synthesize RFC 5322 message stream
    raw_lines = []
    if paste_data.raw_headers:
        raw_lines.append(paste_data.raw_headers.strip())
    else:
        if paste_data.from_header:
            raw_lines.append(f"From: {paste_data.from_header}")
        if paste_data.to_header:
            raw_lines.append(f"To: {paste_data.to_header}")
        if paste_data.reply_to_header:
            raw_lines.append(f"Reply-To: {paste_data.reply_to_header}")
        if paste_data.subject:
            raw_lines.append(f"Subject: {paste_data.subject}")
        raw_lines.append("MIME-Version: 1.0")
        raw_lines.append("Content-Type: text/plain; charset=utf-8")

    raw_lines.append("")  # Header-Body delimiter
    raw_lines.append(paste_data.body_text or paste_data.body_html or "")

    raw_eml_str = "\r\n".join(raw_lines)
    raw_bytes = raw_eml_str.encode("utf-8")

    email_record, evidence_item, custody_event = safe_ingest_email(
        db=db,
        raw_bytes=raw_bytes,
        filename="pasted_raw_email.eml",
        uploader_id=user_id,
        uploader_username=username,
        uploader_role=role,
        source_type="pasted_raw",
        case_id=paste_data.case_id
    )

    email_record = process_and_analyze_email(db=db, email=email_record, raw_bytes=raw_bytes)

    log_audit_event(
        db=db,
        action="EMAIL_PASTE_AND_ANALYSIS",
        user_id=user_id,
        username=username,
        resource_type="Email",
        resource_id=str(email_record.id),
        details={"sha256": email_record.sha256_hash, "risk_score": email_record.total_risk_score}
    )

    return build_email_detail_response(email_record)


@router.get("", response_model=List[EmailSummaryResponse])
def list_emails(
    skip: int = 0,
    limit: int = 50,
    classification: Optional[str] = None,
    case_id: Optional[int] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Lists analyzed emails with filtering and pagination."""
    query = db.query(Email)
    if classification:
        query = query.filter(Email.risk_classification == classification)
    if case_id:
        query = query.filter(Email.case_id == case_id)
    if search:
        query = query.filter(
            (Email.raw_subject.ilike(f"%{search}%")) |
            (Email.raw_from.ilike(f"%{search}%")) |
            (Email.sender_domain.ilike(f"%{search}%")) |
            (Email.sha256_hash.ilike(f"%{search}%"))
        )

    emails = query.order_by(Email.upload_time.desc()).offset(skip).limit(limit).all()
    return emails


@router.get("/{email_id}", response_model=EmailDetailResponse)
def get_email_details(
    email_id: int,
    db: Session = Depends(get_db)
):
    """Fetches full forensic breakdown and indicators for a single email."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")
    return build_email_detail_response(email)


@router.get("/{email_id}/report")
def get_email_report(
    email_id: int,
    format: str = "html",
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """Generates structured forensic intelligence report in HTML or JSON."""
    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()

    report_data = generate_forensic_report(db=db, email_id=email_id)

    log_audit_event(
        db=db,
        action="EXPORT_FORENSIC_REPORT",
        user_id=user.id if user else 1,
        username=username,
        resource_type="Report",
        resource_id=str(email_id),
        details={"format": format}
    )

    if format == "html":
        return HTMLResponse(content=report_data["html_report"])
    return report_data


def build_email_detail_response(email: Email) -> dict:
    """Helper to assemble response schema from email and child records."""
    score_breakdown = json.loads(email.score_breakdown_json or "{}")
    pos_ev = json.loads(email.positive_evidence_json or "[]")
    neg_ev = json.loads(email.negative_evidence_json or "[]")
    mis_ev = json.loads(email.missing_evidence_json or "[]")

    urls_out = []
    for u in email.urls:
        reasons = json.loads(u.risk_reasons_json or "[]")
        urls_out.append({
            "id": u.id,
            "raw_url": u.raw_url,
            "display_text": u.display_text,
            "domain": u.domain,
            "is_ip_based": u.is_ip_based,
            "is_punycode": u.is_punycode,
            "is_shortened": u.is_shortened,
            "is_deceptive": u.is_deceptive,
            "has_suspicious_port": u.has_suspicious_port,
            "risk_score": u.risk_score,
            "risk_reasons": reasons
        })

    atts_out = []
    for a in email.attachments:
        reasons = json.loads(a.risk_reasons_json or "[]")
        atts_out.append({
            "id": a.id,
            "filename": a.filename,
            "file_extension": a.file_extension,
            "declared_mime_type": a.declared_mime_type,
            "magic_file_type": a.magic_file_type,
            "file_size": a.file_size,
            "sha256_hash": a.sha256_hash,
            "has_double_extension": a.has_double_extension,
            "has_macros": a.has_macros,
            "is_script_or_executable": a.is_script_or_executable,
            "is_password_protected": a.is_password_protected,
            "risk_score": a.risk_score,
            "risk_reasons": reasons
        })

    return {
        "id": email.id,
        "original_filename": email.original_filename,
        "sha256_hash": email.sha256_hash,
        "file_size": email.file_size,
        "upload_time": email.upload_time,
        "raw_subject": email.raw_subject,
        "raw_from": email.raw_from,
        "raw_to": email.raw_to,
        "raw_cc": email.raw_cc,
        "raw_reply_to": email.raw_reply_to,
        "raw_return_path": email.raw_return_path,
        "raw_date": email.raw_date,
        "message_id": email.message_id,
        "sender_domain": email.sender_domain,
        "reply_to_domain": email.reply_to_domain,
        "sanitized_body_text": email.sanitized_body_text,
        "sanitized_body_html": email.sanitized_body_html,
        "earliest_public_ip": email.earliest_public_ip,
        "earliest_public_ip_country": email.earliest_public_ip_country,
        "earliest_public_ip_city": email.earliest_public_ip_city,
        "earliest_public_ip_org": email.earliest_public_ip_org,
        "total_risk_score": email.total_risk_score,
        "risk_classification": email.risk_classification,
        "confidence_score": email.confidence_score,
        "score_breakdown": score_breakdown,
        "positive_evidence": pos_ev,
        "negative_evidence": neg_ev,
        "missing_evidence": mis_ev,
        "recommended_action": email.recommended_action,
        "hops": email.hops,
        "auth_results": email.auth_results,
        "urls": urls_out,
        "attachments": atts_out
    }
