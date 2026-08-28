import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User
from app.core.security import oauth2_scheme, decode_token
from app.core.audit import log_audit_event
from app.services.ingestion import safe_ingest_email
from app.services.pipeline import process_and_analyze_email
from app.schemas.schemas import EmailDetailResponse
from app.api.v1.emails import build_email_detail_response

router = APIRouter(prefix="/scenarios", tags=["Demonstration Scenarios"])

# Correct path to backend/sample_data from backend/app/api/v1/scenarios.py
SAMPLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "sample_data"))

SCENARIO_FILES = {
    "A": ("scenario_a_lookalike.eml", "Scenario A: Lookalike-domain phishing (PayPal spoof)"),
    "B": ("scenario_b_executive_impersonation.eml", "Scenario B: Executive Impersonation (CEO gift-card request)"),
    "C": ("scenario_c_bec_compromised.eml", "Scenario C: Business Email Compromise (Wire change on legit domain)"),
    "D": ("scenario_d_malicious_attachment.eml", "Scenario D: Malicious Attachment (Double extension .pdf.exe)"),
    "E": ("scenario_e_legitimate.eml", "Scenario E: Legitimate internal message (Full DMARC pass)")
}


@router.get("/list")
def list_available_scenarios():
    """Lists available pre-packaged synthetic academic demonstration scenarios."""
    out = []
    for key, (filename, description) in SCENARIO_FILES.items():
        out.append({
            "scenario_id": key,
            "filename": filename,
            "description": description
        })
    return out


@router.post("/load/{scenario_id}", response_model=EmailDetailResponse)
def load_and_analyze_scenario(
    scenario_id: str,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """Loads a pre-configured synthetic scenario EML and executes full forensic analysis."""
    s_key = scenario_id.upper()
    if s_key not in SCENARIO_FILES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scenario '{scenario_id}' not found. Available: A, B, C, D, E")

    filename, desc = SCENARIO_FILES[s_key]
    file_path = os.path.join(SAMPLE_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File '{filename}' missing on server.")

    payload = decode_token(token)
    username = payload.get("sub", "analyst")
    user = db.query(User).filter(User.username == username).first()
    user_id = user.id if user else 1
    role = user.role if user else "Analyst"

    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    email_record, evidence_item, custody_event = safe_ingest_email(
        db=db,
        raw_bytes=raw_bytes,
        filename=filename,
        uploader_id=user_id,
        uploader_username=username,
        uploader_role=role,
        source_type="synthetic_scenario"
    )

    email_record = process_and_analyze_email(db=db, email=email_record, raw_bytes=raw_bytes)

    log_audit_event(
        db=db,
        action="LOAD_DEMO_SCENARIO",
        user_id=user_id,
        username=username,
        resource_type="Email",
        resource_id=str(email_record.id),
        details={"scenario": s_key, "description": desc, "sha256": email_record.sha256_hash}
    )

    return build_email_detail_response(email_record)
