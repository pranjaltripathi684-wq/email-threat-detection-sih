from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field


# Auth Schemas
class UserLogin(BaseModel):
    username: str
    password: str


class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = "Analyst"


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Raw Paste Ingestion Schema
class EmailRawPaste(BaseModel):
    subject: Optional[str] = ""
    from_header: Optional[str] = ""
    to_header: Optional[str] = ""
    reply_to_header: Optional[str] = ""
    raw_headers: Optional[str] = ""
    body_text: Optional[str] = ""
    body_html: Optional[str] = ""
    case_id: Optional[int] = None


# Analysis Result Schemas
class HopResponse(BaseModel):
    id: int
    hop_order: int
    receiving_server: Optional[str]
    sending_server: Optional[str]
    extracted_ip: Optional[str]
    ip_classification: str
    timestamp_raw: Optional[str]
    timestamp_utc: Optional[datetime]
    time_delta_seconds: Optional[float]
    tls_status: bool
    tls_cipher: Optional[str]
    is_earliest_reliable_public_ip: bool
    anomaly_flags: Optional[str]
    geo_country: Optional[str]
    geo_city: Optional[str]
    geo_lat: Optional[float]
    geo_lon: Optional[float]
    asn_org: Optional[str]

    class Config:
        from_attributes = True


class AuthResultResponse(BaseModel):
    spf_result: str
    spf_domain: Optional[str]
    dkim_present: bool
    dkim_result: str
    dkim_domain: Optional[str]
    dkim_selector: Optional[str]
    dmarc_result: str
    dmarc_policy: str
    dmarc_alignment: str
    arc_present: bool
    arc_result: str
    from_reply_to_aligned: bool
    is_lookalike_domain_auth: bool
    natural_language_explanation: Optional[str]

    class Config:
        from_attributes = True


class UrlResponse(BaseModel):
    id: int
    raw_url: str
    display_text: Optional[str]
    domain: Optional[str]
    is_ip_based: bool
    is_punycode: bool
    is_shortened: bool
    is_deceptive: bool
    has_suspicious_port: bool
    risk_score: float
    risk_reasons: Optional[List[str]] = []

    class Config:
        from_attributes = True


class AttachmentResponse(BaseModel):
    id: int
    filename: str
    file_extension: Optional[str]
    declared_mime_type: Optional[str]
    magic_file_type: Optional[str]
    file_size: int
    sha256_hash: str
    has_double_extension: bool
    has_macros: bool
    is_script_or_executable: bool
    is_password_protected: bool
    risk_score: float
    risk_reasons: Optional[List[str]] = []

    class Config:
        from_attributes = True


class EmailSummaryResponse(BaseModel):
    id: int
    original_filename: str
    sha256_hash: str
    upload_time: datetime
    raw_subject: Optional[str]
    raw_from: Optional[str]
    raw_to: Optional[str]
    sender_domain: Optional[str]
    total_risk_score: float
    risk_classification: str
    confidence_score: float
    earliest_public_ip: Optional[str]
    earliest_public_ip_country: Optional[str]
    case_id: Optional[int]

    class Config:
        from_attributes = True


class EmailDetailResponse(BaseModel):
    id: int
    original_filename: str
    sha256_hash: str
    file_size: int
    upload_time: datetime
    raw_subject: Optional[str]
    raw_from: Optional[str]
    raw_to: Optional[str]
    raw_cc: Optional[str]
    raw_reply_to: Optional[str]
    raw_return_path: Optional[str]
    raw_date: Optional[str]
    message_id: Optional[str]
    sender_domain: Optional[str]
    reply_to_domain: Optional[str]
    sanitized_body_text: Optional[str]
    sanitized_body_html: Optional[str]
    earliest_public_ip: Optional[str]
    earliest_public_ip_country: Optional[str]
    earliest_public_ip_city: Optional[str]
    earliest_public_ip_org: Optional[str]
    total_risk_score: float
    risk_classification: str
    confidence_score: float
    score_breakdown: Optional[Dict[str, Any]]
    positive_evidence: Optional[List[str]]
    negative_evidence: Optional[List[str]]
    missing_evidence: Optional[List[str]]
    recommended_action: Optional[str]
    hops: List[HopResponse] = []
    auth_results: Optional[AuthResultResponse] = None
    urls: List[UrlResponse] = []
    attachments: List[AttachmentResponse] = []

    class Config:
        from_attributes = True


# Case Schemas
class CaseCreate(BaseModel):
    title: str
    description: str
    severity: Optional[str] = "Medium"
    assigned_analyst_id: Optional[int] = None
    email_ids: Optional[List[int]] = []


class CaseUpdate(BaseModel):
    status: str
    severity: Optional[str] = None
    assigned_analyst_id: Optional[int] = None


class NoteCreate(BaseModel):
    note_text: str
    email_id: Optional[int] = None


class CaseResponse(BaseModel):
    id: int
    case_number: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    assigned_analyst_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    email_count: Optional[int] = 0

    class Config:
        from_attributes = True


# Evidence & Custody Schemas
class CustodyEventResponse(BaseModel):
    id: int
    evidence_id: int
    action: str
    performed_by_username: str
    performed_by_role: str
    timestamp_utc: datetime
    source_location: Optional[str]
    destination_location: Optional[str]
    reason: Optional[str]
    pre_action_hash: Optional[str]
    post_action_hash: Optional[str]
    verification_status: str

    class Config:
        from_attributes = True


class EvidenceItemResponse(BaseModel):
    id: int
    email_id: int
    evidence_uuid: str
    original_sha256: str
    file_size_bytes: int
    collected_at: datetime
    is_immutable: bool
    legal_hold: bool
    custody_events: List[CustodyEventResponse] = []

    class Config:
        from_attributes = True
