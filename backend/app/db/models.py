import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.db.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), nullable=False, default="Analyst")  # Analyst, Administrator, Investigator, Auditor
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    uploaded_emails = relationship("Email", back_populates="uploader", foreign_keys="Email.uploaded_by_id")
    assigned_cases = relationship("Case", back_populates="assigned_analyst")
    audit_logs = relationship("AuditLog", back_populates="user")
    notes = relationship("AnalystNote", back_populates="author")


class RoleModel(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    permissions_json = Column(Text, nullable=True)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(100), unique=True, nullable=False)
    description = Column(String(255), nullable=True)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(50), unique=True, index=True, default=lambda: f"CASE-{uuid.uuid4().hex[:8].upper()}")
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default="Medium")  # Low, Medium, High, Critical
    status = Column(String(50), default="New")  # New, Under investigation, Contained, Escalated, Resolved, Closed, False positive
    assigned_analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_archived = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    assigned_analyst = relationship("User", back_populates="assigned_cases")
    emails = relationship("Email", back_populates="case")
    notes = relationship("AnalystNote", back_populates="case", cascade="all, delete-orphan")


class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String(255), nullable=False)
    sha256_hash = Column(String(64), index=True, nullable=False)
    mime_type = Column(String(100), default="message/rfc822")
    file_size = Column(Integer, nullable=False)
    upload_time = Column(DateTime(timezone=True), default=utcnow)
    source_type = Column(String(50), default="upload")  # upload, pasted_raw, synthetic_scenario, api
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    uploaded_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    evidence_status = Column(String(50), default="Preserved")
    retention_expiry = Column(DateTime(timezone=True), nullable=True)

    # Normalized fields
    raw_subject = Column(Text, nullable=True)
    raw_from = Column(Text, nullable=True)
    raw_to = Column(Text, nullable=True)
    raw_cc = Column(Text, nullable=True)
    raw_reply_to = Column(Text, nullable=True)
    raw_return_path = Column(Text, nullable=True)
    raw_date = Column(String(255), nullable=True)
    message_id = Column(String(255), index=True, nullable=True)
    sender_domain = Column(String(255), index=True, nullable=True)
    reply_to_domain = Column(String(255), index=True, nullable=True)

    # Content
    sanitized_body_text = Column(Text, nullable=True)
    sanitized_body_html = Column(Text, nullable=True)
    raw_headers_text = Column(Text, nullable=True)

    # Risk & Explainability
    total_risk_score = Column(Float, default=0.0, index=True)
    risk_classification = Column(String(50), default="Low risk", index=True)  # Low risk, Suspicious, High risk, Critical
    confidence_score = Column(Float, default=0.0)
    score_breakdown_json = Column(Text, nullable=True)
    positive_evidence_json = Column(Text, nullable=True)
    negative_evidence_json = Column(Text, nullable=True)
    missing_evidence_json = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)

    # Earliest reliable public IP
    earliest_public_ip = Column(String(100), index=True, nullable=True)
    earliest_public_ip_country = Column(String(100), nullable=True)
    earliest_public_ip_city = Column(String(100), nullable=True)
    earliest_public_ip_org = Column(String(255), nullable=True)

    # Relationships
    uploader = relationship("User", back_populates="uploaded_emails", foreign_keys=[uploaded_by_id])
    case = relationship("Case", back_populates="emails")
    headers = relationship("EmailHeader", back_populates="email", cascade="all, delete-orphan")
    hops = relationship("ReceivedHop", back_populates="email", cascade="all, delete-orphan", order_by="ReceivedHop.hop_order")
    auth_results = relationship("AuthenticationResult", back_populates="email", uselist=False, cascade="all, delete-orphan")
    urls = relationship("EmailUrl", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("EmailAttachment", back_populates="email", cascade="all, delete-orphan")
    threat_matches = relationship("ThreatIntelligenceMatch", back_populates="email", cascade="all, delete-orphan")
    evidence_items = relationship("EvidenceItem", back_populates="email", cascade="all, delete-orphan")
    predictions = relationship("ModelPrediction", back_populates="email", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="email", cascade="all, delete-orphan")


class EmailHeader(Base):
    __tablename__ = "email_headers"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    header_name = Column(String(255), nullable=False)
    header_value = Column(Text, nullable=False)
    is_anomalous = Column(Boolean, default=False)
    anomaly_reason = Column(String(255), nullable=True)

    email = relationship("Email", back_populates="headers")


class ReceivedHop(Base):
    __tablename__ = "received_hops"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    hop_order = Column(Integer, nullable=False)  # 1 = earliest (oldest), N = final destination
    receiving_server = Column(String(255), nullable=True)
    sending_server = Column(String(255), nullable=True)
    extracted_ip = Column(String(100), nullable=True, index=True)
    ip_classification = Column(String(50), default="Unknown")  # Public, Private, Loopback, Link-local, Bogon/Reserved
    timestamp_raw = Column(String(255), nullable=True)
    timestamp_utc = Column(DateTime(timezone=True), nullable=True)
    time_delta_seconds = Column(Float, nullable=True)
    tls_status = Column(Boolean, default=False)
    tls_cipher = Column(String(255), nullable=True)
    is_trusted_gateway = Column(Boolean, default=False)
    is_earliest_reliable_public_ip = Column(Boolean, default=False)
    anomaly_flags = Column(Text, nullable=True)  # Comma-separated or JSON string
    raw_hop_value = Column(Text, nullable=True)

    # Enrichment summary for the hop
    geo_country = Column(String(100), nullable=True)
    geo_city = Column(String(100), nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    asn_org = Column(String(255), nullable=True)

    email = relationship("Email", back_populates="hops")


class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    
    # SPF
    spf_result = Column(String(50), default="none")  # pass, fail, softfail, neutral, none, temperror, permerror
    spf_domain = Column(String(255), nullable=True)
    spf_scope = Column(String(50), default="mfrom")
    
    # DKIM
    dkim_present = Column(Boolean, default=False)
    dkim_result = Column(String(50), default="none")  # pass, fail, neutral, none, permerror
    dkim_domain = Column(String(255), nullable=True)
    dkim_selector = Column(String(100), nullable=True)
    dkim_body_hash_valid = Column(Boolean, nullable=True)
    
    # DMARC
    dmarc_result = Column(String(50), default="none")  # pass, fail, none
    dmarc_policy = Column(String(50), default="none")  # reject, quarantine, none
    dmarc_alignment = Column(String(50), default="unaligned")  # strict, relaxed, unaligned
    dmarc_from_domain = Column(String(255), nullable=True)
    
    # ARC
    arc_present = Column(Boolean, default=False)
    arc_result = Column(String(50), default="none")
    
    # Alignments & Traps
    from_reply_to_aligned = Column(Boolean, default=True)
    display_name_spoofed = Column(Boolean, default=False)
    is_lookalike_domain_auth = Column(Boolean, default=False)  # Passed auth on deceptive domain!
    natural_language_explanation = Column(Text, nullable=True)

    email = relationship("Email", back_populates="auth_results")


class EmailUrl(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    raw_url = Column(Text, nullable=False)
    display_text = Column(Text, nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    is_ip_based = Column(Boolean, default=False)
    is_punycode = Column(Boolean, default=False)
    is_shortened = Column(Boolean, default=False)
    is_deceptive = Column(Boolean, default=False)  # e.g. text says paypal.com but href goes elsewhere
    has_suspicious_port = Column(Boolean, default=False)
    path_entropy = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    risk_reasons_json = Column(Text, nullable=True)

    email = relationship("Email", back_populates="urls")


class EmailAttachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_extension = Column(String(50), nullable=True)
    declared_mime_type = Column(String(100), nullable=True)
    magic_file_type = Column(String(100), nullable=True)
    file_size = Column(Integer, default=0)
    sha256_hash = Column(String(64), index=True, nullable=False)
    md5_hash = Column(String(32), nullable=True)
    has_double_extension = Column(Boolean, default=False)
    has_macros = Column(Boolean, default=False)
    is_script_or_executable = Column(Boolean, default=False)
    is_password_protected = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    risk_reasons_json = Column(Text, nullable=True)

    email = relationship("Email", back_populates="attachments")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(50), nullable=False, index=True)  # ip, domain, url, email, hash
    indicator_value = Column(String(255), nullable=False, index=True)
    source = Column(String(100), default="local_analysis")
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)
    reputation_score = Column(Float, default=0.0)  # 0 to 100
    confidence = Column(Float, default=0.8)
    related_campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)


class IPEnrichment(Base):
    __tablename__ = "ip_enrichment"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(100), unique=True, index=True, nullable=False)
    country = Column(String(100), nullable=True)
    country_code = Column(String(10), nullable=True)
    region = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String(50), nullable=True)
    isp = Column(String(255), nullable=True)
    org = Column(String(255), nullable=True)
    is_vpn = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_cloud_proxy = Column(Boolean, default=False)
    reverse_dns = Column(String(255), nullable=True)
    reputation_score = Column(Float, default=0.0)
    last_enriched_at = Column(DateTime(timezone=True), default=utcnow)


class DomainEnrichment(Base):
    __tablename__ = "domain_enrichment"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, index=True, nullable=False)
    a_records_json = Column(Text, nullable=True)
    mx_records_json = Column(Text, nullable=True)
    ns_records_json = Column(Text, nullable=True)
    txt_records_json = Column(Text, nullable=True)
    spf_record = Column(Text, nullable=True)
    dmarc_record = Column(Text, nullable=True)
    registrar = Column(String(255), nullable=True)
    creation_date = Column(DateTime(timezone=True), nullable=True)
    expiration_date = Column(DateTime(timezone=True), nullable=True)
    is_newly_registered = Column(Boolean, default=False)
    last_enriched_at = Column(DateTime(timezone=True), default=utcnow)


class ThreatIntelligenceMatch(Base):
    __tablename__ = "threat_intelligence_matches"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    indicator_value = Column(String(255), nullable=False)
    indicator_type = Column(String(50), nullable=False)
    provider_name = Column(String(100), nullable=False)  # AbuseIPDB, VirusTotal, URLhaus, Internal
    match_details_json = Column(Text, nullable=True)
    severity = Column(String(50), default="Medium")
    confidence = Column(Float, default=0.8)

    email = relationship("Email", back_populates="threat_matches")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    threat_actor_alias = Column(String(100), nullable=True)
    attack_vector = Column(String(100), default="Phishing / Social Engineering")
    first_observed = Column(DateTime(timezone=True), default=utcnow)
    last_observed = Column(DateTime(timezone=True), default=utcnow)
    status = Column(String(50), default="Active")


class GraphEntity(Base):
    __tablename__ = "graph_entities"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(50), nullable=False, index=True)  # Email, Domain, IP, URL, Hash, Case, Campaign
    entity_key = Column(String(255), unique=True, nullable=False, index=True)
    label = Column(String(255), nullable=False)
    properties_json = Column(Text, nullable=True)


class GraphRelationship(Base):
    __tablename__ = "graph_relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_entity_key = Column(String(255), nullable=False, index=True)
    target_entity_key = Column(String(255), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False)  # SENT_FROM, DELIVERED_THROUGH, LINKS_TO, CONTAINS_ATTACHMENT, RELATED_TO_CAMPAIGN
    weight = Column(Float, default=1.0)
    properties_json = Column(Text, nullable=True)


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    evidence_uuid = Column(String(64), unique=True, default=generate_uuid, index=True)
    original_sha256 = Column(String(64), nullable=False, index=True)
    storage_path = Column(String(500), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    collected_at = Column(DateTime(timezone=True), default=utcnow)
    collected_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_immutable = Column(Boolean, default=True)
    legal_hold = Column(Boolean, default=False)

    email = relationship("Email", back_populates="evidence_items")
    custody_events = relationship("CustodyEvent", back_populates="evidence", cascade="all, delete-orphan")


class CustodyEvent(Base):
    __tablename__ = "custody_events"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence_items.id"), nullable=False)
    action = Column(String(100), nullable=False)  # Ingestion, Verification, Access, Export, CustodyTransfer
    performed_by_username = Column(String(100), nullable=False)
    performed_by_role = Column(String(50), nullable=False)
    timestamp_utc = Column(DateTime(timezone=True), default=utcnow)
    source_location = Column(String(255), nullable=True)
    destination_location = Column(String(255), nullable=True)
    reason = Column(Text, nullable=True)
    pre_action_hash = Column(String(64), nullable=True)
    post_action_hash = Column(String(64), nullable=True)
    verification_status = Column(String(50), default="VERIFIED_MATCH")

    evidence = relationship("EvidenceItem", back_populates="custody_events")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    note_text = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    case = relationship("Case", back_populates="notes")
    author = relationship("User", back_populates="notes")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), default="High")  # Low, Medium, High, Critical
    category = Column(String(100), default="Phishing")
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    email = relationship("Email", back_populates="alerts")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False, index=True)  # LOGIN, UPLOAD_EMAIL, ANALYZE_EMAIL, EXPORT_REPORT, MODIFY_CASE, etc.
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    details_json = Column(Text, nullable=True)
    client_ip = Column(String(100), nullable=True)
    user_agent = Column(String(255), nullable=True)
    timestamp_utc = Column(DateTime(timezone=True), default=utcnow, index=True)

    user = relationship("User", back_populates="audit_logs")


class ModelPrediction(Base):
    __tablename__ = "model_predictions"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    model_name = Column(String(100), default="TF-IDF + Calibrated Logistic Regression")
    model_version = Column(String(50), default="v1.0-academic")
    predicted_class = Column(String(50), nullable=False)
    probability_score = Column(Float, nullable=False)
    top_features_json = Column(Text, nullable=True)
    inference_time_ms = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    email = relationship("Email", back_populates="predictions")


class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    setting_key = Column(String(100), unique=True, index=True, nullable=False)
    setting_value_json = Column(Text, nullable=False)
    description = Column(String(255), nullable=True)
    updated_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
