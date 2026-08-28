import json
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.models import (
    Email, EmailHeader, ReceivedHop, AuthenticationResult, EmailUrl,
    EmailAttachment, IPEnrichment, DomainEnrichment, ThreatIntelligenceMatch,
    ModelPrediction, Alert, Indicator, utcnow
)
from app.services.header_parser import parse_email_message
from app.services.auth_analyzer import parse_authentication_headers
from app.services.sender_domain_analyzer import analyze_sender_and_domain
from app.services.content_analyzer import analyze_email_content
from app.services.url_analyzer import extract_and_analyze_urls
from app.services.attachment_analyzer import analyze_attachments_list
from app.services.enrichment import enrich_ip_address, enrich_domain, check_threat_intelligence
from app.services.risk_engine import calculate_comprehensive_risk
from app.services.ml_engine import ml_pipeline
from app.services.correlation_engine import build_and_sync_email_graph


def process_and_analyze_email(db: Session, email: Email, raw_bytes: bytes) -> Email:
    """
    Executes the end-to-end multi-layer forensic analysis pipeline on an ingested email.
    """
    # 1. Header & Message Parsing
    parsed_msg = parse_email_message(raw_bytes)
    
    email.raw_subject = parsed_msg.get("raw_subject")
    email.raw_from = parsed_msg.get("raw_from")
    email.raw_to = parsed_msg.get("raw_to")
    email.raw_cc = parsed_msg.get("raw_cc")
    email.raw_reply_to = parsed_msg.get("raw_reply_to")
    email.raw_return_path = parsed_msg.get("raw_return_path")
    email.raw_date = parsed_msg.get("raw_date")
    email.message_id = parsed_msg.get("message_id")
    email.sender_domain = parsed_msg.get("sender_domain")
    email.reply_to_domain = parsed_msg.get("reply_to_domain")
    email.sanitized_body_text = parsed_msg.get("sanitized_body_text")
    email.sanitized_body_html = parsed_msg.get("sanitized_body_html")
    email.earliest_public_ip = parsed_msg.get("earliest_public_ip")

    # 2. Authentication Analysis (SPF, DKIM, DMARC, ARC)
    auth_data = parse_authentication_headers(
        headers_list=parsed_msg.get("all_headers", []),
        from_email=parsed_msg.get("from_email", ""),
        reply_to_email=parsed_msg.get("reply_to_email", ""),
        sender_domain=parsed_msg.get("sender_domain")
    )

    # 3. Sender Identity & Domain Analysis
    sender_data = analyze_sender_and_domain(
        raw_from=parsed_msg.get("raw_from", ""),
        raw_reply_to=parsed_msg.get("raw_reply_to", "")
    )

    # 4. Content & NLP Heuristics
    content_data = analyze_email_content(
        body_text=parsed_msg.get("sanitized_body_text", ""),
        body_html=parsed_msg.get("sanitized_body_html", ""),
        subject=parsed_msg.get("raw_subject", "")
    )

    # 5. URL Extraction & Inspection
    url_items, url_risk = extract_and_analyze_urls(
        body_text=parsed_msg.get("sanitized_body_text", ""),
        body_html=parsed_msg.get("sanitized_body_html", ""),
        sender_domain=parsed_msg.get("sender_domain", "")
    )

    # 6. Static Attachment Analysis
    att_items, att_risk = analyze_attachments_list(parsed_msg.get("attachments", []))

    # 7. Threat Intelligence Enrichment
    indicators_to_check = []
    if email.earliest_public_ip:
        indicators_to_check.append({"value": email.earliest_public_ip, "type": "ip"})
    if email.sender_domain:
        indicators_to_check.append({"value": email.sender_domain, "type": "domain"})
    for u in url_items:
        indicators_to_check.append({"value": u["raw_url"], "type": "url"})
    for a in att_items:
        indicators_to_check.append({"value": a["sha256_hash"], "type": "hash"})

    threat_matches, threat_intel_score = check_threat_intelligence(indicators_to_check)

    # 8. Explainable 7-Tier Risk Scoring
    risk_assessment = calculate_comprehensive_risk(
        header_data=parsed_msg,
        auth_data=auth_data,
        sender_domain_data=sender_data,
        content_data=content_data,
        url_data=url_items,
        url_risk_score=url_risk,
        attachment_data=att_items,
        attachment_risk_score=att_risk,
        threat_intel_matches=threat_matches,
        threat_intel_score=threat_intel_score
    )

    email.total_risk_score = risk_assessment["total_risk_score"]
    email.risk_classification = risk_assessment["risk_classification"]
    email.confidence_score = risk_assessment["confidence_score"]
    email.score_breakdown_json = json.dumps(risk_assessment["score_breakdown"])
    email.positive_evidence_json = json.dumps(risk_assessment["positive_evidence"])
    email.negative_evidence_json = json.dumps(risk_assessment["negative_evidence"])
    email.missing_evidence_json = json.dumps(risk_assessment["missing_evidence"])
    email.recommended_action = risk_assessment["recommended_action"]

    # 9. ML Inference Prediction
    ml_res = ml_pipeline.predict(
        subject=parsed_msg.get("raw_subject", ""),
        body_text=parsed_msg.get("sanitized_body_text", "")
    )

    # Enrich earliest public IP geo details on email
    if email.earliest_public_ip:
        ip_geo = enrich_ip_address(email.earliest_public_ip)
        email.earliest_public_ip_country = ip_geo.get("country")
        email.earliest_public_ip_city = ip_geo.get("city")
        email.earliest_public_ip_org = ip_geo.get("org")

    # Clear any previous child records if re-analyzing
    db.query(EmailHeader).filter(EmailHeader.email_id == email.id).delete()
    db.query(ReceivedHop).filter(ReceivedHop.email_id == email.id).delete()
    db.query(AuthenticationResult).filter(AuthenticationResult.email_id == email.id).delete()
    db.query(EmailUrl).filter(EmailUrl.email_id == email.id).delete()
    db.query(EmailAttachment).filter(EmailAttachment.email_id == email.id).delete()
    db.query(ThreatIntelligenceMatch).filter(ThreatIntelligenceMatch.email_id == email.id).delete()
    db.query(ModelPrediction).filter(ModelPrediction.email_id == email.id).delete()

    # Save Headers
    for h in parsed_msg.get("all_headers", []):
        eh = EmailHeader(
            email_id=email.id,
            header_name=h["name"],
            header_value=h["value"]
        )
        db.add(eh)

    # Save Received Hops with Geo
    for hop in parsed_msg.get("hops", []):
        geo_info = {}
        if hop.get("extracted_ip") and hop.get("ip_classification") == "Public":
            geo_info = enrich_ip_address(hop["extracted_ip"])

        rh = ReceivedHop(
            email_id=email.id,
            hop_order=hop["hop_order"],
            receiving_server=hop.get("receiving_server"),
            sending_server=hop.get("sending_server"),
            extracted_ip=hop.get("extracted_ip"),
            ip_classification=hop.get("ip_classification"),
            timestamp_raw=hop.get("timestamp_raw"),
            timestamp_utc=hop.get("timestamp_utc"),
            time_delta_seconds=hop.get("time_delta_seconds", 0.0),
            tls_status=hop.get("tls_status", False),
            tls_cipher=hop.get("tls_cipher"),
            is_earliest_reliable_public_ip=hop.get("is_earliest_reliable_public_ip", False),
            anomaly_flags="; ".join(hop.get("anomalies", [])),
            raw_hop_value=hop.get("raw"),
            geo_country=geo_info.get("country"),
            geo_city=geo_info.get("city"),
            geo_lat=geo_info.get("latitude"),
            geo_lon=geo_info.get("longitude"),
            asn_org=geo_info.get("org")
        )
        db.add(rh)

    # Save Authentication Results
    ar = AuthenticationResult(
        email_id=email.id,
        spf_result=auth_data["spf_result"],
        spf_domain=auth_data["spf_domain"],
        spf_scope=auth_data["spf_scope"],
        dkim_present=auth_data["dkim_present"],
        dkim_result=auth_data["dkim_result"],
        dkim_domain=auth_data["dkim_domain"],
        dkim_selector=auth_data["dkim_selector"],
        dkim_body_hash_valid=auth_data["dkim_body_hash_valid"],
        dmarc_result=auth_data["dmarc_result"],
        dmarc_policy=auth_data["dmarc_policy"],
        dmarc_alignment=auth_data["dmarc_alignment"],
        dmarc_from_domain=auth_data["dmarc_from_domain"],
        arc_present=auth_data["arc_present"],
        arc_result=auth_data["arc_result"],
        from_reply_to_aligned=auth_data["from_reply_to_aligned"],
        is_lookalike_domain_auth=auth_data["is_lookalike_domain_auth"],
        natural_language_explanation=auth_data["natural_language_explanation"]
    )
    db.add(ar)

    # Save URLs
    for u in url_items:
        eu = EmailUrl(
            email_id=email.id,
            raw_url=u["raw_url"],
            display_text=u.get("display_text"),
            domain=u.get("domain"),
            is_ip_based=u.get("is_ip_based", False),
            is_punycode=u.get("is_punycode", False),
            is_shortened=u.get("is_shortened", False),
            is_deceptive=u.get("is_deceptive", False),
            has_suspicious_port=u.get("has_suspicious_port", False),
            path_entropy=u.get("path_entropy", 0.0),
            risk_score=u.get("risk_score", 0.0),
            risk_reasons_json=json.dumps(u.get("risk_reasons", []))
        )
        db.add(eu)

    # Save Attachments
    for a in att_items:
        ea = EmailAttachment(
            email_id=email.id,
            filename=a["filename"],
            file_extension=a["file_extension"],
            declared_mime_type=a["declared_mime_type"],
            magic_file_type=a["magic_file_type"],
            file_size=a["file_size"],
            sha256_hash=a["sha256_hash"],
            md5_hash=a["md5_hash"],
            has_double_extension=a["has_double_extension"],
            has_macros=a["has_macros"],
            is_script_or_executable=a["is_script_or_executable"],
            is_password_protected=a["is_password_protected"],
            risk_score=a["risk_score"],
            risk_reasons_json=json.dumps(a["risk_reasons"])
        )
        db.add(ea)

    # Save Threat Intel Matches
    for m in threat_matches:
        tm = ThreatIntelligenceMatch(
            email_id=email.id,
            indicator_value=m["indicator_value"],
            indicator_type=m["indicator_type"],
            provider_name=m["provider_name"],
            severity=m["severity"],
            confidence=m["confidence"],
            match_details_json=json.dumps({"details": m["match_details"]})
        )
        db.add(tm)

    # Save Model Prediction
    mp = ModelPrediction(
        email_id=email.id,
        model_name="TF-IDF + Calibrated Classifier",
        model_version="v1.0-academic",
        predicted_class=ml_res["predicted_class"],
        probability_score=ml_res["probability_score"],
        top_features_json=json.dumps(ml_res["top_features"]),
        inference_time_ms=ml_res["inference_time_ms"]
    )
    db.add(mp)

    # Create Alert if High or Critical Risk
    if email.total_risk_score >= settings.RISK_THRESHOLD_SUSPICIOUS:
        alert = Alert(
            email_id=email.id,
            title=f"{email.risk_classification} Threat: {email.raw_subject or 'Suspicious Email'}"[:250],
            severity=email.risk_classification,
            category=ml_res["predicted_class"],
            is_acknowledged=False
        )
        db.add(alert)

    db.commit()
    db.refresh(email)

    # Sync entity relationships to Graph
    build_and_sync_email_graph(db, email.id)

    return email
