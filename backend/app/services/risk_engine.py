import json
from typing import Dict, Any, List, Tuple
from app.core.config import settings


def evaluate_header_anomalies(parsed_headers: Dict[str, Any], hops: List[Dict[str, Any]]) -> Tuple[float, List[str], List[str]]:
    """Evaluates header risk score (0 to 20)."""
    score = 0.0
    positive_evidence = []
    mitigating_evidence = []

    # Check Message-ID presence and format
    msg_id = parsed_headers.get("message_id", "")
    if not msg_id:
        score += 6.0
        positive_evidence.append("Missing standard RFC 5322 Message-ID header")
    elif not ("<" in msg_id and "@" in msg_id and ">" in msg_id):
        score += 3.0
        positive_evidence.append(f"Malformed non-standard Message-ID structure: '{msg_id}'")

    # Check Hop anomalies
    hop_anomalies = []
    bogon_found = False
    for hop in hops:
        for anom in hop.get("anomalies", []):
            hop_anomalies.append(anom)
        if hop.get("ip_classification") == "Bogon/Reserved":
            bogon_found = True

    if bogon_found:
        score += 6.0
        positive_evidence.append("Bogon or reserved unroutable IP address observed in intermediate relay hops")
    if hop_anomalies:
        score += min(6.0, len(hop_anomalies) * 2.0)
        positive_evidence.extend(hop_anomalies)

    # Check TLS coverage
    tls_hops = sum(1 for h in hops if h.get("tls_status"))
    if hops and tls_hops == len(hops):
        mitigating_evidence.append(f"All {len(hops)} intermediate transmission hops utilized TLS encryption")
    elif hops and tls_hops == 0:
        score += 3.0
        positive_evidence.append("Transmission occurred entirely over unencrypted plaintext SMTP channels")

    return min(settings.WEIGHT_HEADERS, score), positive_evidence, mitigating_evidence


def evaluate_authentication_risk(auth_res: Dict[str, Any]) -> Tuple[float, List[str], List[str]]:
    """Evaluates authentication and alignment risk score (0 to 20)."""
    score = 0.0
    positive_evidence = []
    mitigating_evidence = []

    spf_res = auth_res.get("spf_result", "none").lower()
    dkim_res = auth_res.get("dkim_result", "none").lower()
    dmarc_res = auth_res.get("dmarc_result", "none").lower()
    from_reply_aligned = auth_res.get("from_reply_to_aligned", True)
    is_lookalike_auth = auth_res.get("is_lookalike_domain_auth", False)

    # SPF scoring
    if spf_res in ["fail", "permerror"]:
        score += 6.0
        positive_evidence.append(f"Sender Policy Framework (SPF) failed verification: '{spf_res}'")
    elif spf_res == "softfail":
        score += 3.0
        positive_evidence.append("SPF softfail: Originating IP is not explicitly authorized in sender SPF record")
    elif spf_res == "pass":
        mitigating_evidence.append("SPF authentication passed")

    # DKIM scoring
    if dkim_res == "fail":
        score += 6.0
        positive_evidence.append("DKIM cryptographic signature verification failed (possible tampering or forgery)")
    elif dkim_res == "none" and not auth_res.get("dkim_present"):
        score += 2.0
        positive_evidence.append("No DKIM digital signature present on message")
    elif dkim_res == "pass":
        mitigating_evidence.append("DKIM cryptographic signature verified")

    # DMARC & Alignment scoring
    if dmarc_res == "fail" or auth_res.get("dmarc_alignment") == "unaligned":
        score += 6.0
        positive_evidence.append("DMARC alignment failure: Sender domain could not be verified against SPF/DKIM")
    elif dmarc_res == "pass":
        mitigating_evidence.append("DMARC alignment verified (sender identity aligned with authentication records)")

    # From vs Reply-To Mismatch
    if not from_reply_aligned:
        score += 5.0
        positive_evidence.append("Reply-To address domain differs from visible From sender domain (Reply Redirection Vector)")

    # Lookalike Domain Trap
    if is_lookalike_auth:
        score += 8.0
        positive_evidence.append("Authentic Lookalike Trap: Email passed SPF/DKIM authentication for a registered typosquatting/phishing domain")

    return min(settings.WEIGHT_AUTH, score), positive_evidence, mitigating_evidence


def calculate_comprehensive_risk(
    header_data: Dict[str, Any],
    auth_data: Dict[str, Any],
    sender_domain_data: Dict[str, Any],
    content_data: Dict[str, Any],
    url_data: List[Dict[str, Any]],
    url_risk_score: float,
    attachment_data: List[Dict[str, Any]],
    attachment_risk_score: float,
    threat_intel_matches: List[Dict[str, Any]],
    threat_intel_score: float
) -> Dict[str, Any]:
    """
    Computes total explainable threat score across 7 distinct categories (0-100),
    providing positive and mitigating evidence, confidence, and recommended responses.
    """
    # 1. Header Anomalies (0-20)
    header_score, header_pos, header_neg = evaluate_header_anomalies(header_data, header_data.get("hops", []))
    
    # 2. Authentication (0-20)
    auth_score, auth_pos, auth_neg = evaluate_authentication_risk(auth_data)
    
    # 3. Sender & Domain Impersonation (0-15)
    sender_score = float(sender_domain_data.get("domain_risk_score", 0.0))
    sender_pos = sender_domain_data.get("anomalies", [])
    sender_neg = []
    if not sender_pos and not sender_domain_data.get("is_freemail"):
        sender_neg.append("Sender domain matches established domain without homoglyphs or brand impersonation")

    # 4. Content & NLP Social Engineering (0-15)
    content_score = float(content_data.get("content_risk_score", 0.0))
    
    # Compound Signal: VIP Display Name + Freemail Provider + Financial/Gift-card Cues
    if sender_domain_data.get("is_freemail_abuse") and (content_data.get("financial_cues") or content_data.get("confidentiality_cues")):
        sender_score = min(settings.WEIGHT_SENDER_DOMAIN, sender_score + 5.0)
        sender_pos.append("High-Confidence Executive Impersonation Pattern: VIP display name + freemail origin requesting financial/confidential action")

    content_pos = []
    if content_data.get("urgency_cues"):
        content_pos.append(f"Urgency / Time-Pressure Language detected: {', '.join(content_data['urgency_cues'][:3])}")
    if content_data.get("financial_cues"):
        content_pos.append(f"Financial / Wire Transfer / Payment modification requests: {', '.join(content_data['financial_cues'][:3])}")
    if content_data.get("credential_cues"):
        content_pos.append(f"Credential Harvesting / Password verification requests: {', '.join(content_data['credential_cues'][:3])}")
    if content_data.get("has_forms") or content_data.get("has_scripts"):
        content_pos.append("Embedded interactive forms or scripts discovered in message body")
    content_neg = []
    if not content_pos:
        content_neg.append("No common social engineering, credential harvesting, or urgency triggers identified")

    # 5. URL Risk (0-15)
    url_score = float(url_risk_score)
    url_pos = []
    for u in url_data:
        for r in u.get("risk_reasons", []):
            url_pos.append(r)
    url_neg = []
    if url_data and not url_pos:
        url_neg.append(f"All {len(url_data)} extracted URLs point to legitimate, HTTPS-encrypted standard domains")
    elif not url_data:
        url_neg.append("No external hyperlink destinations embedded in email body")

    # 6. Attachment Risk (0-10)
    att_score = float(attachment_risk_score)
    att_pos = []
    for a in attachment_data:
        for r in a.get("risk_reasons", []):
            att_pos.append(r)
    att_neg = []
    if attachment_data and not att_pos:
        att_neg.append(f"All {len(attachment_data)} attachments passed static magic-byte and extension consistency checks")
    elif not attachment_data:
        att_neg.append("No file attachments present in message")

    # 7. Threat Intel (0-5)
    intel_score = float(threat_intel_score)
    intel_pos = []
    for match in threat_intel_matches:
        intel_pos.append(f"{match['provider_name']} Flagged '{match['indicator_value']}': {match['match_details']}")
    intel_neg = []
    if not threat_intel_matches:
        intel_neg.append("No active indicators matched known threat feeds or blocklists")

    # Total Score Calculation (Capped at 100)
    total_score = round(min(100.0, header_score + auth_score + sender_score + content_score + url_score + att_score + intel_score), 1)

    # Classification
    if total_score >= settings.RISK_THRESHOLD_HIGH:
        classification = "Critical"
    elif total_score >= settings.RISK_THRESHOLD_SUSPICIOUS:
        classification = "High risk"
    elif total_score >= settings.RISK_THRESHOLD_LOW:
        classification = "Suspicious"
    else:
        classification = "Low risk"

    # Positive Evidence Aggregation
    all_positive = header_pos + auth_pos + sender_pos + content_pos + url_pos + att_pos + intel_pos
    all_negative = header_neg + auth_neg + sender_neg + content_neg + url_neg + att_neg + intel_neg
    
    missing_evidence = []
    if not header_data.get("hops"):
        missing_evidence.append("Received headers missing or incomplete (relay path could not be fully traced)")
    if auth_data.get("dkim_result") == "none":
        missing_evidence.append("DKIM public key record could not be retrieved from DNS")

    # Confidence calculation based on evidence completeness
    signal_count = len(all_positive) + len(all_negative)
    confidence = min(0.98, max(0.65, 0.70 + (signal_count * 0.02)))

    # Recommended Action Generator
    if classification == "Critical":
        recommended_action = (
            "CRITICAL THREAT: Immediately isolate recipient endpoint if links were accessed or attachments opened. "
            "Block sender domain, destination URLs, and earliest public relay IP at perimeter mail and firewall gateways. "
            "Initiate incident response ticket and preserve raw .eml evidence."
        )
    elif classification == "High risk":
        recommended_action = (
            "HIGH RISK: Quarantine message across enterprise mailboxes. Flag lookalike domain in threat intelligence repository. "
            "Warn target recipient against clicking links or executing attachments. Verify transaction requests via secondary out-of-band communication."
        )
    elif classification == "Suspicious":
        recommended_action = (
            "SUSPICIOUS: Deliver with warning banner or route to analyst review queue. Monitor for correlated messages in current campaign. "
            "Advise recipient to exercise caution with unverified payment requests."
        )
    else:
        recommended_action = (
            "LOW RISK: Message conforms to legitimate communication standards. Full authentication alignment verified. "
            "Standard delivery permitted."
        )

    score_breakdown = {
        "headers": {"score": round(header_score, 1), "max": settings.WEIGHT_HEADERS},
        "authentication": {"score": round(auth_score, 1), "max": settings.WEIGHT_AUTH},
        "sender_domain": {"score": round(sender_score, 1), "max": settings.WEIGHT_SENDER_DOMAIN},
        "content_nlp": {"score": round(content_score, 1), "max": settings.WEIGHT_CONTENT_NLP},
        "urls": {"score": round(url_score, 1), "max": settings.WEIGHT_URLS},
        "attachments": {"score": round(att_score, 1), "max": settings.WEIGHT_ATTACHMENTS},
        "threat_intel": {"score": round(intel_score, 1), "max": settings.WEIGHT_THREAT_INTEL}
    }

    return {
        "total_risk_score": total_score,
        "risk_classification": classification,
        "confidence_score": round(confidence, 2),
        "score_breakdown": score_breakdown,
        "positive_evidence": all_positive,
        "negative_evidence": all_negative,
        "missing_evidence": missing_evidence,
        "recommended_action": recommended_action
    }
