import os
import pytest
from app.services.header_parser import parse_email_message
from app.services.auth_analyzer import parse_authentication_headers
from app.services.sender_domain_analyzer import analyze_sender_and_domain
from app.services.content_analyzer import analyze_email_content
from app.services.url_analyzer import extract_and_analyze_urls
from app.services.attachment_analyzer import analyze_attachments_list
from app.services.risk_engine import calculate_comprehensive_risk

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_data")


def run_full_pipeline_on_file(filename: str):
    path = os.path.join(SAMPLE_DIR, filename)
    with open(path, "rb") as f:
        raw_bytes = f.read()

    parsed = parse_email_message(raw_bytes)
    auth = parse_authentication_headers(
        headers_list=parsed["all_headers"],
        from_email=parsed["from_email"],
        reply_to_email=parsed["reply_to_email"],
        sender_domain=parsed["sender_domain"]
    )
    sender_dom = analyze_sender_and_domain(parsed["raw_from"], parsed["raw_reply_to"])
    content = analyze_email_content(parsed["sanitized_body_text"], parsed["sanitized_body_html"], parsed["raw_subject"])
    urls, url_risk = extract_and_analyze_urls(parsed["sanitized_body_text"], parsed["sanitized_body_html"], parsed["sender_domain"])
    atts, att_risk = analyze_attachments_list(parsed["attachments"])

    risk = calculate_comprehensive_risk(
        header_data=parsed,
        auth_data=auth,
        sender_domain_data=sender_dom,
        content_data=content,
        url_data=urls,
        url_risk_score=url_risk,
        attachment_data=atts,
        attachment_risk_score=att_risk,
        threat_intel_matches=[],
        threat_intel_score=0.0
    )
    return parsed, auth, sender_dom, content, urls, atts, risk


def test_scenario_a_lookalike_phishing():
    parsed, auth, sender_dom, content, urls, atts, risk = run_full_pipeline_on_file("scenario_a_lookalike.eml")
    assert sender_dom["brand_matches"] or sender_dom["has_homoglyph"] or "paypa1" in parsed["sender_domain"]
    assert risk["total_risk_score"] >= 35.0
    assert risk["risk_classification"] in ["High risk", "Critical", "Suspicious"]


def test_scenario_b_executive_impersonation():
    parsed, auth, sender_dom, content, urls, atts, risk = run_full_pipeline_on_file("scenario_b_executive_impersonation.eml")
    assert sender_dom["is_freemail_abuse"] is True
    assert len(content["financial_cues"]) > 0 or len(content["confidentiality_cues"]) > 0
    assert risk["total_risk_score"] >= 25.0


def test_scenario_c_bec_compromised_legit_domain():
    parsed, auth, sender_dom, content, urls, atts, risk = run_full_pipeline_on_file("scenario_c_bec_compromised.eml")
    # SPF passes because domain was legitimate
    assert auth["spf_result"] == "pass"
    # But content raises financial risk
    assert len(content["financial_cues"]) > 0


def test_scenario_d_malicious_attachment():
    parsed, auth, sender_dom, content, urls, atts, risk = run_full_pipeline_on_file("scenario_d_malicious_attachment.eml")
    assert len(atts) == 1
    assert atts[0]["has_double_extension"] is True
    assert risk["total_risk_score"] >= 30.0


def test_scenario_e_legitimate():
    parsed, auth, sender_dom, content, urls, atts, risk = run_full_pipeline_on_file("scenario_e_legitimate.eml")
    assert auth["spf_result"] == "pass"
    assert auth["dkim_result"] == "pass"
    assert auth["dmarc_result"] == "pass"
    assert risk["risk_classification"] == "Low risk"
