import pytest
from app.services.risk_engine import calculate_comprehensive_risk


def test_clean_email_scoring():
    header_data = {"message_id": "<valid@company.com>", "hops": [{"tls_status": True, "ip_classification": "Public", "anomalies": []}]}
    auth_data = {"spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass", "dmarc_alignment": "strict", "from_reply_to_aligned": True, "is_lookalike_domain_auth": False}
    sender_domain_data = {"domain_risk_score": 0.0, "anomalies": [], "is_freemail": False}
    content_data = {"content_risk_score": 0.0, "urgency_cues": [], "financial_cues": [], "credential_cues": [], "has_forms": False, "has_scripts": False}
    url_data = []
    att_data = []
    intel_matches = []

    res = calculate_comprehensive_risk(
        header_data=header_data,
        auth_data=auth_data,
        sender_domain_data=sender_domain_data,
        content_data=content_data,
        url_data=url_data,
        url_risk_score=0.0,
        attachment_data=att_data,
        attachment_risk_score=0.0,
        threat_intel_matches=intel_matches,
        threat_intel_score=0.0
    )

    assert res["total_risk_score"] < 25.0
    assert res["risk_classification"] == "Low risk"
    assert len(res["negative_evidence"]) > 0


def test_critical_phishing_scoring():
    header_data = {"message_id": None, "hops": []}
    auth_data = {"spf_result": "fail", "dkim_result": "none", "dmarc_result": "fail", "dmarc_alignment": "unaligned", "from_reply_to_aligned": False, "is_lookalike_domain_auth": True}
    sender_domain_data = {"domain_risk_score": 12.0, "anomalies": ["Lookalike domain"], "is_freemail": False}
    content_data = {"content_risk_score": 14.0, "urgency_cues": ["urgent response"], "credential_cues": ["verify your account"], "financial_cues": [], "has_forms": True}
    url_data = [{"risk_reasons": ["Deceptive link anchor"]}]
    att_data = [{"risk_reasons": ["Double extension .pdf.exe"]}]
    intel_matches = [{"provider_name": "VirusTotal", "indicator_value": "hash", "match_details": "Trojan"}]

    res = calculate_comprehensive_risk(
        header_data=header_data,
        auth_data=auth_data,
        sender_domain_data=sender_domain_data,
        content_data=content_data,
        url_data=url_data,
        url_risk_score=15.0,
        attachment_data=att_data,
        attachment_risk_score=10.0,
        threat_intel_matches=intel_matches,
        threat_intel_score=5.0
    )

    assert res["total_risk_score"] >= 75.0
    assert res["risk_classification"] == "Critical"
    assert "CRITICAL THREAT" in res["recommended_action"]
