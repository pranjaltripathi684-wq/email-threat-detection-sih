import pytest
from app.core.security import mask_email, create_access_token, decode_token
from app.services.url_analyzer import extract_and_analyze_urls


def test_pii_email_masking():
    assert mask_email("analyst@example.com", mask_enabled=True) == "a***t@example.com"
    assert mask_email("hr@company.com", mask_enabled=True) == "h***@company.com"
    assert mask_email("analyst@example.com", mask_enabled=False) == "analyst@example.com"


def test_jwt_token_security():
    token = create_access_token(subject="auditor_user", role="Auditor")
    payload = decode_token(token)
    assert payload["sub"] == "auditor_user"
    assert payload["role"] == "Auditor"
    assert payload["type"] == "access"


def test_ssrf_and_ip_url_detection():
    html_sample = (
        '<a href="http://169.254.169.254/latest/meta-data/">Cloud Metadata</a>'
        '<a href="http://127.0.0.1:8080/internal-api">Internal Admin</a>'
    )
    urls, risk = extract_and_analyze_urls(body_text="", body_html=html_sample)
    assert len(urls) == 2
    assert any(u["is_ip_based"] for u in urls)
    assert any(u["has_suspicious_port"] for u in urls)
