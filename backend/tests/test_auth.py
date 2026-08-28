import pytest
from app.services.auth_analyzer import parse_authentication_headers


def test_auth_analyzer_pass():
    headers = [
        {"name": "Authentication-Results", "value": "mx.target.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com"}
    ]
    res = parse_authentication_headers(
        headers_list=headers,
        from_email="user@example.com",
        reply_to_email="user@example.com",
        sender_domain="example.com"
    )
    assert res["spf_result"] == "pass"
    assert res["dkim_result"] == "pass"
    assert res["dmarc_result"] == "pass"
    assert res["from_reply_to_aligned"] is True
    assert res["is_lookalike_domain_auth"] is False


def test_auth_analyzer_lookalike_trap():
    headers = [
        {"name": "Authentication-Results", "value": "mx.target.com; spf=pass smtp.mailfrom=paypa1.com; dkim=pass header.d=paypa1.com; dmarc=pass action=none header.from=paypa1.com"}
    ]
    res = parse_authentication_headers(
        headers_list=headers,
        from_email="security@paypa1.com",
        reply_to_email="drop@other-domain.com",
        sender_domain="paypa1.com"
    )
    assert res["spf_result"] == "pass"
    assert res["is_lookalike_domain_auth"] is True
    assert res["from_reply_to_aligned"] is False
