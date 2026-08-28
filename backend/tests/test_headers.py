import pytest
from datetime import datetime, timezone
from app.services.header_parser import classify_ip_address, extract_ip_from_text, parse_received_header_clause, parse_email_message


def test_ip_classifier():
    assert classify_ip_address("127.0.0.1") == "Loopback"
    assert classify_ip_address("10.0.0.1") == "Private"
    assert classify_ip_address("172.16.5.1") == "Private"
    assert classify_ip_address("192.168.1.100") == "Private"
    assert classify_ip_address("169.254.1.1") == "Link-local"
    assert classify_ip_address("8.8.8.8") == "Public"
    assert classify_ip_address("185.220.101.5") == "Public"
    assert classify_ip_address("240.0.0.1") == "Bogon/Reserved"
    assert classify_ip_address("invalid-ip") == "Invalid"
    assert classify_ip_address(None) == "Unknown"


def test_extract_ip_from_text():
    text = "from mail.example.com (mail.example.com [198.51.100.42]) by mx.target.com"
    assert extract_ip_from_text(text) == "198.51.100.42"
    
    text_v6 = "from node.domain (node [2001:0db8:85a3:0000:0000:8a2e:0370:7334])"
    assert extract_ip_from_text(text_v6) == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


def test_parse_received_header_clause():
    raw_hop = "from relay.sender.com (relay.sender.com [45.33.32.156]) by mx.receiver.com (Postfix) with ESMTPS id 4K8zP; Mon, 25 Aug 2026 14:10:00 +0000"
    res = parse_received_header_clause(raw_hop)
    assert res["extracted_ip"] == "45.33.32.156"
    assert res["ip_classification"] == "Public"
    assert res["tls_status"] is True
    assert res["timestamp_utc"] is not None


def test_parse_email_message():
    eml_raw = (
        b"From: \"Alert Security\" <security@example.com>\r\n"
        b"To: <user@company.com>\r\n"
        b"Subject: Test Security Alert\r\n"
        b"Date: Mon, 25 Aug 2026 14:00:00 +0000\r\n"
        b"Message-ID: <test-123@example.com>\r\n"
        b"Received: from relay.example.com (relay.example.com [198.51.100.42]) by mx.company.com; Mon, 25 Aug 2026 14:01:00 +0000\r\n"
        b"\r\n"
        b"Please verify your credentials immediately at http://login-verify.com"
    )
    parsed = parse_email_message(eml_raw)
    assert parsed["from_email"] == "security@example.com"
    assert parsed["sender_domain"] == "example.com"
    assert parsed["earliest_public_ip"] == "198.51.100.42"
    assert len(parsed["hops"]) == 1
    assert "verify your credentials" in parsed["sanitized_body_text"]
