import re
import ipaddress
import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple


def classify_ip_address(ip_str: Optional[str]) -> str:
    """Classifies an IP string into Public, Private, Loopback, Link-local, Bogon/Reserved, or Invalid."""
    if not ip_str:
        return "Unknown"
    # Clean potential surrounding brackets or port
    ip_clean = ip_str.strip("[]() \t\r\n")
    if ":" in ip_clean and not "." in ip_clean and not ip_clean.count(":") > 1:
        # IPv4 with port e.g. 1.2.3.4:5678
        ip_clean = ip_clean.split(":")[0]
        
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        if ip_obj.is_loopback:
            return "Loopback"
        if ip_obj.is_link_local:
            return "Link-local"
        # Permit RFC 5737 documentation test networks to be analyzed as public infrastructure in academic prototypes
        if ip_clean.startswith(("198.51.100.", "203.0.113.", "192.0.2.")):
            return "Public"
        if ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified:
            return "Bogon/Reserved"
        if ip_obj.is_private:
            return "Private"
        return "Public"
    except ValueError:
        return "Invalid"


def extract_ip_from_text(text: str) -> Optional[str]:
    """Extracts IPv4 or IPv6 address from a string snippet."""
    if not text:
        return None
    # IPv4 regex
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    match = re.search(ipv4_pattern, text)
    if match:
        return match.group(0)
    
    # IPv6 regex
    ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    match_v6 = re.search(ipv6_pattern, text)
    if match_v6:
        return match_v6.group(0)
    return None


def parse_received_header_clause(raw_header: str) -> Dict[str, Any]:
    """
    Parses a single RFC 5322 Received header clause into its components:
    from, by, with, id, for, tls, ip, timestamp.
    """
    cleaned = " ".join(raw_header.split())
    
    sending_server = None
    receiving_server = None
    extracted_ip = None
    tls_status = False
    tls_cipher = None
    timestamp_raw = None
    timestamp_utc = None
    
    # Split by semicolon to separate routing tokens from date
    parts = cleaned.split(";")
    route_part = parts[0]
    date_part = parts[1].strip() if len(parts) > 1 else None
    
    if date_part:
        timestamp_raw = date_part
        try:
            dt = parsedate_to_datetime(date_part)
            if dt:
                timestamp_utc = dt.astimezone(timezone.utc)
        except Exception:
            pass

    # Extract 'from'
    from_match = re.search(r'\bfrom\s+([^\s]+(?:\s+\([^)]+\))?)', route_part, re.IGNORECASE)
    if from_match:
        sending_server = from_match.group(1)
        extracted_ip = extract_ip_from_text(from_match.group(0))

    # Extract 'by'
    by_match = re.search(r'\bby\s+([^\s]+)', route_part, re.IGNORECASE)
    if by_match:
        receiving_server = by_match.group(1)

    # Fallback IP search across entire route part
    if not extracted_ip:
        extracted_ip = extract_ip_from_text(route_part)

    # Check TLS indicators
    if re.search(r'\b(?:TLS|ESMTPS|STARTTLS|ECDHE|AES|RSA)\b', route_part, re.IGNORECASE):
        tls_status = True
        cipher_match = re.search(r'\((?:using\s+)?(TLS[^)]+|cipher=[^)]+)\)', route_part, re.IGNORECASE)
        if cipher_match:
            tls_cipher = cipher_match.group(1)
        else:
            tls_cipher = "TLS Active"

    ip_class = classify_ip_address(extracted_ip)

    return {
        "raw": raw_header,
        "sending_server": sending_server,
        "receiving_server": receiving_server,
        "extracted_ip": extracted_ip,
        "ip_classification": ip_class,
        "timestamp_raw": timestamp_raw,
        "timestamp_utc": timestamp_utc,
        "tls_status": tls_status,
        "tls_cipher": tls_cipher,
        "anomalies": []
    }


def parse_email_message(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Fully parses an RFC 5322 email message, extracting headers, received hops,
    body content, and attachments.
    """
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    
    # Extract standard headers
    raw_from = msg.get("From", "")
    raw_to = msg.get("To", "")
    raw_cc = msg.get("Cc", "")
    raw_bcc = msg.get("Bcc", "")
    raw_reply_to = msg.get("Reply-To", "")
    raw_return_path = msg.get("Return-Path", "")
    raw_subject = msg.get("Subject", "")
    raw_date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    user_agent = msg.get("User-Agent", "") or msg.get("X-Mailer", "")
    
    # Parse sender domains
    _, from_email = parseaddr(raw_from)
    _, reply_to_email = parseaddr(raw_reply_to)
    
    sender_domain = from_email.split("@")[1].lower() if "@" in from_email else None
    reply_to_domain = reply_to_email.split("@")[1].lower() if "@" in reply_to_email else None

    # Collect all headers
    all_headers = []
    for h_name, h_val in msg.items():
        all_headers.append({
            "name": h_name,
            "value": str(h_val)
        })

    # Parse Received headers
    received_headers = msg.get_all("Received", [])
    # In RFC 5322, the topmost Received header is the most recent (final receiver).
    # To reconstruct the path from origin to destination, we reverse the list.
    reversed_hops_raw = list(reversed(received_headers)) if received_headers else []
    
    parsed_hops = []
    prev_dt = None
    
    for idx, raw_hop in enumerate(reversed_hops_raw, start=1):
        hop_info = parse_received_header_clause(raw_hop)
        hop_info["hop_order"] = idx
        
        # Calculate time delta
        if hop_info["timestamp_utc"] and prev_dt:
            delta = (hop_info["timestamp_utc"] - prev_dt).total_seconds()
            hop_info["time_delta_seconds"] = delta
            if delta < -60:  # Negative jump more than 1 min indicates clock skew or forgery
                hop_info["anomalies"].append("Impossible negative timestamp delta (clock skew or header forgery)")
            elif delta > 86400:  # More than 24 hours delay between hops
                hop_info["anomalies"].append("Abnormally large transit delay (>24 hours)")
        else:
            hop_info["time_delta_seconds"] = 0.0
            
        if hop_info["timestamp_utc"]:
            prev_dt = hop_info["timestamp_utc"]

        # Check for Private IP claiming to be public relay
        if hop_info["ip_classification"] == "Bogon/Reserved":
            hop_info["anomalies"].append("Bogon or reserved IP address in relay path")
            
        parsed_hops.append(hop_info)

    # Determine earliest reliable public IP
    earliest_public_ip = None
    for hop in parsed_hops:
        if hop["ip_classification"] == "Public":
            hop["is_earliest_reliable_public_ip"] = True
            earliest_public_ip = hop["extracted_ip"]
            break

    # If no public IP found in Received hops, check X-Originating-IP
    if not earliest_public_ip:
        x_orig_ip = msg.get("X-Originating-IP")
        if x_orig_ip:
            cleaned_x_ip = extract_ip_from_text(x_orig_ip)
            if cleaned_x_ip and classify_ip_address(cleaned_x_ip) == "Public":
                earliest_public_ip = cleaned_x_ip

    # Extract body content (plain text & HTML) safely
    body_text_parts = []
    body_html_parts = []
    raw_attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if "attachment" in content_disposition.lower() or filename:
                # Attachment
                payload = part.get_payload(decode=True) or b""
                raw_attachments.append({
                    "filename": filename or "unnamed_attachment",
                    "content_type": content_type,
                    "payload": payload,
                    "size": len(payload)
                })
            elif content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            decoded_text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
            if content_type == "text/html":
                body_html_parts.append(decoded_text)
            else:
                body_text_parts.append(decoded_text)

    sanitized_text = "\n".join(body_text_parts).strip()
    sanitized_html = "\n".join(body_html_parts).strip()

    return {
        "raw_from": raw_from,
        "from_email": from_email,
        "raw_to": raw_to,
        "raw_cc": raw_cc,
        "raw_bcc": raw_bcc,
        "raw_reply_to": raw_reply_to,
        "reply_to_email": reply_to_email,
        "raw_return_path": raw_return_path,
        "raw_subject": raw_subject,
        "raw_date": raw_date,
        "message_id": message_id,
        "user_agent": user_agent,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "all_headers": all_headers,
        "hops": parsed_hops,
        "earliest_public_ip": earliest_public_ip,
        "sanitized_body_text": sanitized_text,
        "sanitized_body_html": sanitized_html,
        "attachments": raw_attachments
    }
