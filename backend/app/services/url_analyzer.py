import re
import math
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Tuple

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "tiny.cc", "goo.gl", "rebrand.ly", "bl.ink"
}

SUSPICIOUS_URL_EXTENSIONS = {
    ".exe", ".scr", ".zip", ".vbs", ".iso", ".bat", ".cmd", ".ps1", ".hta", ".apk"
}


def calculate_entropy(s: str) -> float:
    """Calculates Shannon entropy of a string (measure of randomness/obfuscation)."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


def extract_and_analyze_urls(body_text: str, body_html: str, sender_domain: str = "") -> Tuple[List[Dict[str, Any]], float]:
    """
    Extracts all URLs from plain text and HTML, checking for deceptive anchors,
    IP-based destinations, shorteners, high entropy, and malicious patterns.
    """
    extracted_urls: List[Dict[str, Any]] = []
    seen_urls = set()

    # 1. Extract from HTML anchors (gives display text + destination)
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                display_text = a_tag.get_text(strip=True)
                if href and href.startswith(("http://", "https://", "ftp://")) and href not in seen_urls:
                    seen_urls.add(href)
                    extracted_urls.append({
                        "raw_url": href,
                        "display_text": display_text,
                        "source": "html_anchor"
                    })
        except Exception:
            pass

    # 2. Extract plain text URLs using Regex
    url_pattern = r'https?://[^\s<>"\')]+'
    found_plain = re.findall(url_pattern, body_text or "")
    for u in found_plain:
        u_clean = u.rstrip(".,;!?:")
        if u_clean not in seen_urls:
            seen_urls.add(u_clean)
            extracted_urls.append({
                "raw_url": u_clean,
                "display_text": u_clean,
                "source": "plain_text"
            })

    # Detailed Analysis of each URL
    total_url_risk = 0.0
    analyzed_list = []

    for item in extracted_urls:
        raw_url = item["raw_url"]
        display_text = item.get("display_text", "")
        
        parsed = urlparse(raw_url)
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        path = parsed.path
        
        is_ip_based = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', hostname))
        is_punycode = "xn--" in hostname
        is_shortened = hostname in SHORTENER_DOMAINS
        has_suspicious_port = bool(port and port not in [80, 443])
        path_entropy = calculate_entropy(path)
        
        # Deceptive Link Check: display text looks like a domain/URL but points somewhere else
        is_deceptive = False
        if display_text and ("http" in display_text.lower() or "." in display_text):
            display_clean = display_text.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()
            if "." in display_clean and hostname and not (display_clean in hostname or hostname in display_clean):
                is_deceptive = True

        reasons = []
        item_risk = 0.0

        if is_deceptive:
            item_risk += 7.0
            reasons.append(f"Deceptive Link: Visible anchor '{display_text}' does not match actual destination '{hostname}'")
        if is_ip_based:
            item_risk += 6.0
            reasons.append(f"Direct IP-based URL destination: '{hostname}'")
        if is_punycode:
            item_risk += 5.0
            reasons.append(f"Punycode internationalized domain: '{hostname}'")
        if is_shortened:
            item_risk += 4.0
            reasons.append(f"Obfuscated via URL shortener service: '{hostname}'")
        if has_suspicious_port:
            item_risk += 3.0
            reasons.append(f"Non-standard HTTP port observed: ':{port}'")
        if any(path.lower().endswith(ext) for ext in SUSPICIOUS_URL_EXTENSIONS):
            item_risk += 6.0
            reasons.append("URL directly downloads executable or script payload")
        if path_entropy > 4.5:
            item_risk += 2.0
            reasons.append(f"High-entropy randomized path: {path_entropy:.2f}")

        item_risk = min(15.0, item_risk)
        total_url_risk = max(total_url_risk, item_risk)

        analyzed_list.append({
            "raw_url": raw_url,
            "display_text": display_text,
            "domain": hostname,
            "is_ip_based": is_ip_based,
            "is_punycode": is_punycode,
            "is_shortened": is_shortened,
            "is_deceptive": is_deceptive,
            "has_suspicious_port": has_suspicious_port,
            "path_entropy": round(path_entropy, 2),
            "risk_score": round(item_risk, 1),
            "risk_reasons": reasons
        })

    return analyzed_list, min(15.0, total_url_risk)
