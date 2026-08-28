import re
import unicodedata
from email.utils import parseaddr
from typing import Dict, Any, List, Optional, Tuple

KNOWN_TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "chase", "netflix",
    "wellsfargo", "bankofamerica", "citi", "facebook", "meta", "instagram",
    "linkedin", "dropbox", "docusign", "adobe", "office365", "outlook",
    "irs", "internal-support", "helpdesk", "it-support", "payroll", "hr-portal"
]

FREEMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "yandex.com", "zoho.com", "icloud.com",
    "gmx.com", "tutanota.com"
}

SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".icu", ".cyou", ".click", ".buzz", ".rest", ".tk",
    ".ml", ".ga", ".cf", ".gq", ".work", ".loan", ".racing", ".win", ".bid"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Calculates Jaro-Winkler string similarity (0.0 to 1.0)."""
    if not s1 or not s2:
        return 0.0
    if s1 == s2:
        return 1.0

    len1, len2 = len(s1), len(s2)
    match_distance = max(len1, len2) // 2 - 1
    if match_distance < 0:
        match_distance = 0

    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3.0
    
    # Winkler modification for common prefix up to 4 chars
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return jaro + (prefix * 0.1 * (1.0 - jaro))


def detect_homoglyphs_and_punycode(domain: str) -> Tuple[bool, List[str]]:
    """Checks for IDN / Punycode (xn--) and confusable homoglyph characters."""
    reasons = []
    is_homoglyph = False
    
    if not domain:
        return False, []

    if domain.startswith("xn--") or ".xn--" in domain:
        is_homoglyph = True
        reasons.append("Domain uses internationalized Punycode (xn--) notation")

    # Character substitutions common in typosquatting
    subs = [
        (r'0', 'o'), (r'1', 'l'), (r'rn', 'm'), (r'vv', 'w'), (r'cl', 'd'), (r'l', 'i')
    ]
    
    # Check for mixed scripts or non-ASCII
    for char in domain:
        if ord(char) > 127:
            is_homoglyph = True
            reasons.append(f"Non-ASCII Unicode character detected in domain: '{char}' (U+{ord(char):04X})")
            break

    return is_homoglyph, reasons


def analyze_sender_and_domain(raw_from: str, raw_reply_to: str) -> Dict[str, Any]:
    """
    Performs deep sender identity, display name, domain similarity,
    and impersonation analysis.
    """
    display_name, from_email = parseaddr(raw_from or "")
    reply_display, reply_email = parseaddr(raw_reply_to or "")
    
    sender_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
    reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""

    anomalies = []
    brand_matches = []
    is_display_spoofed = False
    is_freemail_abuse = False
    is_suspicious_tld = False
    subdomain_depth = sender_domain.count(".") if sender_domain else 0
    
    # Check Punycode & Homoglyphs
    has_homoglyph, homoglyph_reasons = detect_homoglyphs_and_punycode(sender_domain)
    anomalies.extend(homoglyph_reasons)

    # Check Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            is_suspicious_tld = True
            anomalies.append(f"Domain registered under high-abuse TLD: '{tld}'")
            break

    # Check Subdomain depth
    if subdomain_depth > 3:
        anomalies.append(f"Excessive subdomain depth ({subdomain_depth} levels) in sender domain")

    # Check Freemail abuse with VIP/Executive or Corporate Display Name
    is_freemail = sender_domain in FREEMAIL_PROVIDERS
    if is_freemail and display_name:
        vip_keywords = ["ceo", "cfo", "director", "president", "executive", "admin", "it support", "security team", "helpdesk", "billing"]
        if any(kw in display_name.lower() for kw in vip_keywords):
            is_freemail_abuse = True
            is_display_spoofed = True
            anomalies.append(f"Executive / Corporate display name '{display_name}' sending from public freemail provider '{sender_domain}'")

    # Brand similarity and typosquatting inspection
    domain_base = sender_domain.split(".")[0] if sender_domain else ""
    domain_tokens = re.split(r'[-._]', sender_domain.split(".")[0]) if sender_domain else []
    
    # Common brand lookalike substitution patterns
    homoglyph_brand_regexes = [
        (r'paypa[l1i0]', 'paypal'),
        (r'micr[o0]s[o0]ft', 'microsoft'),
        (r'g[o0][o0]g[l1]e', 'google'),
        (r'app[l1]e', 'apple'),
        (r'amaz[o0]n', 'amazon'),
        (r'chase[-_]?(?:verify|security|bank)', 'chase')
    ]
    for pattern, matched_brand in homoglyph_brand_regexes:
        if re.search(pattern, sender_domain, re.IGNORECASE) and not sender_domain.endswith(f"{matched_brand}.com") and sender_domain != f"{matched_brand}.com":
            brand_matches.append({
                "brand": matched_brand,
                "similarity_type": f"Homoglyph/Lookalike Pattern ('{pattern}')",
                "similarity_score": 0.98
            })
            anomalies.append(f"Sender domain '{sender_domain}' matches known phishing homoglyph for brand '{matched_brand}'")

    for brand in KNOWN_TARGET_BRANDS:
        # Check exact brand name embedded in non-official domain (e.g. paypal-security-update.com)
        if brand in sender_domain and not sender_domain.endswith(f"{brand}.com") and not sender_domain == f"{brand}.com":
            if not any(b["brand"] == brand for b in brand_matches):
                brand_matches.append({
                    "brand": brand,
                    "similarity_type": "Keyword Inclusion",
                    "similarity_score": 0.95
                })
                anomalies.append(f"Sender domain incorporates brand '{brand}' outside authorized apex domain")
        else:
            # Check string similarity metrics against base and sub-tokens
            candidates = [domain_base] + domain_tokens
            for cand in set(candidates):
                if not cand:
                    continue
                jw_score = jaro_winkler_similarity(cand, brand)
                lev_dist = levenshtein_distance(cand, brand)
                if jw_score > 0.85 and lev_dist <= 2 and cand != brand:
                    if not any(b["brand"] == brand for b in brand_matches):
                        brand_matches.append({
                            "brand": brand,
                            "similarity_type": f"Typosquatting Token '{cand}' (Distance: {lev_dist}, Jaro-Winkler: {jw_score:.2f})",
                            "similarity_score": round(jw_score, 3)
                        })
                        anomalies.append(f"Domain token '{cand}' in '{sender_domain}' is a suspected lookalike of '{brand}' (Distance: {lev_dist})")

    # Display name mismatch vs address
    if display_name and "@" in display_name:
        anomalies.append("Display name deceptively formatted as an email address (Header Address Masking)")
        is_display_spoofed = True

    # Calculate domain risk score (0 to 15)
    domain_risk = 0.0
    if brand_matches:
        domain_risk += 8.0
    if is_freemail_abuse:
        domain_risk += 6.0
    if is_display_spoofed:
        domain_risk += 4.0
    if has_homoglyph:
        domain_risk += 5.0
    if is_suspicious_tld:
        domain_risk += 3.0
    if subdomain_depth > 3:
        domain_risk += 2.0
    domain_risk = min(15.0, domain_risk)

    return {
        "display_name": display_name,
        "from_email": from_email,
        "sender_domain": sender_domain,
        "reply_domain": reply_domain,
        "is_freemail": is_freemail,
        "is_freemail_abuse": is_freemail_abuse,
        "is_display_spoofed": is_display_spoofed,
        "has_homoglyph": has_homoglyph,
        "is_suspicious_tld": is_suspicious_tld,
        "subdomain_depth": subdomain_depth,
        "brand_matches": brand_matches,
        "anomalies": anomalies,
        "domain_risk_score": domain_risk
    }
