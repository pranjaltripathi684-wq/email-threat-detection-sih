import re
from typing import Dict, Any, List, Optional
from email.utils import parseaddr


def parse_authentication_headers(
    headers_list: List[Dict[str, str]],
    from_email: str,
    reply_to_email: str,
    sender_domain: Optional[str]
) -> Dict[str, Any]:
    """
    Parses and evaluates SPF, DKIM, DMARC, ARC headers and checks alignment
    against visible From and Reply-To domains.
    """
    spf_result = "none"
    spf_domain = None
    spf_scope = "mfrom"
    
    dkim_present = False
    dkim_result = "none"
    dkim_domain = None
    dkim_selector = None
    dkim_body_hash_valid = None
    
    dmarc_result = "none"
    dmarc_policy = "none"
    dmarc_alignment = "unaligned"
    
    arc_present = False
    arc_result = "none"
    
    auth_results_raw = []
    received_spf_raw = []
    dkim_sigs_raw = []
    
    for h in headers_list:
        h_name = h["name"].lower()
        h_val = h["value"]
        
        if h_name == "authentication-results":
            auth_results_raw.append(h_val)
        elif h_name == "received-spf":
            received_spf_raw.append(h_val)
        elif h_name == "dkim-signature":
            dkim_sigs_raw.append(h_val)
            dkim_present = True
        elif h_name.startswith("arc-"):
            arc_present = True

    # Parse Received-SPF
    if received_spf_raw:
        for r_spf in received_spf_raw:
            match_res = re.match(r'^([a-zA-Z]+)', r_spf.strip())
            if match_res:
                spf_result = match_res.group(1).lower()
            # Extract domain from received-spf if present
            dom_match = re.search(r'(?:domain of|designates\s+([^\s]+)\s+as|identity=mfrom;\s*envelope-from="?([^"\s]+)"?)', r_spf, re.IGNORECASE)
            if dom_match:
                dom = dom_match.group(1) or dom_match.group(2)
                if dom and "@" in dom:
                    spf_domain = dom.split("@")[-1].strip("<>")
                elif dom:
                    spf_domain = dom.strip("<>;")

    # Parse Authentication-Results
    if auth_results_raw:
        combined_auth = " ".join(auth_results_raw)
        
        # SPF in Auth-Results
        spf_auth_match = re.search(r'\bspf=([a-zA-Z]+)(?:\s+\((?:[^)]+)\))?(?:\s+smtp\.(?:mailfrom|mfrom)=([^\s;]+))?', combined_auth, re.IGNORECASE)
        if spf_auth_match:
            spf_result = spf_auth_match.group(1).lower()
            if spf_auth_match.group(2):
                spf_domain = spf_auth_match.group(2).split("@")[-1].strip("<>;\"")

        # DKIM in Auth-Results
        dkim_auth_match = re.search(r'\bdkim=([a-zA-Z]+)(?:\s+\((?:[^)]+)\))?(?:\s+header\.(?:i|d)=([^\s;]+))?', combined_auth, re.IGNORECASE)
        if dkim_auth_match:
            dkim_result = dkim_auth_match.group(1).lower()
            if dkim_auth_match.group(2):
                dkim_domain = dkim_auth_match.group(2).split("@")[-1].strip("<>;\"")

        # DMARC in Auth-Results
        dmarc_auth_match = re.search(r'\bdmarc=([a-zA-Z]+)(?:\s+\((?:[^)]+)\))?(?:\s+action=([^\s;]+))?(?:\s+header\.from=([^\s;]+))?', combined_auth, re.IGNORECASE)
        if dmarc_auth_match:
            dmarc_result = dmarc_auth_match.group(1).lower()
            if dmarc_auth_match.group(2):
                dmarc_policy = dmarc_auth_match.group(2).lower()

        # ARC in Auth-Results
        arc_auth_match = re.search(r'\barc=([a-zA-Z]+)', combined_auth, re.IGNORECASE)
        if arc_auth_match:
            arc_result = arc_auth_match.group(1).lower()

    # Parse DKIM-Signature header if details not extracted
    if dkim_sigs_raw and not dkim_domain:
        first_sig = dkim_sigs_raw[0]
        d_match = re.search(r'\bd=([a-zA-Z0-9.\-_]+)', first_sig)
        if d_match:
            dkim_domain = d_match.group(1).lower()
        s_match = re.search(r'\bs=([a-zA-Z0-9.\-_]+)', first_sig)
        if s_match:
            dkim_selector = s_match.group(1)
            
        if "bh=" in first_sig:
            dkim_body_hash_valid = True

    # Alignment calculations
    from_dom = sender_domain.lower() if sender_domain else ""
    spf_aligned = bool(from_dom and spf_domain and (from_dom == spf_domain.lower() or from_dom.endswith("." + spf_domain.lower())))
    dkim_aligned = bool(from_dom and dkim_domain and (from_dom == dkim_domain.lower() or from_dom.endswith("." + dkim_domain.lower())))

    if dmarc_result == "pass":
        dmarc_alignment = "strict" if (spf_aligned and dkim_aligned) else "relaxed"
    elif dmarc_result == "fail":
        dmarc_alignment = "unaligned"
    else:
        # Infer alignment if no explicit DMARC header
        if (spf_result == "pass" and spf_aligned) or (dkim_result == "pass" and dkim_aligned):
            dmarc_alignment = "relaxed"
            if dmarc_result == "none":
                dmarc_result = "pass"
        else:
            dmarc_alignment = "unaligned"

    # From vs Reply-To alignment
    from_reply_aligned = True
    if reply_to_email and from_email:
        _, f_addr = parseaddr(from_email)
        _, r_addr = parseaddr(reply_to_email)
        if f_addr and r_addr and f_addr.lower() != r_addr.lower():
            # Check domain level
            f_d = f_addr.split("@")[-1].lower() if "@" in f_addr else ""
            r_d = r_addr.split("@")[-1].lower() if "@" in r_addr else ""
            if f_d != r_d:
                from_reply_aligned = False

    # Check for Lookalike domain authentication trap
    # (i.e. SPF and DKIM pass for a domain, but the domain itself is deceptive / lookalike)
    is_lookalike_auth = False
    lookalike_patterns = [
        r'paypa[l1i]', r'micr[o0]s[o0]ft', r'goog[l1]e', r'app[l1]e', r'amaz[o0]n',
        r'chase-verify', r'secure-banking', r'update-account'
    ]
    if from_dom:
        for pat in lookalike_patterns:
            if re.search(pat, from_dom) and not any(legit in from_dom for legit in ["paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com", "chase.com"]):
                if spf_result == "pass" or dkim_result == "pass":
                    is_lookalike_auth = True
                    break

    # Natural language explanation
    explanation_parts = []
    explanation_parts.append(f"SPF evaluated as '{spf_result}' (Domain: {spf_domain or 'None'}).")
    explanation_parts.append(f"DKIM evaluated as '{dkim_result}' (Signing Domain: {dkim_domain or 'None'}).")
    explanation_parts.append(f"DMARC status: '{dmarc_result}' with policy '{dmarc_policy}'. Alignment mode: '{dmarc_alignment}'.")

    if not from_reply_aligned:
        explanation_parts.append("WARNING: Reply-To domain differs from visible From sender domain (potential redirect/fraud vector).")
    if is_lookalike_auth:
        explanation_parts.append("CAUTION: Email passed sender authentication, but the signing domain matches a suspected lookalike domain pattern (Authentic Phishing Trap).")
    if dmarc_result == "fail":
        explanation_parts.append("DMARC alignment failed: Neither SPF nor DKIM could be aligned with the visible From address.")

    return {
        "spf_result": spf_result,
        "spf_domain": spf_domain,
        "spf_scope": spf_scope,
        "dkim_present": dkim_present,
        "dkim_result": dkim_result,
        "dkim_domain": dkim_domain,
        "dkim_selector": dkim_selector,
        "dkim_body_hash_valid": dkim_body_hash_valid,
        "dmarc_result": dmarc_result,
        "dmarc_policy": dmarc_policy,
        "dmarc_alignment": dmarc_alignment,
        "dmarc_from_domain": from_dom,
        "arc_present": arc_present,
        "arc_result": arc_result,
        "from_reply_to_aligned": from_reply_aligned,
        "is_lookalike_domain_auth": is_lookalike_auth,
        "natural_language_explanation": " ".join(explanation_parts)
    }
