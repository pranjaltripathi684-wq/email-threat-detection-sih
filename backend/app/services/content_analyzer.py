import re
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Tuple

URGENCY_KEYWORDS = [
    r'\bimmediate(?:ly)?\b', r'\bwithin\s+(?:24|12|48)\s+hours\b',
    r'\baccount\s+(?:suspended|restricted|disabled|locked)\b', r'\bfinal\s+notice\b',
    r'\burgent(?:ly)?\b', r'\baction\s+required\b',
    r'\btime\s+sensitive\b', r'\basap\b', r'\bexpire(?:s)?\s+today\b'
]

AUTHORITY_FEAR_KEYWORDS = [
    r'\blegal\b', r'\blaw\s+enforcement\b', r'\bsubpoena\b', r'\bdisciplinary\b',
    r'\btermination\b', r'\bcompliance\s+penalty\b', r'\bcourt\b',
    r'\bsecurity\s+breach\b', r'\bunauthorized\s+access\b'
]

FINANCIAL_WIRE_KEYWORDS = [
    r'\bwire\s+transfer\b', r'\bupdated?\s+bank(?:ing)?\s+details\b', r'\brouting\s+number\b',
    r'\bdirect\s+deposit\b', r'\bgift\s+cards?\b', r'\bapple\s+gift\s+cards?\b',
    r'\bsteam\s+cards?\b', r'\bbitcoin\b', r'\bcrypto(?:currency)?\b', r'\bnew\s+invoice\b',
    r'\bremittance\b', r'\bpayment\s+instructions?\b', r'\bchange\s+of\s+account\b', r'\binvoice\b'
]

CREDENTIAL_HARVEST_KEYWORDS = [
    r'\bconfirm\s+(?:your\s+)?password\b', r'\bverify\s+(?:your\s+)?(?:account|credentials|identity)\b',
    r'\blogin\s+immediately\b', r'\bupdate\s+credentials?\b', r'\bsession\s+expired\b',
    r'\bsecurity\s+check\b', r'\bre-authenticate\b', r'\bclick\s+here\b'
]

CONFIDENTIALITY_BYPASS_KEYWORDS = [
    r'\bconfidential(?:ity)?\b', r'\bdo\s+not\s+(?:call|contact)\b', r'\bkeep\s+this\s+private\b',
    r'\bbypass\s+standard\s+procedure\b', r'\brush\s+request\b', r'\bexecutive\b', r'\bdiscrete\b'
]


def extract_cues(text: str, regex_list: List[str]) -> List[str]:
    """Finds all matching regex patterns in text."""
    matches = []
    for pattern in regex_list:
        found = re.findall(pattern, text, re.IGNORECASE)
        if found:
            for f in set(found):
                matches.append(f)
    return matches


def analyze_email_content(body_text: str, body_html: str, subject: str = "") -> Dict[str, Any]:
    """
    Analyzes subject and body text/HTML for social engineering patterns,
    urgency, credential harvesting, financial fraud, and embedded HTML threats.
    """
    full_text = f"{subject}\n{body_text}".strip()
    
    # Parse HTML for hidden inputs, forms, scripts, iframes
    has_forms = False
    has_scripts = False
    has_iframes = False
    has_hidden_inputs = False
    
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "html.parser")
            if soup.find("form"):
                has_forms = True
            if soup.find("script"):
                has_scripts = True
            if soup.find("iframe"):
                has_iframes = True
            if soup.find("input", {"type": "hidden"}):
                has_hidden_inputs = True
                
            # If no plain text was provided, extract text from HTML
            if not full_text:
                full_text = soup.get_text(separator=" ", strip=True)
        except Exception:
            pass

    urgency_cues = extract_cues(full_text, URGENCY_KEYWORDS)
    fear_cues = extract_cues(full_text, AUTHORITY_FEAR_KEYWORDS)
    financial_cues = extract_cues(full_text, FINANCIAL_WIRE_KEYWORDS)
    credential_cues = extract_cues(full_text, CREDENTIAL_HARVEST_KEYWORDS)
    confidentiality_cues = extract_cues(full_text, CONFIDENTIALITY_BYPASS_KEYWORDS)

    # Heuristic category determination
    detected_categories = []
    if credential_cues:
        detected_categories.append("Credential Theft")
    if financial_cues:
        detected_categories.append("Financial Fraud / BEC")
    if urgency_cues and (credential_cues or financial_cues):
        detected_categories.append("Phishing Campaign")
    if confidentiality_cues:
        detected_categories.append("Social Engineering")

    # Content Risk Score Calculation (0 to 15)
    content_risk = 0.0
    if credential_cues:
        content_risk += 5.0
    if financial_cues:
        content_risk += 5.0
    if urgency_cues:
        content_risk += 3.0
    if fear_cues:
        content_risk += 3.0
    if confidentiality_cues:
        content_risk += 3.0
    if has_forms:
        content_risk += 4.0
    if has_scripts or has_iframes:
        content_risk += 4.0

    content_risk = min(15.0, content_risk)

    return {
        "text_length": len(full_text),
        "urgency_cues": urgency_cues,
        "fear_authority_cues": fear_cues,
        "financial_cues": financial_cues,
        "credential_cues": credential_cues,
        "confidentiality_cues": confidentiality_cues,
        "has_forms": has_forms,
        "has_scripts": has_scripts,
        "has_iframes": has_iframes,
        "has_hidden_inputs": has_hidden_inputs,
        "detected_categories": detected_categories,
        "content_risk_score": content_risk
    }
