import os
import re
import hashlib
from typing import List, Dict, Any, Tuple

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".wsf", ".cpl", ".jar", ".com", ".pif", ".msi", ".iso", ".img"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".ppsm"
}

MAGIC_SIGNATURES = [
    (b"MZ", "Windows Executable/PE (MZ)"),
    (b"\x7fELF", "Linux Executable (ELF)"),
    (b"PK\x03\x04", "ZIP Archive / OpenXML Document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 Compound File (MS Office Legacy)"),
    (b"%PDF-", "PDF Document"),
    (b"\x1f\x8b", "GZIP Compressed File"),
    (b"Rar!\x1a\x07", "RAR Archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive")
]


def detect_magic_file_type(payload: bytes) -> str:
    """Detects file type using magic byte signatures."""
    if not payload:
        return "Empty"
    for magic, name in MAGIC_SIGNATURES:
        if payload.startswith(magic):
            return name
    return "Unknown Binary / Text"


def analyze_static_attachment(filename: str, payload: bytes, declared_mime: str = "") -> Dict[str, Any]:
    """
    Performs safe static inspection of email attachments without executing code.
    Detects double extensions, magic byte anomalies, macro signatures, and script content.
    """
    file_size = len(payload)
    sha256_hash = hashlib.sha256(payload).hexdigest()
    md5_hash = hashlib.md5(payload).hexdigest()
    
    # Extract file extension
    base, ext = os.path.splitext(filename)
    ext_lower = ext.lower()
    
    # Detect Double Extension e.g. "invoice.pdf.exe" or "doc.xlsx.vbs"
    has_double_ext = False
    inner_base, inner_ext = os.path.splitext(base)
    if inner_ext and ext_lower in EXECUTABLE_EXTENSIONS:
        has_double_ext = True

    # Magic byte inspection
    magic_type = detect_magic_file_type(payload)
    
    # Executable inspection
    is_script_or_executable = False
    if ext_lower in EXECUTABLE_EXTENSIONS or payload.startswith(b"MZ") or payload.startswith(b"\x7fELF"):
        is_script_or_executable = True

    # Macro & Script inspection within document/archive payload
    has_macros = False
    if ext_lower in MACRO_EXTENSIONS:
        has_macros = True
    elif b"vbaProject.bin" in payload or b"Attribut" in payload and b"VB_Name" in payload:
        has_macros = True
    elif b"AutoOpen" in payload or b"Workbook_Open" in payload or b"Document_Open" in payload:
        has_macros = True

    # Password protection check for Zip archives
    is_password_protected = False
    if payload.startswith(b"PK\x03\x04") and len(payload) > 8:
        # General purpose bit flag 0 indicates encryption
        flags = int.from_bytes(payload[6:8], byteorder="little")
        if flags & 0x1:
            is_password_protected = True

    # HTML / SVG with embedded scripts
    has_embedded_html_script = False
    if ext_lower in [".html", ".htm", ".svg"]:
        if b"<script" in payload.lower() or b"onload=" in payload.lower() or b"javascript:" in payload.lower():
            has_embedded_html_script = True

    # Risk scoring (0 to 10)
    reasons = []
    risk_score = 0.0

    if has_double_ext:
        risk_score += 10.0
        reasons.append(f"Double extension attack detected: '{filename}'")
    if is_script_or_executable:
        risk_score += 8.0
        reasons.append(f"Direct script or executable payload format: '{ext_lower}'")
    if has_macros:
        risk_score += 7.0
        reasons.append("Embedded VBA Macros / AutoOpen execution routines detected in document")
    if has_embedded_html_script:
        risk_score += 6.0
        reasons.append("HTML attachment contains embedded JavaScript execution triggers")
    if is_password_protected:
        risk_score += 4.0
        reasons.append("Password-protected archive (used to evade automated scanner inspection)")

    # Extension vs Magic byte mismatch
    if ext_lower in [".pdf"] and not payload.startswith(b"%PDF-"):
        risk_score += 5.0
        reasons.append("File extension declared as PDF but file header is not valid PDF magic bytes")

    risk_score = min(10.0, risk_score)

    return {
        "filename": filename,
        "file_extension": ext_lower,
        "declared_mime_type": declared_mime,
        "magic_file_type": magic_type,
        "file_size": file_size,
        "sha256_hash": sha256_hash,
        "md5_hash": md5_hash,
        "has_double_extension": has_double_ext,
        "has_macros": has_macros,
        "is_script_or_executable": is_script_or_executable,
        "is_password_protected": is_password_protected,
        "risk_score": round(risk_score, 1),
        "risk_reasons": reasons
    }


def analyze_attachments_list(attachments_raw: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], float]:
    """Analyzes all extracted attachments and returns the maximum attachment risk score."""
    analyzed = []
    max_risk = 0.0
    for att in attachments_raw:
        res = analyze_static_attachment(
            filename=att.get("filename", "unnamed"),
            payload=att.get("payload", b""),
            declared_mime=att.get("content_type", "")
        )
        analyzed.append(res)
        max_risk = max(max_risk, res["risk_score"])
    return analyzed, max_risk
