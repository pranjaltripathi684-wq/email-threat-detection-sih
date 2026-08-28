import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from jinja2 import Template
from sqlalchemy.orm import Session
from app.db.models import Email, EvidenceItem, CustodyEvent, ReceivedHop, AuthenticationResult, EmailUrl, EmailAttachment, ThreatIntelligenceMatch, ModelPrediction
from app.core.config import settings

REPORT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forensic Intelligence Report - {{ email.sha256_hash[:12] }}</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #1e293b; margin: 0; padding: 40px; background: #f8fafc; }
        .container { max-width: 1000px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #0f172a; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-start; }
        .header h1 { margin: 0; font-size: 22px; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px; }
        .header .meta { font-size: 12px; color: #64748b; text-align: right; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; text-transform: uppercase; }
        .badge-critical { background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
        .badge-high { background: #ffedd5; color: #9a3412; border: 1px solid #fb923c; }
        .badge-suspicious { background: #fef9c3; color: #854d0e; border: 1px solid #facc15; }
        .badge-low { background: #dcfce7; color: #166534; border: 1px solid #4ade80; }
        
        .section { margin-bottom: 30px; page-break-inside: avoid; }
        .section h2 { font-size: 15px; text-transform: uppercase; color: #334155; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 14px; letter-spacing: 0.5px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 15px; font-size: 13px; }
        th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }
        th { background: #f1f5f9; color: #475569; font-weight: 600; }
        .disclaimer-box { background: #fffbeb; border: 1px solid #fde68a; border-left: 4px solid #d97706; padding: 14px; border-radius: 4px; font-size: 12px; color: #92400e; margin-bottom: 25px; }
        .highlight-box { background: #f8fafc; border: 1px solid #e2e8f0; padding: 14px; border-radius: 4px; font-size: 13px; }
        .score-display { font-size: 28px; font-weight: bold; }
        .evidence-list { margin: 0; padding-left: 20px; font-size: 13px; }
        .evidence-list li { margin-bottom: 4px; }
        .mono { font-family: 'Courier New', Courier, monospace; font-size: 12px; word-break: break-all; }
        @media print {
            body { background: #fff; padding: 0; }
            .container { box-shadow: none; padding: 0; width: 100%; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>Forensic Threat Intelligence Report</h1>
            <div style="font-size: 13px; color: #475569; margin-top: 4px;">AI-Powered Email Forensics & Geolocation Analysis Platform</div>
        </div>
        <div class="meta">
            <div><strong>Report ID:</strong> RPT-{{ email.id }}-{{ email.sha256_hash[:8] }}</div>
            <div><strong>Generated:</strong> {{ generated_at }} UTC</div>
            <div><strong>Classification:</strong> RESTRICTED / FORENSIC EVIDENCE</div>
        </div>
    </div>

    <!-- 1. Executive Summary -->
    <div class="section">
        <h2>1. Executive Summary</h2>
        <div class="highlight-box" style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <div><strong>Threat Assessment:</strong> <span class="badge badge-{{ email.risk_classification.lower().replace(' ', '-') }}">{{ email.risk_classification }}</span></div>
                <div style="margin-top: 6px;"><strong>Predicted Category (ML):</strong> {{ prediction.predicted_class if prediction else 'N/A' }} (Confidence: {{ (prediction.probability_score * 100)|round(1) if prediction else 0 }}%)</div>
                <div style="margin-top: 6px;"><strong>Earliest Reliable Public IP:</strong> <span class="mono">{{ email.earliest_public_ip or 'None identified' }}</span> ({{ email.earliest_public_ip_country or 'Unknown' }})</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 12px; color: #64748b; text-transform: uppercase;">Total Risk Score</div>
                <div class="score-display">{{ email.total_risk_score }} / 100</div>
            </div>
        </div>
    </div>

    <!-- Attribution Disclaimer -->
    <div class="disclaimer-box">
        <strong>LEGAL & ATTRIBUTION DISCLAIMER:</strong> {{ disclaimer }}
    </div>

    <!-- 2. Case & Evidence Information -->
    <div class="section">
        <h2>2. Case & Evidence Integrity</h2>
        <table>
            <tr><th width="30%">Evidence ID (UUID)</th><td class="mono">{{ evidence.evidence_uuid if evidence else 'N/A' }}</td></tr>
            <tr><th>Cryptographic Hash (SHA-256)</th><td class="mono">{{ email.sha256_hash }}</td></tr>
            <tr><th>Original File Name</th><td>{{ email.original_filename }}</td></tr>
            <tr><th>File Size / MIME</th><td>{{ email.file_size }} bytes ({{ email.mime_type }})</td></tr>
            <tr><th>Acquisition Timestamp</th><td>{{ email.upload_time }} UTC</td></tr>
            <tr><th>Associated Case</th><td>{{ case.case_number ~ ' - ' ~ case.title if case else 'Unassigned' }}</td></tr>
        </table>
    </div>

    <!-- 3. Email Metadata -->
    <div class="section">
        <h2>3. Email Metadata & Header Attributes</h2>
        <table>
            <tr><th width="30%">Subject</th><td><strong>{{ email.raw_subject or '(No Subject)' }}</strong></td></tr>
            <tr><th>From (Declared)</th><td>{{ email.raw_from }}</td></tr>
            <tr><th>Reply-To</th><td>{{ email.raw_reply_to or 'Same as From' }}</td></tr>
            <tr><th>To / Recipient</th><td>{{ email.raw_to }}</td></tr>
            <tr><th>Message-ID</th><td class="mono">{{ email.message_id or 'Missing' }}</td></tr>
            <tr><th>Date Header</th><td>{{ email.raw_date }}</td></tr>
        </table>
    </div>

    <!-- 4. Authentication Matrix -->
    <div class="section">
        <h2>4. Authentication & Alignment Analysis (SPF, DKIM, DMARC, ARC)</h2>
        <table>
            <tr>
                <th>Protocol</th>
                <th>Result</th>
                <th>Domain / Selector</th>
                <th>Alignment Status</th>
            </tr>
            <tr>
                <td><strong>SPF</strong></td>
                <td><span class="badge">{{ auth.spf_result if auth else 'none' }}</span></td>
                <td>{{ auth.spf_domain if auth else '-' }}</td>
                <td>{{ 'Aligned' if auth and auth.spf_result == 'pass' else 'Unaligned / Missing' }}</td>
            </tr>
            <tr>
                <td><strong>DKIM</strong></td>
                <td><span class="badge">{{ auth.dkim_result if auth else 'none' }}</span></td>
                <td>{{ (auth.dkim_domain ~ ' (s=' ~ auth.dkim_selector ~ ')') if auth and auth.dkim_domain else '-' }}</td>
                <td>{{ 'Cryptographically Valid' if auth and auth.dkim_result == 'pass' else 'No Valid Sig' }}</td>
            </tr>
            <tr>
                <td><strong>DMARC</strong></td>
                <td><span class="badge">{{ auth.dmarc_result if auth else 'none' }}</span></td>
                <td>Policy: {{ auth.dmarc_policy if auth else 'none' }}</td>
                <td>{{ auth.dmarc_alignment if auth else 'unaligned' }}</td>
            </tr>
            <tr>
                <td><strong>ARC</strong></td>
                <td><span class="badge">{{ auth.arc_result if auth else 'none' }}</span></td>
                <td>Chain Present: {{ 'Yes' if auth and auth.arc_present else 'No' }}</td>
                <td>-</td>
            </tr>
        </table>
        <div class="highlight-box">
            <strong>Authentication Assessment:</strong> {{ auth.natural_language_explanation if auth else 'No authentication headers processed.' }}
        </div>
    </div>

    <!-- 5. Relay Path & Hop Reconstruction -->
    <div class="section">
        <h2>5. Received Relay Path & Earliest Public IP Reconstruction</h2>
        <table>
            <thead>
                <tr>
                    <th>Hop</th>
                    <th>From (Sending)</th>
                    <th>By (Receiving)</th>
                    <th>IP Address</th>
                    <th>Class</th>
                    <th>TLS</th>
                    <th>Time Delta</th>
                </tr>
            </thead>
            <tbody>
                {% for hop in hops %}
                <tr style="{{ 'background: #eff6ff; font-weight: bold;' if hop.is_earliest_reliable_public_ip else '' }}">
                    <td>{{ hop.hop_order }}</td>
                    <td class="mono">{{ hop.sending_server or 'N/A' }}</td>
                    <td class="mono">{{ hop.receiving_server or 'N/A' }}</td>
                    <td class="mono">{{ hop.extracted_ip or 'None' }}</td>
                    <td>{{ hop.ip_classification }}</td>
                    <td>{{ 'Yes' if hop.tls_status else 'No' }}</td>
                    <td>{{ hop.time_delta_seconds|round(1) }}s</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- 6. URL & Attachment Indicators -->
    <div class="section">
        <h2>6. Indicators of Compromise (URLs & Attachments)</h2>
        {% if urls %}
        <h3 style="font-size: 13px; color: #475569;">Extracted URLs ({{ urls|length }})</h3>
        <table>
            <thead>
                <tr><th>Destination URL</th><th>Display Text</th><th>Domain</th><th>Flags</th><th>Risk</th></tr>
            </thead>
            <tbody>
                {% for u in urls %}
                <tr>
                    <td class="mono">{{ u.raw_url }}</td>
                    <td>{{ u.display_text }}</td>
                    <td>{{ u.domain }}</td>
                    <td>{{ 'DECEPTIVE LINK' if u.is_deceptive else '-' }}</td>
                    <td>{{ u.risk_score }} / 15</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        {% if attachments %}
        <h3 style="font-size: 13px; color: #475569;">Static Attachment Forensics ({{ attachments|length }})</h3>
        <table>
            <thead>
                <tr><th>Filename</th><th>Size</th><th>Magic Bytes</th><th>SHA-256 Hash</th><th>Risk</th></tr>
            </thead>
            <tbody>
                {% for att in attachments %}
                <tr>
                    <td><strong>{{ att.filename }}</strong></td>
                    <td>{{ att.file_size }} bytes</td>
                    <td>{{ att.magic_file_type }}</td>
                    <td class="mono">{{ att.sha256_hash }}</td>
                    <td>{{ att.risk_score }} / 10</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>

    <!-- 7. Explainable Evidence & Actionable Recommendations -->
    <div class="section">
        <h2>7. Explainable Risk Signals & Recommended Response</h2>
        <div style="margin-bottom: 12px;">
            <strong>Positive Threat Indicators:</strong>
            <ul class="evidence-list" style="color: #b91c1c;">
                {% for ev in positive_evidence %}
                <li>{{ ev }}</li>
                {% endfor %}
            </ul>
        </div>

        {% if negative_evidence %}
        <div style="margin-bottom: 12px;">
            <strong>Mitigating Factors:</strong>
            <ul class="evidence-list" style="color: #15803d;">
                {% for ev in negative_evidence %}
                <li>{{ ev }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <div class="highlight-box" style="border-left: 4px solid #0284c7; background: #f0f9ff;">
            <strong>Recommended Operational Action:</strong><br>
            {{ email.recommended_action }}
        </div>
    </div>

    <!-- 8. Chain of Custody -->
    <div class="section">
        <h2>8. Chain of Custody Audit Log</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Action</th>
                    <th>Actor / Role</th>
                    <th>Reason / Verification</th>
                    <th>Hash Status</th>
                </tr>
            </thead>
            <tbody>
                {% for c in custody_events %}
                <tr>
                    <td>{{ c.timestamp_utc }}</td>
                    <td><strong>{{ c.action }}</strong></td>
                    <td>{{ c.performed_by_username }} ({{ c.performed_by_role }})</td>
                    <td>{{ c.reason }}</td>
                    <td><span class="badge badge-low">{{ c.verification_status }}</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

</div>
</body>
</html>
"""


def generate_forensic_report(db: Session, email_id: int) -> Dict[str, Any]:
    """Generates structured HTML and JSON forensic reports for an email."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise ValueError("Email not found")

    evidence = db.query(EvidenceItem).filter(EvidenceItem.email_id == email.id).first()
    custody_events = db.query(CustodyEvent).filter(CustodyEvent.evidence_id == evidence.id).all() if evidence else []
    hops = db.query(ReceivedHop).filter(ReceivedHop.email_id == email.id).order_by(ReceivedHop.hop_order).all()
    auth = db.query(AuthenticationResult).filter(AuthenticationResult.email_id == email.id).first()
    urls = db.query(EmailUrl).filter(EmailUrl.email_id == email.id).all()
    attachments = db.query(EmailAttachment).filter(EmailAttachment.email_id == email.id).all()
    prediction = db.query(ModelPrediction).filter(ModelPrediction.email_id == email.id).first()
    case = email.case

    positive_evidence = json.loads(email.positive_evidence_json or "[]")
    negative_evidence = json.loads(email.negative_evidence_json or "[]")

    template = Template(REPORT_HTML_TEMPLATE)
    html_content = template.render(
        email=email,
        evidence=evidence,
        custody_events=custody_events,
        hops=hops,
        auth=auth,
        urls=urls,
        attachments=attachments,
        prediction=prediction,
        case=case,
        positive_evidence=positive_evidence,
        negative_evidence=negative_evidence,
        disclaimer=settings.ATTRIBUTION_DISCLAIMER,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    )

    return {
        "email_id": email.id,
        "sha256_hash": email.sha256_hash,
        "risk_score": email.total_risk_score,
        "risk_classification": email.risk_classification,
        "html_report": html_content
    }
