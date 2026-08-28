from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Indicator, Campaign, IPEnrichment, DomainEnrichment, ThreatIntelligenceMatch
from app.services.enrichment import enrich_ip_address, enrich_domain

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])


@router.get("/indicators/{indicator_type}/{value}")
def lookup_indicator(indicator_type: str, value: str, db: Session = Depends(get_db)):
    """Looks up threat intelligence and reputation for an IP, domain, URL, or hash."""
    ind_type = indicator_type.lower()
    
    enrichment_data = {}
    if ind_type in ["ip", "ip_address"]:
        enrichment_data = enrich_ip_address(value)
    elif ind_type in ["domain", "sender_domain"]:
        enrichment_data = enrich_domain(value)

    # Query historical matches in database
    matches = db.query(ThreatIntelligenceMatch).filter(ThreatIntelligenceMatch.indicator_value == value).all()
    match_list = []
    for m in matches:
        match_list.append({
            "provider": m.provider_name,
            "severity": m.severity,
            "confidence": m.confidence,
            "email_id": m.email_id
        })

    return {
        "indicator_type": indicator_type,
        "indicator_value": value,
        "enrichment": enrichment_data,
        "threat_matches": match_list,
        "disclaimer": "Threat intelligence indicators are confidence-based observations and do not assert sole ownership or individual culpability."
    }


@router.get("/campaigns")
def list_campaigns(db: Session = Depends(get_db)):
    """Lists observed phishing and fraud campaigns."""
    campaigns = db.query(Campaign).all()
    return campaigns
