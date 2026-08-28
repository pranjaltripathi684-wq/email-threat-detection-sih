import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform"
    PROJECT_VERSION: str = "1.0.0-academic-prototype"
    API_V1_STR: str = "/api/v1"
    
    # Security & Tokens
    SECRET_KEY: str = os.getenv("SECRET_KEY", "academic_super_secret_email_forensics_jwt_key_2026_change_in_prod")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Database (Defaults to SQLite for instant local prototype, easily switched to Postgres)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./email_forensics.db")
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "*"
    ]
    
    # Upload limits
    MAX_EMAIL_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB
    ALLOWED_EXTENSIONS: List[str] = [".eml", ".txt", ".msg"]
    
    # Privacy Defaults
    DEFAULT_PII_MASKING: bool = True
    ALLOW_EXTERNAL_ENRICHMENT_BY_DEFAULT: bool = False
    
    # Attribution Disclaimer text
    ATTRIBUTION_DISCLAIMER: str = (
        "DEFENSIVE FORENSIC DISCLAIMER: This platform provides technical attribution support and "
        "confidence-based indicator correlation. It does not definitively identify an individual attacker "
        "or assert verified physical location. Relay servers, VPNs, Tor nodes, cloud proxies, and compromised "
        "infrastructure can obscure the true source. Geolocation represents the estimated physical location "
        "of the earliest reliable public relay infrastructure only."
    )
    
    # Scoring weights (Total 100)
    WEIGHT_HEADERS: float = 20.0
    WEIGHT_AUTH: float = 20.0
    WEIGHT_SENDER_DOMAIN: float = 15.0
    WEIGHT_CONTENT_NLP: float = 15.0
    WEIGHT_URLS: float = 15.0
    WEIGHT_ATTACHMENTS: float = 10.0
    WEIGHT_THREAT_INTEL: float = 5.0
    
    # Thresholds
    RISK_THRESHOLD_LOW: float = 25.0
    RISK_THRESHOLD_SUSPICIOUS: float = 50.0
    RISK_THRESHOLD_HIGH: float = 75.0

    model_config = SettingsConfigDict(case_sensitive=True, extra="allow")


settings = Settings()
