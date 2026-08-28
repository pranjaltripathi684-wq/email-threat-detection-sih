from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.database import engine, Base, SessionLocal
from app.db.models import User, SystemSetting
from app.api.v1.auth import router as auth_router
from app.api.v1.emails import router as emails_router
from app.api.v1.cases import router as cases_router
from app.api.v1.intelligence import router as intel_router
from app.api.v1.graph import router as graph_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.admin import router as admin_router
from app.api.v1.scenarios import router as scenarios_router

# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Academic prototype for deep email header forensics, relay hop geolocation, authentication validation, and explainable threat scoring.",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Initializes database tables and creates default user accounts and seed data."""
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Seed default role-based test users if database is empty
        users_to_seed = [
            ("admin", "admin@forensics.local", "AdminPass123!", "System Administrator", "Administrator"),
            ("analyst", "analyst@forensics.local", "AnalystPass123!", "Senior Threat Analyst", "Analyst"),
            ("investigator", "investigator@forensics.local", "InvestigatorPass123!", "Lead Case Investigator", "Investigator"),
            ("auditor", "auditor@forensics.local", "AuditorPass123!", "Compliance Auditor", "Auditor")
        ]
        for uname, email, pwd, full_name, role in users_to_seed:
            existing = db.query(User).filter(User.username == uname).first()
            if not existing:
                u = User(
                    username=uname,
                    email=email,
                    hashed_password=get_password_hash(pwd),
                    full_name=full_name,
                    role=role,
                    is_active=True
                )
                db.add(u)
        db.commit()
    finally:
        db.close()


# Health check endpoints
@app.get("/api/health", tags=["Health"])
@app.get("/api/v1/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "platform": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "database": "connected",
        "disclaimer": settings.ATTRIBUTION_DISCLAIMER
    }


# Include V1 Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(emails_router, prefix=settings.API_V1_STR)
app.include_router(cases_router, prefix=settings.API_V1_STR)
app.include_router(intel_router, prefix=settings.API_V1_STR)
app.include_router(graph_router, prefix=settings.API_V1_STR)
app.include_router(evidence_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)
app.include_router(scenarios_router, prefix=settings.API_V1_STR)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred.", "error": str(exc)}
    )
