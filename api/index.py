"""Vercel entry point: serves the FastAPI backend as one serverless function.

The frontend is built to static files by Vercel; every /api/* request is
rewritten here (see vercel.json). Only /tmp is writable on Vercel, so the
SQLite database and evidence store live there and are rebuilt on cold start.
The five synthetic demo scenarios are pre-analysed so visitors land on a
populated dashboard.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/email_forensics.db")
os.environ.setdefault("EVIDENCE_STORAGE_DIR", "/tmp/evidence")
os.makedirs(os.environ["EVIDENCE_STORAGE_DIR"], exist_ok=True)

from app.main import app, startup_event  # noqa: E402
from app.db.database import SessionLocal  # noqa: E402
from app.db.models import Email, User  # noqa: E402
from app.services.ingestion import safe_ingest_email  # noqa: E402
from app.services.pipeline import process_and_analyze_email  # noqa: E402
from app.api.v1.scenarios import SAMPLE_DIR, SCENARIO_FILES  # noqa: E402


def _seed_demo_scenarios():
    db = SessionLocal()
    try:
        if db.query(Email).count():
            return
        analyst = db.query(User).filter(User.username == "analyst").first()
        for filename, _desc in SCENARIO_FILES.values():
            with open(os.path.join(SAMPLE_DIR, filename), "rb") as f:
                raw = f.read()
            email, _, _ = safe_ingest_email(
                db=db, raw_bytes=raw, filename=filename,
                uploader_id=analyst.id, uploader_username=analyst.username,
                uploader_role=analyst.role, source_type="synthetic_scenario",
            )
            process_and_analyze_email(db=db, email=email, raw_bytes=raw)
    finally:
        db.close()


# Serverless platforms may not send ASGI lifespan events, so run startup here.
startup_event()
try:
    _seed_demo_scenarios()
except Exception as exc:  # demo seeding must never take the API down
    print(f"[demo] scenario seeding skipped: {exc}")
