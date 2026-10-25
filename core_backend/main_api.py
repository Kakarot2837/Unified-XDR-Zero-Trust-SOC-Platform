# core_backend/main_api.py
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core_backend.database.models import (
    SessionLocal, User, AuthSession, ThreatIndicator, SecurityAlert, IncidentResponseAudit, redis_cache
)
from core_backend.database.seed_db import init_and_seed_db

app = FastAPI(title="Unified XDR & Zero-Trust SOC Backend")

# Auto-initialize DB on startup
@app.on_event("startup")
def startup_event():
    init_and_seed_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Unified Telemetry Payload Schema ---
class TelemetryEvent(BaseModel):
    user_id: Optional[int] = 1
    session_id: Optional[str] = "sess_pune_01"
    source_ip: str
    indicator_value: Optional[str] = None
    module_name: str
    threat_type: str
    severity: str
    base_risk_score: float
    confidence_score: float = 1.0
    raw_payload: str

@app.post("/api/ingest-telemetry")
def ingest_telemetry(event: TelemetryEvent, db: Session = Depends(get_db)):
    # 1. IOC Threat Enrichment Lookup (Module 10b)
    lookup_val = event.indicator_value or event.source_ip
    matched_ioc = db.query(ThreatIndicator).filter(
        ThreatIndicator.indicator_value == lookup_val
    ).first()

    ioc_id = matched_ioc.ioc_id if matched_ioc else None
    ioc_bonus = 25.0 if matched_ioc else 0.0
    ioc_tag = f"Matched IOC: {matched_ioc.threat_actor} (Rep: {matched_ioc.reputation_score}%)" if matched_ioc else "No Known IOC Match"

    # 2. Save Enriched Security Alert to DBMS
    new_alert = SecurityAlert(
        user_id=event.user_id,
        session_id=event.session_id,
        ioc_id=ioc_id,
        source_ip=event.source_ip,
        module_name=event.module_name,
        threat_type=event.threat_type,
        severity=event.severity,
        base_risk_score=event.base_risk_score,
        ioc_bonus_score=ioc_bonus,
        confidence_score=event.confidence_score,
        raw_payload=f"{event.raw_payload} | [{ioc_tag}]",
        status="OPEN"
    )
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)

    # 3. Multi-Signal Risk Correlation Engine (10-Minute Sliding Window)
    window_start = datetime.utcnow() - timedelta(minutes=10)
    recent_alerts = db.query(SecurityAlert).filter(
        SecurityAlert.source_ip == event.source_ip,
        SecurityAlert.timestamp >= window_start
    ).all()

    total_risk = sum(a.base_risk_score * a.confidence_score for a in recent_alerts)
    max_ioc_bonus = max((a.ioc_bonus_score for a in recent_alerts), default=0.0)
    r_total = round(total_risk + max_ioc_bonus, 1)

    # 4. Automated Zero-Trust SOAR Response
    soar_action = "ALLOW_MONITOR"
    if r_total >= 80.0:
        soar_action = "SESSION_LOCKED_AND_IP_BLOCKED"
        redis_cache.block_ip(event.source_ip)
    elif r_total >= 40.0:
        soar_action = "FACE_STEP_UP_FORCED"

    # Update Session State
    session_obj = db.query(AuthSession).filter_by(session_id=event.session_id).first()
    if session_obj:
        session_obj.session_risk_score = r_total
        session_obj.source_ip = event.source_ip
        if r_total >= 80.0:
            session_obj.session_status = "LOCKED"
        elif r_total >= 40.0:
            session_obj.session_status = "STEP_UP_REQUIRED"

    # Log Audit Trail if Action Taken
    if soar_action != "ALLOW_MONITOR":
        db.add(IncidentResponseAudit(
            alert_id=new_alert.alert_id,
            automated_action=soar_action,
            analyst_notes=f"Triggered automatically at Cumulative Session Risk = {r_total}/100"
        ))

    db.commit()

    return {
        "status": "ingested",
        "alert_id": new_alert.alert_id,
        "ioc_enriched": bool(matched_ioc),
        "ioc_details": ioc_tag,
        "cumulative_session_risk": r_total,
        "automated_soar_action": soar_action
    } 