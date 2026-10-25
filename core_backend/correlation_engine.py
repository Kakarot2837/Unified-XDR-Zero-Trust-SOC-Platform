# core_backend/correlation_engine.py
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core_backend.database.models import (
    SessionLocal, AuthSession, ThreatIndicator,
    SecurityAlert, IncidentResponseAudit, redis_cache
)

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

def record_and_correlate_alert(event: TelemetryEvent, db: Session) -> dict:
    lookup_val = event.indicator_value or event.source_ip
    matched_ioc = db.query(ThreatIndicator).filter(
        ThreatIndicator.indicator_value == lookup_val
    ).first()

    ioc_id = matched_ioc.ioc_id if matched_ioc else None
    ioc_bonus = 25.0 if matched_ioc else 0.0
    ioc_tag = (
        f"IOC HIT: {matched_ioc.threat_actor} (Rep: {matched_ioc.reputation_score}%)"
        if matched_ioc else "Clean IOC"
    )

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

    # 10-minute sliding window correlation
    window_start = datetime.utcnow() - timedelta(minutes=10)
    recent_alerts = db.query(SecurityAlert).filter(
        SecurityAlert.session_id == event.session_id,
        SecurityAlert.timestamp >= window_start
    ).all()

    total_risk = sum(a.base_risk_score * a.confidence_score for a in recent_alerts)
    max_ioc_bonus = max((a.ioc_bonus_score for a in recent_alerts), default=0.0)
    r_total = round(total_risk + max_ioc_bonus, 1)

    soar_action = "ALLOW_MONITOR"
    if r_total >= 80.0:
        soar_action = "SESSION_LOCKED_AND_IP_BLOCKED"
        redis_cache.block_ip(event.source_ip)
    elif r_total >= 40.0:
        soar_action = "FACE_STEP_UP_FORCED"

    session_obj = db.query(AuthSession).filter_by(session_id=event.session_id).first()
    if session_obj:
        session_obj.session_risk_score = r_total
        session_obj.source_ip = event.source_ip
        if r_total >= 80.0:
            session_obj.session_status = "LOCKED"
        elif r_total >= 40.0:
            session_obj.session_status = "STEP_UP_REQUIRED"

    if soar_action != "ALLOW_MONITOR":
        db.add(IncidentResponseAudit(
            alert_id=new_alert.alert_id,
            automated_action=soar_action,
            analyst_notes=f"Auto-SOAR triggered at Session Risk = {r_total}/100 ({ioc_tag})"
        ))
    db.commit()

    return {
        "alert_id": new_alert.alert_id,
        "module": event.module_name,
        "ioc_enriched": bool(matched_ioc),
        "ioc_details": ioc_tag,
        "cumulative_session_risk": r_total,
        "automated_soar_action": soar_action
    }