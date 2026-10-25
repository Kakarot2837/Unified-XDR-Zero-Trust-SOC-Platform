# core_backend/database/models.py
import time
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey, text
)
from sqlalchemy.orm import declarative_base, sessionmaker

# Creates a local relational SQLite database file automatically
DATABASE_URL = "sqlite:///./xdr_soc.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- In-Memory Redis Fallback (For Rate Limiting, DoS PPS & IP Blocklist) ---
class InMemoryRedisCache:
    def __init__(self):
        self.store = {}
        self.blocked_ips = set()

    def incr_with_ttl(self, key: str, ttl_seconds: int = 60) -> int:
        now = time.time()
        if key in self.store:
            count, expiry = self.store[key]
            if now < expiry:
                self.store[key] = (count + 1, expiry)
                return count + 1
        self.store[key] = (1, now + ttl_seconds)
        return 1

    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

redis_cache = InMemoryRedisCache()

# --- 5 Core Relational DBMS Tables ---

class User(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="ANALYST")
    mean_dwell_ms = Column(Float, default=85.0)
    std_dwell_ms = Column(Float, default=15.0)
    mean_flight_ms = Column(Float, default=120.0)
    std_flight_ms = Column(Float, default=25.0)
    face_encoding_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuthSession(Base):
    __tablename__ = "auth_sessions"
    session_id = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), index=True)
    login_timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    city = Column(String(60), default="Pune")
    country = Column(String(60), default="India")
    latitude = Column(Float, default=18.5204)
    longitude = Column(Float, default=73.8567)
    geo_velocity_kmh = Column(Float, default=0.0)
    session_risk_score = Column(Float, default=0.0)
    session_status = Column(String(20), default="ACTIVE") # ACTIVE, STEP_UP_REQUIRED, LOCKED

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    ioc_id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_value = Column(String(255), unique=True, nullable=False, index=True)
    indicator_type = Column(String(20), nullable=False) # IP, DOMAIN, SHA256
    threat_actor = Column(String(100), nullable=False)
    reputation_score = Column(Integer, default=90)
    source_feed = Column(String(50), default="AbuseIPDB / Local")
    last_seen = Column(DateTime, default=datetime.utcnow)

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    session_id = Column(String(64), ForeignKey("auth_sessions.session_id"), nullable=True)
    ioc_id = Column(Integer, ForeignKey("threat_indicators.ioc_id"), nullable=True)
    source_ip = Column(String(45), nullable=False, index=True)
    module_name = Column(String(50), nullable=False, index=True)
    threat_type = Column(String(80), nullable=False)
    severity = Column(String(15), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    base_risk_score = Column(Float, nullable=False)
    ioc_bonus_score = Column(Float, default=0.0)
    confidence_score = Column(Float, default=1.0)
    raw_payload = Column(Text, nullable=False)
    status = Column(String(20), default="OPEN")

class IncidentResponseAudit(Base):
    __tablename__ = "incident_response_audit"
    action_id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("security_alerts.alert_id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    automated_action = Column(String(100), nullable=False)
    analyst_notes = Column(Text, default="Automated Zero-Trust SOAR Policy Execution")