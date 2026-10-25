# core_backend/database/seed_db.py
from sqlalchemy import text
from core_backend.database.models import (
    Base, engine, SessionLocal, User, AuthSession, ThreatIndicator
)

def init_and_seed_db():
    print("[*] Creating relational tables in xdr_soc.db...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # 1. Seed Default User with Baseline Keystroke Biometrics
    if not db.query(User).filter_by(username="aditya_admin").first():
        admin_user = User(
            username="aditya_admin",
            email="aditya@vit.edu",
            password_hash="kakarot_ultra_secret_123",
            role="ADMIN",
            mean_dwell_ms=85.0,
            std_dwell_ms=15.0,
            mean_flight_ms=120.0,
            std_flight_ms=25.0,
            face_encoding_json="[0.12, -0.08, 0.44, 0.91]"
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

        # Create initial baseline login session from Pune
        initial_session = AuthSession(
            session_id="sess_pune_01",
            user_id=admin_user.user_id,
            source_ip="103.21.125.10",
            city="Pune",
            country="India",
            latitude=18.5204,
            longitude=73.8567,
            geo_velocity_kmh=0.0,
            session_risk_score=10.0,
            session_status="ACTIVE"
        )
        db.add(initial_session)

    # 2. Seed Threat Intelligence IOCs (Malicious IPs, Domains, and Malware SHA-256 Hashes)
    sample_iocs = [
        ("185.220.101.45", "IP", "Tor Exit Node / Russian Proxy", 98, "AbuseIPDB"),
        ("45.155.205.233", "IP", "Lazarus APT Scanner", 95, "AlienVault OTX"),
        ("198.51.100.77", "IP", "Mirai DDoS Botnet Node", 92, "Spamhaus"),
        ("secure-bank-otp-verify.com", "DOMAIN", "Phishing / Vishing C2", 96, "OpenPhish"),
        # EICAR Standard Antivirus Test File SHA-256 Hash
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "SHA256", "EICAR.Test.Malware", 100, "VirusTotal"),
        # Custom Demo Malware Hash (for file containing text: MALWARE_PAYLOAD_DEMO)
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256", "Ransomware.LockBit.Dropper", 99, "HybridAnalysis")
    ]

    for val, i_type, actor, score, feed in sample_iocs:
        if not db.query(ThreatIndicator).filter_by(indicator_value=val).first():
            db.add(ThreatIndicator(
                indicator_value=val,
                indicator_type=i_type,
                threat_actor=actor,
                reputation_score=score,
                source_feed=feed
            ))

    db.commit()

    # 3. Create SQL Analytical Views for DBMS Evaluation
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE VIEW IF NOT EXISTS vw_high_risk_users AS
            SELECT 
                u.user_id,
                u.username,
                u.role,
                s.session_id,
                s.source_ip,
                s.city || ', ' || s.country AS location,
                s.geo_velocity_kmh,
                s.session_risk_score,
                s.session_status,
                COUNT(a.alert_id) AS total_alerts
            FROM users u
            LEFT JOIN auth_sessions s ON u.user_id = s.user_id
            LEFT JOIN security_alerts a ON u.user_id = a.user_id
            GROUP BY u.user_id, s.session_id
            ORDER BY s.session_risk_score DESC;
        """))
        conn.execute(text("""
            CREATE VIEW IF NOT EXISTS vw_threat_module_summary AS
            SELECT 
                module_name,
                severity,
                COUNT(alert_id) AS alert_count,
                ROUND(AVG(base_risk_score + ioc_bonus_score), 2) AS avg_total_risk
            FROM security_alerts
            GROUP BY module_name, severity
            ORDER BY alert_count DESC;
        """))
        conn.commit()

    db.close()
    print("[+] Database seeded successfully with Users, Sessions, IOCs, and SQL Views!")

if __name__ == "__main__":
    init_and_seed_db()