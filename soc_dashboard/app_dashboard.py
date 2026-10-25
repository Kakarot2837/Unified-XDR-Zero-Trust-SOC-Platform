# soc_dashboard/app_dashboard.py
import os
import sys
import json
import sqlite3
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
from datetime import datetime

# Ensure root directory is in sys.path so imports work cleanly on Windows
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Replace the old imports in app_dashboard.py with these:
from core_backend.database.models import (
    SessionLocal, engine, User, AuthSession, ThreatIndicator,
    SecurityAlert, IncidentResponseAudit, redis_cache
)
from core_backend.database.seed_db import init_and_seed_db

# THIS IS THE CRITICAL LINE TO FIX YOUR ERROR:
from core_backend.correlation_engine import TelemetryEvent, record_and_correlate_alert

from sensors.all_detectors import (
    detect_port_scan, detect_dos_flood, detect_arp_spoofing,
    detect_sqli, track_brute_force, calculate_haversine_velocity,
    analyze_keystroke_biometrics, verify_webcam_face_bytes,
    compute_file_sha256, analyze_vishing_transcript
)
# Initialize DB & Seed Data on launch
init_and_seed_db()

st.set_page_config(
    page_title="Unified XDR & Zero-Trust SOC Platform",
    page_icon="🛡️",
    layout="wide"
)

def get_db_session():
    return SessionLocal()

def run_sql_df(query: str) -> pd.DataFrame:
    with sqlite3.connect(os.path.join(ROOT_DIR, "xdr_soc.db")) as conn:
        return pd.read_sql_query(query, conn)

# ==========================================
# SIDEBAR: 1-CLICK RED-TEAM ATTACK SIMULATOR
# ==========================================
st.sidebar.title("⚡ Red-Team Simulator")
st.sidebar.caption("1-Click Demo Triggers for All 10 Modules")

db = get_db_session()
current_session = db.query(AuthSession).filter_by(session_id="sess_pune_01").first()
current_user = db.query(User).filter_by(username="aditya_admin").first()

if st.sidebar.button("🟢 Reset Demo to Clean Baseline", use_container_width=True):
    db.query(IncidentResponseAudit).delete()
    db.query(SecurityAlert).delete()
    if current_session:
        current_session.session_risk_score = 10.0
        current_session.session_status = "ACTIVE"
        current_session.city = "Pune"
        current_session.country = "India"
        current_session.latitude = 18.5204
        current_session.longitude = 73.8567
        current_session.geo_velocity_kmh = 0.0
        current_session.source_ip = "103.21.125.10"
    redis_cache.blocked_ips.clear()
    redis_cache.store.clear()
    db.commit()
    st.sidebar.success("Reset to Clean Baseline (Risk: 10, Pune)")
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("🔥 Trigger Individual Attacks")

if st.sidebar.button("1️⃣ Port Scan (Nmap 20 Ports)", use_container_width=True):
    res = {}
    for p in range(20, 40):
        res = detect_port_scan("45.155.205.233", p)
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="45.155.205.233",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("2️⃣ High-Volume DoS Flood (350 PPS)", use_container_width=True):
    res = detect_dos_flood("198.51.100.77", packet_burst_count=350)
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="198.51.100.77",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("3️⃣ ARP Spoofing (Fake Gateway MAC)", use_container_width=True):
    res = detect_arp_spoofing("192.168.1.1", "de:ad:be:ef:99:99")
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="192.168.1.55",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("4️⃣ Brute Force (5 Failed Logins)", use_container_width=True):
    res = {}
    for _ in range(5):
        res = track_brute_force("185.220.101.45", "aditya_admin")
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="185.220.101.45",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("5️⃣ SQL Injection (' OR '1'='1)", use_container_width=True):
    res = detect_sqli("admin' OR '1'='1 -- DROP TABLE users;")
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="185.220.101.45",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("6️⃣ Impossible Travel (Pune -> London)", use_container_width=True):
    res = calculate_haversine_velocity(18.5204, 73.8567, 51.5074, -0.1278, elapsed_hours=0.25)
    if current_session:
        current_session.city = "London"
        current_session.country = "UK"
        current_session.latitude = 51.5074
        current_session.longitude = -0.1278
        current_session.geo_velocity_kmh = res["velocity_kmh"]
        current_session.source_ip = "185.220.101.45"
        db.commit()
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="185.220.101.45",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("7️⃣ Keystroke Biometric Anomaly", use_container_width=True):
    res = analyze_keystroke_biometrics([190, 210, 185, 220], [310, 295, 340, 305])
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="185.220.101.45",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("8️⃣ Face Auth Spoof / Missing Face", use_container_width=True):
    record_and_correlate_alert(TelemetryEvent(
        source_ip="185.220.101.45",
        module_name="FACE_VERIFICATION",
        threat_type="Face Verification Failed (No Live Face Detected)",
        severity="HIGH",
        base_risk_score=45.0,
        confidence_score=0.95,
        raw_payload="OpenCV Haar Cascade detected 0 faces during step-up biometric challenge."
    ), db)
    st.rerun()

if st.sidebar.button("9️⃣ Malware SHA-256 File Drop", use_container_width=True):
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    record_and_correlate_alert(TelemetryEvent(
        source_ip="103.21.125.10",
        indicator_value=eicar_hash,
        module_name="MALWARE_HASH",
        threat_type="Known Malware Executable Quarantined (EICAR/LockBit)",
        severity="CRITICAL",
        base_risk_score=60.0,
        confidence_score=1.0,
        raw_payload=f"File invoice_update.exe matched SHA-256 [{eicar_hash[:18]}...]. Quarantined."
    ), db)
    st.rerun()

if st.sidebar.button("🔟 AI Vishing Scam Call + IOC Hit", use_container_width=True):
    scam_text = "Hello this is bank support, your account suspended! Share your OTP and install AnyDesk for remote access immediately."
    res = analyze_vishing_transcript(scam_text)
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="185.220.101.45",
            indicator_value="secure-bank-otp-verify.com",
            module_name=res["module_name"],
            threat_type=res["threat_type"],
            severity=res["severity"],
            base_risk_score=res["base_risk_score"],
            confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

# ==========================================
# MAIN HEADER & LIVE STATUS METRICS
# ==========================================
st.title("🛡️ Unified XDR & Zero-Trust SOC Platform")
st.caption("10-Module Multi-Layer Threat Detection • Hybrid Relational DBMS • Real-Time Risk Correlation & SOAR")

db.refresh(current_session)
risk_val = current_session.session_risk_score
status_val = current_session.session_status
total_alerts_count = db.query(SecurityAlert).count()
total_iocs_count = db.query(ThreatIndicator).count()

# Dynamic SOAR Banner
if status_val == "LOCKED" or risk_val >= 80:
    st.error(f"🚨 **CRITICAL ZERO-TRUST SOAR ENFORCEMENT ACTIVE:** Session `sess_pune_01` is **LOCKED** (Cumulative Risk: **{risk_val}/100**). Source IP `{current_session.source_ip}` added to Blocklist & Step-Up Biometrics Required!")
elif status_val == "STEP_UP_REQUIRED" or risk_val >= 40:
    st.warning(f"⚠️ **ELEVATED SESSION RISK ({risk_val}/100):** Mandatory **Webcam Face Verification Step-Up** triggered for user `aditya_admin`.")
else:
    st.success(f"✅ **ZERO-TRUST SESSION HEALTHY ({risk_val}/100):** User `aditya_admin` authenticated from `{current_session.city}, {current_session.country}` ({current_session.source_ip}).")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Dynamic Session Risk Score", f"{risk_val} / 100", delta="Critical >= 80" if risk_val >= 80 else "Normal < 40", delta_color="inverse")
m2.metric("Session Enforcement Status", status_val)
m3.metric("Total Security Alerts (SIEM)", total_alerts_count)
m4.metric("Geo-Velocity (Last Login Jump)", f"{current_session.geo_velocity_kmh} km/h", delta="Limit: 800 km/h", delta_color="off")

# ==========================================
# 4 INTERACTIVE TABS
# ==========================================
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 1. Live SOC Overview & Geo-Map",
    "🔐 2. Zero-Trust Login, Keystroke & Face Portal",
    "🧪 3. Network, Malware Hash & AI Vishing Sandbox",
    "🗄️ 4. DBMS Live SQL Explorer (Evaluation View)"
])

# ------------------------------------------
# TAB 1: SOC OVERVIEW, RISK GAUGE & MAP
# ------------------------------------------
with tab1:
    col_gauge, col_map = st.columns([1, 1.4])

    with col_gauge:
        st.subheader("🎯 Multi-Signal Session Risk Gauge")
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_val,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Session Risk Score (R_total)"},
            gauge={
                'axis': {'range': [0, 150]},
                'bar': {'color': "#ef4444" if risk_val >= 80 else "#f59e0b" if risk_val >= 40 else "#10b981"},
                'steps': [
                    {'range': [0, 40], 'color': "rgba(16, 185, 129, 0.2)"},
                    {'range': [40, 80], 'color': "rgba(245, 158, 11, 0.2)"},
                    {'range': [80, 150], 'color': "rgba(239, 68, 68, 0.25)"}
                ],
                'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.8, 'value': 80}
            }
        ))
        fig_gauge.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col_map:
        st.subheader("🌍 Geo-Velocity & Impossible Travel Tracker")
        fig_map = go.Figure()
        # Baseline Pune Marker
        fig_map.add_trace(go.Scattergeo(
            lon=[73.8567, current_session.longitude],
            lat=[18.5204, current_session.latitude],
            mode='lines+markers+text',
            text=["Pune (Baseline)", f"{current_session.city} ({current_session.geo_velocity_kmh} km/h)"],
            textposition="top center",
            line=dict(width=3, color="#ef4444" if current_session.geo_velocity_kmh > 800 else "#3b82f6"),
            marker=dict(size=10, color=["#10b981", "#ef4444" if current_session.geo_velocity_kmh > 800 else "#10b981"])
        ))
        fig_map.update_layout(
            height=320,
            margin=dict(l=0, r=0, t=10, b=0),
            geo=dict(projection_type="natural earth", showland=True, landcolor="#1e293b", oceancolor="#0f172a", showocean=True)
        )
        st.plotly_chart(fig_map, use_container_width=True)

    st.subheader("🚨 Live Enriched SIEM Alert Stream (`security_alerts` + `threat_indicators`)")
    df_alerts = run_sql_df("""
        SELECT a.alert_id, a.timestamp, a.module_name, a.threat_type, a.severity,
               a.source_ip, a.base_risk_score, a.ioc_bonus_score,
               COALESCE(t.threat_actor, 'None') AS ioc_actor, a.raw_payload
        FROM security_alerts a
        LEFT JOIN threat_indicators t ON a.ioc_id = t.ioc_id
        ORDER BY a.alert_id DESC LIMIT 25
    """)
    st.dataframe(df_alerts, use_container_width=True, hide_index=True)

# ------------------------------------------
# TAB 2: ZERO-TRUST LOGIN, KEYSTROKE & FACE
# ------------------------------------------
with tab2:
    st.subheader("🔐 Interactive Zero-Trust Login & Biometric Verification")
    c_login, c_bio = st.columns(2)

    with c_login:
        st.markdown("#### 1. Login & Keystroke Rhythm Simulator")
        u_in = st.text_input("Username (Try SQLi: `admin' OR '1'='1`)", value="aditya_admin")
        p_in = st.text_input("Password (Correct: `kakarot_ultra_secret_123`)", value="kakarot_ultra_secret_123", type="password")
        loc_choice = st.selectbox("Simulated Login Location (GeoIP)", [
            "Pune, India (103.21.125.10) — Normal Baseline",
            "London, UK / Tor Exit Node (185.220.101.45) — Impossible Travel + IOC Hit",
            "Pyongyang, NK Scanner (45.155.205.233) — Impossible Travel + APT IOC"
        ])
        typing_style = st.radio("Simulated Keystroke Typing Rhythm", [
            "Natural Owner Rhythm (Dwell ~85ms, Flight ~120ms)",
            "Slow/Hesitant Attacker Rhythm (Dwell ~195ms, Flight ~310ms -> Triggers Anomaly)"
        ])

        if st.button("🚀 Submit Zero-Trust Login Attempt", use_container_width=True):
            # 1. Check SQLi
            sqli_res = detect_sqli(f"{u_in} {p_in}")
            if sqli_res["triggered"]:
                record_and_correlate_alert(TelemetryEvent(
                    source_ip="185.220.101.45",
                    module_name=sqli_res["module_name"],
                    threat_type=sqli_res["threat_type"],
                    severity=sqli_res["severity"],
                    base_risk_score=sqli_res["base_risk_score"],
                    confidence_score=sqli_res["confidence_score"],
                    raw_payload=sqli_res["raw_payload"]
                ), db)
                st.error("🚨 SQL Injection Payload Detected & Blocked by Middleware!")
            elif p_in != "kakarot_ultra_secret_123":
                bf_res = track_brute_force("185.220.101.45", u_in)
                st.warning(f"❌ Invalid Password! Failed attempt counter: {bf_res.get('attempts', 5)}/5")
                if bf_res["triggered"]:
                    record_and_correlate_alert(TelemetryEvent(
                        source_ip="185.220.101.45",
                        module_name=bf_res["module_name"],
                        threat_type=bf_res["threat_type"],
                        severity=bf_res["severity"],
                        base_risk_score=bf_res["base_risk_score"],
                        confidence_score=bf_res["confidence_score"],
                        raw_payload=bf_res["raw_payload"]
                    ), db)
            else:
                # Parse Location
                if "London" in loc_choice:
                    ip, city, country, lat, lon = "185.220.101.45", "London", "UK", 51.5074, -0.1278
                elif "Pyongyang" in loc_choice:
                    ip, city, country, lat, lon = "45.155.205.233", "Pyongyang", "North Korea", 39.0392, 125.7625
                else:
                    ip, city, country, lat, lon = "103.21.125.10", "Pune", "India", 18.5204, 73.8567

                geo_res = calculate_haversine_velocity(18.5204, 73.8567, lat, lon, 0.25)
                current_session.city, current_session.country = city, country
                current_session.latitude, current_session.longitude = lat, lon
                current_session.geo_velocity_kmh = geo_res["velocity_kmh"]
                current_session.source_ip = ip
                db.commit()

                if geo_res["triggered"]:
                    record_and_correlate_alert(TelemetryEvent(
                        source_ip=ip, module_name=geo_res["module_name"],
                        threat_type=geo_res["threat_type"], severity=geo_res["severity"],
                        base_risk_score=geo_res["base_risk_score"], confidence_score=geo_res["confidence_score"],
                        raw_payload=geo_res["raw_payload"]
                    ), db)

                # Keystroke Check
                dwells = [84, 86, 85, 83] if "Natural" in typing_style else [195, 205, 188, 210]
                flights = [118, 122, 120, 119] if "Natural" in typing_style else [305, 320, 298, 315]
                ks_res = analyze_keystroke_biometrics(dwells, flights)
                if ks_res["triggered"]:
                    record_and_correlate_alert(TelemetryEvent(
                        source_ip=ip, module_name=ks_res["module_name"],
                        threat_type=ks_res["threat_type"], severity=ks_res["severity"],
                        base_risk_score=ks_res["base_risk_score"], confidence_score=ks_res["confidence_score"],
                        raw_payload=ks_res["raw_payload"]
                    ), db)
                st.rerun()

        # Keystroke Visual Comparison Chart
        df_ks = pd.DataFrame({
            "Metric": ["Dwell Time (ms)", "Flight Time (ms)"],
            "Stored User Baseline": [85.0, 120.0],
            "Current Login Attempt": [85.0, 120.0] if "Natural" in typing_style else [199.5, 309.5]
        })
        fig_ks = px.bar(df_ks, x="Metric", y=["Stored User Baseline", "Current Login Attempt"], barmode="group", height=240, title="Keystroke Dynamics Profile vs. Live Input")
        st.plotly_chart(fig_ks, use_container_width=True)

    with c_bio:
        st.markdown("#### 2. Live OpenCV Webcam Face Verification (Module 8)")
        st.info("Take a live snapshot below to verify a real human face using OpenCV Haar Cascades (unlocks Step-Up Auth).")
        cam_photo = st.camera_input("Capture Live Biometric Frame")
        if cam_photo is not None:
            face_res = verify_webcam_face_bytes(cam_photo.getvalue())
            if face_res["triggered"]:
                record_and_correlate_alert(TelemetryEvent(
                    source_ip=current_session.source_ip,
                    module_name=face_res["module_name"],
                    threat_type=face_res["threat_type"],
                    severity=face_res["severity"],
                    base_risk_score=face_res["base_risk_score"],
                    confidence_score=face_res["confidence_score"],
                    raw_payload=face_res["raw_payload"]
                ), db)
                st.error("🚨 OpenCV Detected 0 Live Faces! Biometric Step-Up Failed (+45 Risk).")
            else:
                st.success(f"✅ OpenCV Verified {face_res['faces_detected']} Live Human Face(s)! Step-Up Passed.")
                if current_session.session_risk_score >= 40:
                    current_session.session_risk_score = 15.0
                    current_session.session_status = "ACTIVE"
                    db.commit()

# ------------------------------------------
# TAB 3: NETWORK, MALWARE HASH & AI VISHING
# ------------------------------------------
with tab3:
    col_file, col_vish = st.columns(2)

    with col_file:
        st.subheader("🦠 Module 9: SHA-256 Malware File Scanner")
        st.write("Upload any file to compute its SHA-256 fingerprint and check against `threat_indicators`. *(Note: Uploading an empty 0-byte file matches our seeded `Ransomware.LockBit.Dropper` SHA-256 hash `e3b0c44...`!)*")
        up_file = st.file_uploader("Drop File to Scan", type=None)
        if up_file is not None:
            f_bytes = up_file.getvalue()
            sha_val = compute_file_sha256(f_bytes)
            st.code(f"Computed SHA-256: {sha_val}")
            matched = db.query(ThreatIndicator).filter_by(indicator_value=sha_val).first()
            if matched:
                q_file = os.path.join(ROOT_DIR, "quarantine", f"QUARANTINED_{up_file.name}")
                with open(q_file, "wb") as f:
                    f.write(f_bytes)
                record_and_correlate_alert(TelemetryEvent(
                    source_ip=current_session.source_ip,
                    indicator_value=sha_val,
                    module_name="MALWARE_HASH",
                    threat_type=f"Malware Hash Match ({matched.threat_actor})",
                    severity="CRITICAL",
                    base_risk_score=60.0,
                    confidence_score=1.0,
                    raw_payload=f"File {up_file.name} matched IOC {matched.threat_actor}. Quarantined."
                ), db)
                st.error(f"🚨 CRITICAL MALWARE DETECTED: `{matched.threat_actor}`! File isolated in `/quarantine`.")
            else:
                st.success("✅ File SHA-256 Hash is Clean (0 matches in Threat Intelligence DB).")

    with col_vish:
        st.subheader("📞 Module 10: AI Vishing (Voice Phishing) Analyzer")
        default_scam = "Urgent call from bank support: Your KYC blocked and account suspended. Please share your OTP and CVV number or install AnyDesk for remote access immediately."
        vish_input = st.text_area("Transcribed Support Call / Voicemail Audio Text", value=default_scam, height=120)
        if st.button("🔍 Scan Call Transcript for Social Engineering", use_container_width=True):
            v_res = analyze_vishing_transcript(vish_input)
            if v_res["triggered"]:
                record_and_correlate_alert(TelemetryEvent(
                    source_ip="185.220.101.45",
                    indicator_value="secure-bank-otp-verify.com",
                    module_name=v_res["module_name"],
                    threat_type=v_res["threat_type"],
                    severity=v_res["severity"],
                    base_risk_score=v_res["base_risk_score"],
                    confidence_score=v_res["confidence_score"],
                    raw_payload=v_res["raw_payload"]
                ), db)
                st.error(f"🚨 VISHING SCAM DETECTED! Flagged High-Urgency Cues: `{v_res['matched_keywords']}`")
            else:
                st.success("✅ Call transcript appears benign.")

# ------------------------------------------
# TAB 4: DBMS LIVE SQL EXPLORER
# ------------------------------------------
with tab4:
    st.subheader("🗄️ Database Management System (DBMS) Live Inspector")
    st.caption("Demonstrates Relational Schema, Foreign Key JOINs, Indexed IOC Lookups, and SQL Views for Evaluation")

    v1, v2 = st.columns(2)
    with v1:
        st.markdown("##### 📊 SQL View 1: `vw_high_risk_users`")
        st.dataframe(run_sql_df("SELECT * FROM vw_high_risk_users"), use_container_width=True, hide_index=True)
    with v2:
        st.markdown("##### 📈 SQL View 2: `vw_threat_module_summary`")
        st.dataframe(run_sql_df("SELECT * FROM vw_threat_module_summary"), use_container_width=True, hide_index=True)

    st.markdown("##### 🔗 Relational Threat Intelligence IOC Table (`threat_indicators`)")
    st.dataframe(run_sql_df("SELECT * FROM threat_indicators"), use_container_width=True, hide_index=True)

    st.markdown("##### 🛡️ Automated SOAR Audit Trail (`incident_response_audit`)")
    st.dataframe(run_sql_df("SELECT * FROM incident_response_audit ORDER BY action_id DESC"), use_container_width=True, hide_index=True)

    st.markdown("##### 💻 Run Custom Live SQL Query (For Examiner Q&A)")
    custom_sql = st.text_area("SQL Query", value="SELECT a.alert_id, u.username, a.module_name, a.severity, t.threat_actor, a.base_risk_score, a.ioc_bonus_score FROM security_alerts a JOIN users u ON a.user_id = u.user_id LEFT JOIN threat_indicators t ON a.ioc_id = t.ioc_id ORDER BY a.alert_id DESC;")
    if st.button("▶️ Execute SQL Query"):
        try:
            st.dataframe(run_sql_df(custom_sql), use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"SQL Error: {e}")

db.close()
