# soc_dashboard/app_dashboard.py
import os
import sys
import time
import wave
import math
import struct
import json
import sqlite3
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core_backend.database.models import (
    SessionLocal, User, AuthSession, ThreatIndicator,
    SecurityAlert, IncidentResponseAudit, redis_cache
)
from core_backend.database.seed_db import init_and_seed_db
from core_backend.correlation_engine import TelemetryEvent, record_and_correlate_alert
from sensors.all_detectors import (
    detect_port_scan, detect_dos_flood, detect_arp_spoofing,
    detect_sqli, track_brute_force, analyze_keystroke_biometrics,
    verify_webcam_face_bytes, compute_file_sha256, analyze_ai_voice_fft
)

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

if "authenticated_gate" not in st.session_state:
    st.session_state.authenticated_gate = False
if "failed_login_count" not in st.session_state:
    st.session_state.failed_login_count = 0
if "lockout_until" not in st.session_state:
    st.session_state.lockout_until = 0.0

db = get_db_session()

# ==============================================================================
# ZERO-TRUST LOGIN GATE + >5 ATTEMPTS 30s SCREEN LOCKOUT + CAMERA THREAT SCANNER
# ==============================================================================
if not st.session_state.authenticated_gate:
    st.title("🔐 Zero-Trust SOC Gatekeeper — Mandatory Authentication")
    st.caption("Protected by Brute-Force Lockout (>5 Attempts = 30s Screen Lock), SQLi WAF & Live Camera Threat Analysis")

    now_ts = time.time()
    remaining_lock = int(st.session_state.lockout_until - now_ts)

    if remaining_lock > 0:
        st.error(f"🚨 **BRUTE-FORCE LOCKOUT TRIGGERED!** Too many failed login attempts (>5). Screen is locked for **{remaining_lock} seconds**!")
        st.progress(min(remaining_lock / 30.0, 1.0))
        time.sleep(1)
        st.rerun()

    col_gate_login, col_gate_cam = st.columns([1.1, 1])

    with col_gate_login:
        st.subheader("1️⃣ Enter Operator Credentials")
        gate_user = st.text_input("SOC Username", value="aditya_admin")
        gate_pass = st.text_input("SOC Password (Default: `kakarot_ultra_secret_123`)", type="password")
        st.caption(f"Active Failed Attempts: **{st.session_state.failed_login_count} / 5**")

        if st.button("🚀 Authenticate & Open SOC Dashboard", use_container_width=True):
            sqli_check = detect_sqli(f"{gate_user} {gate_pass}", target_endpoint="/gatekeeper/login")
            if sqli_check["triggered"]:
                record_and_correlate_alert(TelemetryEvent(
                    source_ip="185.220.101.45", module_name=sqli_check["module_name"],
                    threat_type=sqli_check["threat_type"], severity=sqli_check["severity"],
                    base_risk_score=sqli_check["base_risk_score"], confidence_score=sqli_check["confidence_score"],
                    raw_payload=sqli_check["raw_payload"]
                ), db)
                st.error(f"🚨 SQL Injection Blocked! Command logged: `{sqli_check['telemetry']['attacker_command_used']}`")
            elif gate_user == "aditya_admin" and gate_pass == "kakarot_ultra_secret_123":
                st.session_state.failed_login_count = 0
                st.session_state.authenticated_gate = True
                st.success("✅ Authentication Successful! Loading SOC Platform...")
                st.rerun()
            else:
                st.session_state.failed_login_count += 1
                bf_res = track_brute_force("185.220.101.45", gate_user)
                if st.session_state.failed_login_count > 5 or bf_res["triggered"]:
                    st.session_state.lockout_until = time.time() + 30.0
                    record_and_correlate_alert(TelemetryEvent(
                        source_ip="185.220.101.45", module_name="BRUTE_FORCE",
                        threat_type=f"Brute Force Lockout ({st.session_state.failed_login_count} Attempts -> 30s Lock)",
                        severity="HIGH", base_risk_score=30.0, confidence_score=0.98,
                        raw_payload=json.dumps({
                            "source_ip": "185.220.101.45", "target_username": gate_user,
                            "failed_attempts_count": st.session_state.failed_login_count,
                            "action_taken": "SCREEN_LOCKED_30_SECONDS"
                        })
                    ), db)
                    st.rerun()
                else:
                    st.warning(f"❌ Invalid Credentials! Attempt {st.session_state.failed_login_count}/5 (Locks for 30s after 5 attempts).")

    with col_gate_cam:
        st.subheader("2️⃣ Live Camera Threat & Shoulder-Surfing Scanner")
        st.info("Detects: (1) Single Authorized User, (2) Multiple Persons / Shoulder-Surfing Threat, (3) Covered/Dark Lens Spoof, (4) Missing Operator.")
        gate_cam = st.camera_input("Scan Operator Environment")
        if gate_cam is not None:
            cam_res = verify_webcam_face_bytes(gate_cam.getvalue())
            for note in cam_res["notifications"]:
                if "THREAT" in note or "ALERT" in note:
                    st.error(note)
                else:
                    st.success(note)
            st.json(cam_res["telemetry"])
            if cam_res["triggered"]:
                record_and_correlate_alert(TelemetryEvent(
                    source_ip="103.21.125.10", module_name=cam_res["module_name"],
                    threat_type=cam_res["threat_type"], severity=cam_res["severity"],
                    base_risk_score=cam_res["base_risk_score"], confidence_score=cam_res["confidence_score"],
                    raw_payload=cam_res["raw_payload"]
                ), db)

    db.close()
    st.stop()

# ==============================================================================
# MAIN SOC PLATFORM (IMPOSSIBLE TRAVEL COMPLETELY REMOVED)
# ==============================================================================
current_session = db.query(AuthSession).filter_by(session_id="sess_pune_01").first()

st.sidebar.title("⚡ Red-Team & Controls")
if st.sidebar.button("🔒 Logout (Test Login Gate & 30s Lock)", use_container_width=True):
    st.session_state.authenticated_gate = False
    st.rerun()

if st.sidebar.button("🟢 Reset Demo to Clean Baseline", use_container_width=True):
    db.query(IncidentResponseAudit).delete()
    db.query(SecurityAlert).delete()
    if current_session:
        current_session.session_risk_score = 10.0
        current_session.session_status = "ACTIVE"
        current_session.source_ip = "103.21.125.10"
    redis_cache.blocked_ips.clear()
    redis_cache.store.clear()
    db.commit()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("🔥 1-Click Attack Triggers")

if st.sidebar.button("1️⃣ Port Scan (19 Ports Probed)", use_container_width=True):
    res = {}
    for p in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8000, 8080]:
        res = detect_port_scan("45.155.205.233", p)
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="45.155.205.233", module_name=res["module_name"],
            threat_type=res["threat_type"], severity=res["severity"],
            base_risk_score=res["base_risk_score"], confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("2️⃣ High-Volume DoS (380 PPS)", use_container_width=True):
    res = detect_dos_flood("198.51.100.77", packet_burst_count=380, protocol="UDP/SYN Volumetric Flood")
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="198.51.100.77", module_name=res["module_name"],
            threat_type=res["threat_type"], severity=res["severity"],
            base_risk_score=res["base_risk_score"], confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("3️⃣ ARP Spoofing (MITM MAC Hijack)", use_container_width=True):
    res = detect_arp_spoofing("192.168.1.1", "de:ad:be:ef:99:99", "Gratuitous ARP Reply (op=2)")
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="192.168.1.55", module_name=res["module_name"],
            threat_type=res["threat_type"], severity=res["severity"],
            base_risk_score=res["base_risk_score"], confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("4️⃣ Brute Force (6 Failed Logins)", use_container_width=True):
    res = {}
    for _ in range(6):
        res = track_brute_force("185.220.101.45", "aditya_admin")
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="185.220.101.45", module_name=res["module_name"],
            threat_type=res["threat_type"], severity=res["severity"],
            base_risk_score=res["base_risk_score"], confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

if st.sidebar.button("5️⃣ SQL Injection (UNION SELECT)", use_container_width=True):
    res = detect_sqli("admin' OR '1'='1' UNION SELECT username, password_hash FROM users; --")
    if res.get("triggered"):
        record_and_correlate_alert(TelemetryEvent(
            source_ip="185.220.101.45", module_name=res["module_name"],
            threat_type=res["threat_type"], severity=res["severity"],
            base_risk_score=res["base_risk_score"], confidence_score=res["confidence_score"],
            raw_payload=res["raw_payload"]
        ), db)
    st.rerun()

# --- HEADER & METRICS ---
st.title("🛡️ Unified XDR & Zero-Trust SOC Platform")
db.refresh(current_session)
risk_val = min(round(current_session.session_risk_score, 1), 100.0)
status_val = current_session.session_status
total_alerts_count = db.query(SecurityAlert).count()

m1, m2, m3 = st.columns(3)
m1.metric("Dynamic Session Risk Score", f"{risk_val} / 100")
m2.metric("Zero-Trust Session Status", status_val)
m3.metric("Total Alerts Stored in DB", total_alerts_count)

tab1, tab_true, tab_live, tab2, tab3, tab4 = st.tabs([
    "📊 1. SOC Overview & SIEM Stream",
    "🔍 2. True Sensor Telemetry Values",
    "📡 3. Live Attacker Feed (Auto-Reload)",
    "📸 4. Camera Threat & Keystroke Biometrics",
    "🎙️ 5. FFT AI Voice Rec & SHA-256 Malware",
    "🗄️ 6. DBMS Live SQL Explorer"
])

# ------------------------------------------------------------------------------
# TAB 1: SOC OVERVIEW & SIEM STREAM
# ------------------------------------------------------------------------------
with tab1:
    c1, c2 = st.columns([1, 1.5])
    with c1:
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=risk_val,
            title={'text': "Unified Session Risk Score (0-100)"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "#ef4444" if risk_val >= 80 else "#f59e0b" if risk_val >= 40 else "#10b981"},
                'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.8, 'value': 80}
            }
        ))
        fig_gauge.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig_gauge, use_container_width=True)
    with c2:
        st.markdown("#### 🚨 Live Enriched SIEM Alert Stream (`security_alerts` + `threat_indicators`)")
        df_siem = run_sql_df("""
            SELECT a.alert_id, a.timestamp, a.module_name, a.threat_type, a.severity,
                   a.source_ip, a.base_risk_score, a.ioc_bonus_score,
                   COALESCE(t.threat_actor, 'Clean / Unlisted') AS ioc_actor
            FROM security_alerts a
            LEFT JOIN threat_indicators t ON a.ioc_id = t.ioc_id
            ORDER BY a.alert_id DESC LIMIT 15
        """)
        st.dataframe(df_siem, use_container_width=True, hide_index=True)

# ------------------------------------------------------------------------------
# TAB 2: TRUE SENSOR TELEMETRY VALUES
# ------------------------------------------------------------------------------
with tab_true:
    st.subheader("🔍 True Software Telemetry Inspector (Stored in Database)")
    t_col1, t_col2 = st.columns(2)
    with t_col1:
        ports_input = st.multiselect("Module 1 (Port Scan): Select Ports to Attack", [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8000, 8080], default=[21, 22, 80, 443, 3306, 3389])
        if st.button("Run Port Scan & Log True Ports"):
            res = {}
            for p in ports_input:
                res = detect_port_scan("45.155.205.233", p)
            record_and_correlate_alert(TelemetryEvent(
                source_ip="45.155.205.233", module_name="PORT_SCAN",
                threat_type=f"Port Scan ({len(ports_input)} Ports Attacked)", severity="MEDIUM",
                base_risk_score=30.0, confidence_score=0.95, raw_payload=json.dumps(res["telemetry"])
            ), db)
            st.rerun()

        dos_pps_in = st.slider("Module 2 (DoS Flood): Packets Per Second (PPS)", 50, 1000, 420)
        if st.button("Run DoS Flood & Log True PPS"):
            res = detect_dos_flood("198.51.100.77", packet_burst_count=dos_pps_in, protocol="TCP SYN Flood")
            record_and_correlate_alert(TelemetryEvent(
                source_ip="198.51.100.77", module_name="DOS_FLOOD",
                threat_type=f"DoS Flood ({dos_pps_in} PPS)", severity="CRITICAL",
                base_risk_score=50.0, confidence_score=0.99, raw_payload=json.dumps(res["telemetry"])
            ), db)
            st.rerun()

    with t_col2:
        arp_ip_in = st.selectbox("Module 3 (ARP Spoofing): Target IP", ["192.168.1.1", "192.168.1.10", "10.0.0.1"])
        arp_mac_in = st.text_input("Attacker Claimed MAC Address", value="de:ad:be:ef:caf:e1")
        arp_type_in = st.selectbox("ARP Packet Type", ["Gratuitous ARP Reply (op=2)", "Unsolicited ARP Broadcast (op=1)"])
        if st.button("Run ARP Spoof & Log MAC Binding"):
            res = detect_arp_spoofing(arp_ip_in, arp_mac_in, arp_type_in)
            record_and_correlate_alert(TelemetryEvent(
                source_ip="192.168.1.55", module_name="ARP_SPOOFING",
                threat_type=f"ARP Spoof ({arp_ip_in} -> {arp_mac_in})", severity="CRITICAL",
                base_risk_score=55.0, confidence_score=1.0, raw_payload=json.dumps(res["telemetry"])
            ), db)
            st.rerun()

        sqli_cmd_in = st.text_input("Module 5 (SQLi): Attacker SQL Command", value="admin' OR 1=1 UNION SELECT table_name FROM information_schema.tables; --")
        if st.button("Run SQLi & Log Attacker Command"):
            res = detect_sqli(sqli_cmd_in)
            record_and_correlate_alert(TelemetryEvent(
                source_ip="185.220.101.45", module_name="SQL_INJECTION",
                threat_type="SQL Injection Command Intercepted", severity="HIGH",
                base_risk_score=45.0, confidence_score=0.98, raw_payload=json.dumps(res["telemetry"])
            ), db)
            st.rerun()

    st.markdown("---")
    alerts_all = db.query(SecurityAlert).order_by(SecurityAlert.alert_id.desc()).all()
    port_rows, dos_rows, arp_rows, sqli_rows = [], [], [], []
    for a in alerts_all:
        raw_str = a.raw_payload.split(" | [")[0]
        try:
            data = json.loads(raw_str)
        except Exception:
            data = {"raw": raw_str}
        if a.module_name == "PORT_SCAN":
            port_rows.append({
                "Alert ID": a.alert_id, "Timestamp": a.timestamp, "Attacker IP": a.source_ip,
                "Number of Ports Attacked": data.get("ports_attacked_count", "N/A"),
                "Exact Ports Attacked": str(data.get("ports_attacked_list", raw_str)),
                "Services Probed": data.get("services_probed", "TCP Ports")
            })
        elif a.module_name == "DOS_FLOOD":
            dos_rows.append({
                "Alert ID": a.alert_id, "Timestamp": a.timestamp, "Attacker IP": a.source_ip,
                "Packets Per Second (PPS)": data.get("packets_per_second", "350"),
                "Protocol Type": data.get("protocol_vector", "SYN Flood"),
                "Estimated Bandwidth (Mbps)": data.get("estimated_bandwidth_mbps", "N/A")
            })
        elif a.module_name == "ARP_SPOOFING":
            arp_rows.append({
                "Alert ID": a.alert_id, "Timestamp": a.timestamp,
                "Connected IP Address": data.get("target_ip_address", "192.168.1.1"),
                "Trusted Legit MAC": data.get("trusted_legit_mac", "00:11:22:33:44:55"),
                "Attacker Spoofed MAC": data.get("attacker_spoofed_mac", raw_str),
                "ARP Connection Type": data.get("arp_packet_type", "op=2 Reply")
            })
        elif a.module_name == "SQL_INJECTION":
            sqli_rows.append({
                "Alert ID": a.alert_id, "Timestamp": a.timestamp, "Attacker IP": a.source_ip,
                "Exact SQL Command Used": data.get("attacker_command_used", raw_str),
                "Matched Signatures": str(data.get("matched_sqli_signatures", "")),
                "Classification": data.get("sqli_attack_classification", "SQLi")
            })

    st.markdown("**1️⃣ Port Scanning True Telemetry (Number of Ports & Exact Ports Attacked)**")
    st.dataframe(pd.DataFrame(port_rows) if port_rows else pd.DataFrame([{"Info": "Trigger Port Scan to see live port numbers."}]), use_container_width=True, hide_index=True)

    st.markdown("**2️⃣ High-Volume DoS True Telemetry (Packets Per Second Used)**")
    st.dataframe(pd.DataFrame(dos_rows) if dos_rows else pd.DataFrame([{"Info": "Trigger DoS Flood to see live PPS counts."}]), use_container_width=True, hide_index=True)

    st.markdown("**3️⃣ ARP Spoofing True Telemetry (IP Address -> MAC Binding & Type)**")
    st.dataframe(pd.DataFrame(arp_rows) if arp_rows else pd.DataFrame([{"Info": "Trigger ARP Spoofing to see IP-to-MAC table."}]), use_container_width=True, hide_index=True)

    st.markdown("**4️⃣ SQL Injection True Telemetry (Exact Commands Used by Attacker)**")
    st.dataframe(pd.DataFrame(sqli_rows) if sqli_rows else pd.DataFrame([{"Info": "Trigger SQLi to see intercepted attacker SQL commands."}]), use_container_width=True, hide_index=True)

# ------------------------------------------------------------------------------
# TAB 3: LIVE RECORD OF ATTACKER (AUTO-RELOAD)
# ------------------------------------------------------------------------------
with tab_live:
    st.subheader("📡 Live Attacker Intelligence & Real-Time Reload Feed")
    auto_reload = st.checkbox("🔄 Enable Live Auto-Reload (Refreshes Every 3 Seconds)", value=False)
    if st.button("🔄 Reload Attacker Feed Now"):
        st.rerun()

    df_attackers = run_sql_df("""
        SELECT 
            a.alert_id AS [Record ID],
            a.timestamp AS [Attack Timestamp],
            a.source_ip AS [Attacker IP],
            COALESCE(t.threat_actor, 'Unknown / Unlisted Actor') AS [Identified Threat Actor],
            a.module_name AS [Detection Module],
            a.threat_type AS [Attack Summary],
            a.severity AS [Severity],
            (a.base_risk_score + a.ioc_bonus_score) AS [Total Risk Impact],
            a.raw_payload AS [True Telemetry JSON]
        FROM security_alerts a
        LEFT JOIN threat_indicators t ON a.ioc_id = t.ioc_id
        ORDER BY a.alert_id DESC
    """)
    st.dataframe(df_attackers, use_container_width=True, hide_index=True)

    if auto_reload:
        time.sleep(3)
        st.rerun()

# ------------------------------------------------------------------------------
# TAB 4: CAMERA THREAT & KEYSTROKE BIOMETRICS
# ------------------------------------------------------------------------------
with tab2:
    col_ks, col_cam = st.columns(2)
    with col_ks:
        st.subheader("⌨️ Keystroke Behavioral Biometrics")
        rhythm_choice = st.radio("Select Typing Cadence Profile:", [
            "Authorized Owner Rhythm (Dwell ~85ms, Flight ~120ms)",
            "Intruder / Hesitant Rhythm (Dwell ~195ms, Flight ~310ms -> Triggers Anomaly)"
        ])
        if st.button("🔍 Verify Keystroke Biometrics"):
            if "Intruder" in rhythm_choice:
                k_res = analyze_keystroke_biometrics([190, 200, 195], [305, 315, 310])
                record_and_correlate_alert(TelemetryEvent(
                    source_ip="185.220.101.45", module_name="KEYSTROKE_BIOMETRICS",
                    threat_type=k_res["threat_type"], severity="MEDIUM",
                    base_risk_score=35.0, confidence_score=0.95, raw_payload=k_res["raw_payload"]
                ), db)
                st.error(f"🚨 Keystroke Anomaly Triggered! Z-Score: {k_res['z_score']}")
            else:
                k_res = analyze_keystroke_biometrics([84, 86, 85], [118, 122, 120])
                st.success(f"✅ Biometric Rhythm Matched! Z-Score: {k_res['z_score']}")
            st.json(k_res["telemetry"])

    with col_cam:
        st.subheader("📸 Live Camera Threat & Multi-Person Detector")
        st.caption("Analyzes: Single Operator (Safe) vs. Multiple Persons (Shoulder-Surfing) vs. Covered Lens vs. Absent User.")
        live_cam = st.camera_input("Capture Frame for Live Threat Analysis")
        if live_cam is not None:
            c_res = verify_webcam_face_bytes(live_cam.getvalue())
            for note in c_res["notifications"]:
                if "THREAT" in note or "ALERT" in note:
                    st.error(note)
                else:
                    st.success(note)
            st.json(c_res["telemetry"])
            if c_res["triggered"]:
                record_and_correlate_alert(TelemetryEvent(
                    source_ip=current_session.source_ip, module_name="FACE_VERIFICATION",
                    threat_type=c_res["threat_type"], severity="HIGH",
                    base_risk_score=c_res["base_risk_score"], confidence_score=0.95,
                    raw_payload=c_res["raw_payload"]
                ), db)

# ------------------------------------------------------------------------------
# TAB 5: PURE FFT AI VOICE REC (RANDOM SPEECH) & 1-CLICK MALWARE GENERATOR
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# TAB 5: PURE FFT AI VOICE REC (RANDOM SPEECH) & 1-CLICK BINARY .EXE GENERATOR
# ------------------------------------------------------------------------------
with tab3:
    st.markdown("### 🛠️ Step 1: 1-Click Safe Binary Malware & Audio Generator")
    if st.button("✨ Click Here to Auto-Create Binary .EXE Malware & Speech Audio Files in Project Folder", use_container_width=True):
        # 1. Create a REAL Binary PE Executable (.exe) with MZ headers & raw machine bytes (Not plain text!)
        mal_path = os.path.join(ROOT_DIR, "ransomware_dropper_sim.exe")
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00"
        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$"
        pe_sections = b"PE\x00\x00\x4c\x01\x03\x00.text\x00\x00\x00.data\x00\x00\x00"
        compiled_payload = b"\x55\x89\xe5\x83\xec\x18\xc7\x04\x24\x90\x90\xcc\xeb\xfe\xde\xad\xbe\xef" * 120
        
        mal_bytes = pe_header + b"\x00" * 40 + dos_stub + b"\x00" * 64 + pe_sections + compiled_payload
        
        with open(mal_path, "wb") as f:
            f.write(mal_bytes)
            
        mal_sha = compute_file_sha256(mal_bytes)
        
        # Register the binary's SHA-256 hash in the database (without confidence_level error!)
        if not db.query(ThreatIndicator).filter_by(indicator_value=mal_sha).first():
            db.add(ThreatIndicator(
                indicator_type="SHA256",
                indicator_value=mal_sha,
                threat_actor="Ransomware.LockBit.BinaryDropper",
                reputation_score=99
            ))
            db.commit()

        # 2. Create AI Robotic Speech WAV (Simulating AI voice clone)
        ai_wav_path = os.path.join(ROOT_DIR, "ai_clone_random_speech.wav")
        sr = 16000
        with wave.open(ai_wav_path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
            for i in range(sr * 3):
                t = i / sr
                env = 0.6 + 0.4 * math.sin(2 * math.pi * 4.0 * t)
                sig = env * (0.5 * math.sin(2 * math.pi * 175 * t) + 0.3 * math.sin(2 * math.pi * 350 * t) + 0.2 * math.sin(2 * math.pi * 700 * t))
                wf.writeframesraw(struct.pack("<h", int(sig * 16000)))

        # 3. Create Natural Human Speech WAV (Simulating real human voice with pitch jitter)
        hum_wav_path = os.path.join(ROOT_DIR, "human_natural_random_speech.wav")
        np.random.seed(42)
        with wave.open(hum_wav_path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
            phase = 0.0
            for i in range(sr * 3):
                t = i / sr
                syllable_gate = 1.0 if math.sin(2 * math.pi * 2.5 * t) > -0.2 else 0.05
                f0 = 140.0 + 45.0 * math.sin(2 * math.pi * 1.8 * t) + np.random.normal(0, 12.0)
                phase += 2 * math.pi * f0 / sr
                sig = syllable_gate * (0.6 * math.sin(phase) + 0.25 * np.random.normal(0, 0.5))
                wf.writeframesraw(struct.pack("<h", int(max(-1.0, min(1.0, sig)) * 16000)))

        st.success(f"✅ Created Binary & Audio files inside `{ROOT_DIR}`:\n"
                   f"1. `ransomware_dropper_sim.exe` (Compiled PE Binary — SHA-256: `{mal_sha}`)\n"
                   f"2. `ai_clone_random_speech.wav` (Triggers FFT AI Deepfake Alert)\n"
                   f"3. `human_natural_random_speech.wav` (Passes as Natural Human Voice)")

    st.markdown("---")
    col_v, col_m = st.columns(2)

    with col_v:
        st.subheader("🎙️ Pure FFT AI Voice Deepfake Detector (No Keywords!)")
        st.caption("Uses Fast Fourier Transform (`np.fft.rfft`) to measure Spectral Flatness, Centroid Frequency, and Pitch Jitter Variance on any random spoken audio.")
        audio_up = st.file_uploader("Upload Any Spoken Audio (.wav)", type=["wav"])

        if audio_up is not None:
            a_bytes = audio_up.getvalue()
            st.audio(a_bytes)
            v_res = analyze_ai_voice_fft(a_bytes, audio_up.name)
            st.json(v_res["telemetry"])

            if v_res["triggered"]:
                record_and_correlate_alert(TelemetryEvent(
                    source_ip="185.220.101.45", module_name="AI_VOICE_FFT",
                    threat_type=v_res["threat_type"], severity="CRITICAL",
                    base_risk_score=55.0, confidence_score=v_res["confidence_score"],
                    raw_payload=v_res["raw_payload"]
                ), db)
                st.error(f"🚨 {v_res['threat_type']} — Verdict: `{v_res['telemetry']['verdict']}`")
            else:
                st.success(f"✅ Authentic Human Voice Verified! Verdict: `{v_res['telemetry']['verdict']}`")

    with col_m:
        st.subheader("🦠 SHA-256 Malware File Scanner")
        st.caption("Select `demo_malware_payload.txt` from your project folder (created by the button above) or any empty `.txt` file!")
        mal_up = st.file_uploader("Upload File for SHA-256 Inspection", type=None)
        if mal_up is not None:
            f_bytes = mal_up.getvalue()
            sha_val = compute_file_sha256(f_bytes)
            st.code(f"File: {mal_up.name}\nSHA-256: {sha_val}")
            matched = db.query(ThreatIndicator).filter_by(indicator_value=sha_val).first()
            if matched:
                q_path = os.path.join(ROOT_DIR, "quarantine", f"QUARANTINED_{mal_up.name}")
                with open(q_path, "wb") as f:
                    f.write(f_bytes)
                record_and_correlate_alert(TelemetryEvent(
                    source_ip=current_session.source_ip, indicator_value=sha_val,
                    module_name="MALWARE_HASH", threat_type=f"Malware SHA-256 Match ({matched.threat_actor})",
                    severity="CRITICAL", base_risk_score=60.0, confidence_score=1.0,
                    raw_payload=json.dumps({"filename": mal_up.name, "sha256": sha_val, "threat_actor": matched.threat_actor, "quarantine_path": q_path})
                ), db)
                st.error(f"🚨 MALWARE DETECTED: `{matched.threat_actor}`! Quarantined to `{q_path}`.")
            else:
                st.success("✅ SHA-256 Hash Clean.")

# ------------------------------------------------------------------------------
# TAB 6: DBMS LIVE SQL EXPLORER
# ------------------------------------------------------------------------------
with tab4:
    st.subheader("🗄️ Database Management System (DBMS) Live Explorer")
    c_v1, c_v2 = st.columns(2)
    with c_v1:
        st.markdown("**SQL View: `vw_high_risk_users`**")
        st.dataframe(run_sql_df("SELECT * FROM vw_high_risk_users"), use_container_width=True, hide_index=True)
    with c_v2:
        st.markdown("**SQL View: `vw_threat_module_summary`**")
        st.dataframe(run_sql_df("SELECT * FROM vw_threat_module_summary"), use_container_width=True, hide_index=True)

    st.markdown("**Automated SOAR Audit Trail (`incident_response_audit`)**")
    st.dataframe(run_sql_df("SELECT * FROM incident_response_audit ORDER BY action_id DESC"), use_container_width=True, hide_index=True)

db.close()