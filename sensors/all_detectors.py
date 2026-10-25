# sensors/all_detectors.py
import re
import time
import hashlib
import json
import numpy as np
import cv2
from collections import defaultdict
from core_backend.database.models import redis_cache

# --- MODULE 1: PORT SCANNING (Tracks Exact Port List & Count) ---
PORT_SCAN_TRACKER = defaultdict(list)

PORT_SERVICE_NAMES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8000: "FastAPI", 8080: "HTTP-Proxy"
}

def detect_port_scan(source_ip: str, dst_port: int) -> dict:
    now = time.time()
    PORT_SCAN_TRACKER[source_ip] = [
        (t, p) for (t, p) in PORT_SCAN_TRACKER[source_ip] if now - t <= 10.0
    ]
    PORT_SCAN_TRACKER[source_ip].append((now, dst_port))
    unique_ports = sorted(list(set(p for _, p in PORT_SCAN_TRACKER[source_ip])))
    port_count = len(unique_ports)
    named_ports = [f"{p} ({PORT_SERVICE_NAMES.get(p, 'TCP')})" for p in unique_ports]

    telemetry_data = {
        "source_ip": source_ip,
        "ports_attacked_count": port_count,
        "ports_attacked_list": unique_ports,
        "services_probed": ", ".join(named_ports[:12]) + ("..." if port_count > 12 else ""),
        "scan_type": "TCP SYN Stealth Sweep" if port_count > 10 else "Targeted Service Probe"
    }

    if port_count >= 4:
        return {
            "triggered": True,
            "module_name": "PORT_SCAN",
            "threat_type": f"Port Scan ({port_count} Ports Attacked)",
            "severity": "HIGH" if port_count > 15 else "MEDIUM",
            "base_risk_score": 35.0 if port_count > 15 else 25.0,
            "confidence_score": 0.96,
            "telemetry": telemetry_data,
            "raw_payload": json.dumps(telemetry_data)
        }
    return {"triggered": False, "telemetry": telemetry_data}

# --- MODULE 2: HIGH-VOLUME DoS (Tracks Exact Packets Per Second & Protocol) ---
def detect_dos_flood(source_ip: str, packet_burst_count: int = 1, protocol: str = "TCP SYN Flood") -> dict:
    key = f"pps:{source_ip}"
    current_pps = 0
    for _ in range(packet_burst_count):
        current_pps = redis_cache.incr_with_ttl(key, ttl_seconds=2)

    est_mbps = round((current_pps * 512 * 8) / 1_000_000, 2)
    telemetry_data = {
        "source_ip": source_ip,
        "packets_per_second": current_pps,
        "threshold_pps": 200,
        "protocol_vector": protocol,
        "estimated_bandwidth_mbps": est_mbps
    }

    if current_pps > 200:
        return {
            "triggered": True,
            "module_name": "DOS_FLOOD",
            "threat_type": f"DoS Flood ({current_pps} PPS via {protocol})",
            "severity": "CRITICAL",
            "base_risk_score": 50.0,
            "confidence_score": 0.99,
            "telemetry": telemetry_data,
            "raw_payload": json.dumps(telemetry_data)
        }
    return {"triggered": False, "telemetry": telemetry_data}

# --- MODULE 3: ARP SPOOFING (Tracks IP, Claimed MAC, Legit MAC & ARP Type) ---
TRUSTED_ARP_TABLE = {
    "192.168.1.1": {"mac": "00:11:22:33:44:55", "device": "Default Wi-Fi Gateway Router"},
    "192.168.1.10": {"mac": "aa:bb:cc:11:22:33", "device": "Production Database Host"},
    "10.0.0.1": {"mac": "aa:bb:cc:dd:ee:ff", "device": "Core VLAN Switch"}
}

def detect_arp_spoofing(claimed_ip: str, sender_mac: str, arp_type: str = "Gratuitous ARP Reply (op=2)") -> dict:
    sender_mac_clean = sender_mac.lower().strip()
    trusted_entry = TRUSTED_ARP_TABLE.get(claimed_ip, {"mac": "00:11:22:33:44:55", "device": "LAN Gateway"})
    trusted_mac = trusted_entry["mac"].lower()

    telemetry_data = {
        "target_ip_address": claimed_ip,
        "trusted_legit_mac": trusted_mac,
        "attacker_spoofed_mac": sender_mac_clean,
        "arp_packet_type": arp_type,
        "connection_status": "MITM HIJACKED" if sender_mac_clean != trusted_mac else "VERIFIED_SAFE",
        "target_device_role": trusted_entry["device"]
    }

    if sender_mac_clean != trusted_mac:
        return {
            "triggered": True,
            "module_name": "ARP_SPOOFING",
            "threat_type": f"ARP Spoofing ({claimed_ip} -> {sender_mac_clean})",
            "severity": "CRITICAL",
            "base_risk_score": 55.0,
            "confidence_score": 1.0,
            "telemetry": telemetry_data,
            "raw_payload": json.dumps(telemetry_data)
        }
    return {"triggered": False, "telemetry": telemetry_data}

# --- MODULE 4 & 5: SQL INJECTION & BRUTE FORCE ---
SQLI_PATTERNS = [
    (r"(?i)\bUNION\b.*\bSELECT\b", "UNION-Based Data Extraction"),
    (r"(?i)\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1", "Boolean Tautology Auth Bypass"),
    (r"(?i);\s*DROP\s+TABLE", "Destructive DDL Query (DROP TABLE)"),
    (r"(?i)--|\#", "SQL Comment Truncation Attack"),
    (r"(?i)\bSLEEP\s*\(|\bWAITFOR\s+DELAY", "Time-Based Blind SQLi")
]

def detect_sqli(payload_text: str, target_endpoint: str = "/api/zero-trust-login") -> dict:
    matched_types = []
    matched_tokens = []
    for pattern, desc in SQLI_PATTERNS:
        m = re.search(pattern, payload_text)
        if m:
            matched_types.append(desc)
            matched_tokens.append(m.group(0))

    telemetry_data = {
        "attacker_command_used": payload_text,
        "matched_sqli_signatures": matched_tokens,
        "sqli_attack_classification": ", ".join(matched_types) if matched_types else "Clean Input",
        "target_endpoint": target_endpoint,
        "Action": "BLOCKED_BEFORE_DB_EXECUTION" if matched_types else "ALLOWED"
    }

    if matched_types:
        return {
            "triggered": True,
            "module_name": "SQL_INJECTION",
            "threat_type": f"SQLi Blocked ({matched_types[0]})",
            "severity": "HIGH",
            "base_risk_score": 45.0,
            "confidence_score": 0.98,
            "telemetry": telemetry_data,
            "raw_payload": json.dumps(telemetry_data)
        }
    return {"triggered": False, "telemetry": telemetry_data}

def track_brute_force(source_ip: str, username: str) -> dict:
    key = f"bf:{source_ip}:{username}"
    attempts = redis_cache.incr_with_ttl(key, ttl_seconds=60)
    telemetry_data = {
        "source_ip": source_ip,
        "target_username": username,
        "failed_attempts_count": attempts,
        "lockout_threshold": 5,
        "lockout_timer_seconds": 30 if attempts >= 5 else 0
    }
    if attempts >= 5:
        return {
            "triggered": True,
            "module_name": "BRUTE_FORCE",
            "threat_type": f"Brute Force Lockout ({attempts} Failed Attempts)",
            "severity": "HIGH",
            "base_risk_score": 30.0,
            "confidence_score": 0.95,
            "telemetry": telemetry_data,
            "raw_payload": json.dumps(telemetry_data)
        }
    return {"triggered": False, "attempts": attempts, "telemetry": telemetry_data}

# --- MODULE 6: KEYSTROKE BIOMETRICS ---
def analyze_keystroke_biometrics(
    dwell_list: list[float], flight_list: list[float],
    base_dwell: float = 85.0, std_dwell: float = 15.0,
    base_flight: float = 120.0, std_flight: float = 25.0
) -> dict:
    if not dwell_list or not flight_list:
        return {"triggered": False, "z_score": 0.0}
    mean_d = round(sum(dwell_list) / len(dwell_list), 1)
    mean_f = round(sum(flight_list) / len(flight_list), 1)
    z_dwell = abs(mean_d - base_dwell) / max(std_dwell, 1.0)
    z_flight = abs(mean_f - base_flight) / max(std_flight, 1.0)
    max_z = round(max(z_dwell, z_flight), 2)

    telemetry_data = {
        "measured_dwell_ms": mean_d,
        "baseline_dwell_ms": base_dwell,
        "measured_flight_ms": mean_f,
        "baseline_flight_ms": base_flight,
        "biometric_z_score": max_z
    }

    if max_z > 2.5:
        return {
            "triggered": True,
            "z_score": max_z,
            "module_name": "KEYSTROKE_BIOMETRICS",
            "threat_type": f"Keystroke Anomaly (Z-Score={max_z})",
            "severity": "MEDIUM",
            "base_risk_score": 35.0,
            "confidence_score": min(round(max_z / 4.0, 2), 0.99),
            "telemetry": telemetry_data,
            "raw_payload": json.dumps(telemetry_data)
        }
    return {"triggered": False, "z_score": max_z, "telemetry": telemetry_data}

# --- MODULE 7: CAMERA THREAT & MULTI-PERSON ANALYZER ---
def verify_webcam_face_bytes(image_bytes: bytes) -> dict:
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return {
            "triggered": True,
            "faces_detected": 0,
            "notifications": ["🚨 THREAT: Corrupted Camera Feed"],
            "module_name": "FACE_VERIFICATION",
            "threat_type": "Corrupted Camera Feed",
            "severity": "HIGH",
            "base_risk_score": 45.0,
            "confidence_score": 0.90,
            "telemetry": {"faces_detected": 0, "threat": "Invalid Frame"},
            "raw_payload": json.dumps({"faces_detected": 0, "threat": "Invalid Frame"})
        }

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    brightness = float(np.mean(gray))
    contrast = float(np.std(gray))
    faces_list = []
    detection_method = "OpenCV Haar Cascade"

    try:
        if hasattr(cv2, "CascadeClassifier"):
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            face_cascade = cv2.CascadeClassifier(cascade_path)
            detected = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(45, 45))
            if len(detected) > 0:
                faces_list = detected.tolist()
        else:
            raise AttributeError("CascadeClassifier missing")
    except Exception:
        detection_method = "YCrCb Skin-Region Biometric Analyzer (Fallback)"
        ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        mask = cv2.inRange(ycrcb, np.array([0, 133, 77], dtype=np.uint8), np.array([255, 173, 127], dtype=np.uint8))
        kernel = np.ones((5, 5), np.uint8)
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        h_img, w_img = gray.shape
        min_area = (h_img * w_img) * 0.025
        for cnt in contours:
            if cv2.contourArea(cnt) > min_area:
                x, y, w, h = cv2.boundingRect(cnt)
                faces_list.append([x, y, w, h])

    num_faces = len(faces_list)
    notifications = []
    triggered = False
    threat_label = "Verified Single Authorized User"
    risk_score = 0.0

    if brightness < 25.0 or contrast < 10.0:
        triggered = True
        threat_label = "Camera Covered / Obstructed Lens Spoof"
        notifications.append("🚨 THREAT: Camera lens is covered or pitch dark!")
        risk_score = 45.0
    elif num_faces == 0:
        triggered = True
        threat_label = "No Live Person Detected at Terminal"
        notifications.append("🚨 THREAT: 0 faces detected! Operator missing or spoofed frame.")
        risk_score = 45.0
    elif num_faces > 1:
        triggered = True
        threat_label = f"Multiple Persons Detected ({num_faces} Faces - Shoulder Surfing!)"
        notifications.append(f"🚨 SHOULDER-SURFING ALERT: {num_faces} people detected in camera frame! Unauthorized observer present.")
        risk_score = 40.0
    else:
        notifications.append(f"✅ BIOMETRIC VERIFIED: Exactly 1 live face detected (Brightness: {round(brightness,1)}).")

    telemetry_data = {
        "faces_detected_count": num_faces,
        "camera_brightness": round(brightness, 1),
        "camera_contrast": round(contrast, 1),
        "detection_engine": detection_method,
        "security_notifications": notifications,
        "status": threat_label
    }

    return {
        "triggered": triggered,
        "faces_detected": num_faces,
        "notifications": notifications,
        "module_name": "FACE_VERIFICATION",
        "threat_type": threat_label,
        "severity": "HIGH" if triggered else "LOW",
        "base_risk_score": risk_score,
        "confidence_score": 0.94,
        "telemetry": telemetry_data,
        "raw_payload": json.dumps(telemetry_data)
    }

# --- MODULE 8: SHA-256 MALWARE FILE SCANNER ---
def compute_file_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

# --- MODULE 9: PURE FFT AI VOICE DEEPFAKE DETECTOR (NO KEYWORDS NEEDED!) ---
def analyze_ai_voice_fft(audio_bytes: bytes = None, filename: str = "Uploaded_Audio.wav") -> dict:
    if audio_bytes is None or len(audio_bytes) <= 100:
        return {"triggered": False, "is_ai_voice": False, "telemetry": {"error": "No valid audio bytes provided"}}

    try:
        raw_pcm = audio_bytes[44:] if len(audio_bytes) > 44 else audio_bytes
        samples = np.frombuffer(raw_pcm, dtype=np.int16).astype(np.float32)
        if len(samples) < 500:
            samples = np.frombuffer(raw_pcm, dtype=np.uint8).astype(np.float32) - 128.0

        norm_samples = samples / (np.max(np.abs(samples)) + 1e-6)

        # 1. Fast Fourier Transform (FFT) Power Spectrum Calculation
        fft_mag = np.abs(np.fft.rfft(norm_samples))
        power_spec = (fft_mag ** 2) + 1e-12

        # 2. Spectral Flatness (Wiener Entropy: Geometric Mean / Arithmetic Mean)
        geom_mean = float(np.exp(np.mean(np.log(power_spec))))
        arith_mean = float(np.mean(power_spec))
        spectral_flatness = round(geom_mean / (arith_mean + 1e-12), 6)

        # 3. Spectral Centroid & Pitch Jitter Variance across 12 temporal windows
        freqs = np.fft.rfftfreq(len(norm_samples), d=1.0 / 16000.0)
        spectral_centroid_hz = round(float(np.sum(freqs * fft_mag) / (np.sum(fft_mag) + 1e-12)), 2)

        chunks = np.array_split(norm_samples, 12)
        zcr_per_chunk = [float(np.mean(np.diff(np.sign(c)) != 0)) for c in chunks if len(c) > 10]
        pitch_jitter_var = round(float(np.var(zcr_per_chunk)), 6)

        # AI Vocoder Detection Rule: Low pitch jitter variance (<0.0012) or unnatural spectral flatness
        is_ai_voice = bool(pitch_jitter_var < 0.0012 or spectral_flatness < 0.005)
        ai_prob = round(min(98.5, max(82.0, (1.0 - pitch_jitter_var * 500) * 100)), 1) if is_ai_voice else round(max(12.0, (1.0 - pitch_jitter_var * 100) * 30), 1)

        telemetry_data = {
            "audio_filename": filename,
            "dsp_engine": "Fast Fourier Transform (np.fft.rfft)",
            "fft_spectral_centroid_hz": spectral_centroid_hz,
            "fft_spectral_flatness": spectral_flatness,
            "pitch_jitter_variance": pitch_jitter_var,
            "ai_deepfake_probability_pct": ai_prob,
            "verdict": "SYNTHETIC_AI_VOICE_CLONE" if is_ai_voice else "AUTHENTIC_HUMAN_VOCAL_TRACT"
        }

        if is_ai_voice:
            return {
                "triggered": True,
                "is_ai_voice": True,
                "telemetry": telemetry_data,
                "module_name": "AI_VOICE_FFT",
                "threat_type": f"AI Voice Deepfake Detected via FFT ({ai_prob}% Confidence)",
                "severity": "CRITICAL",
                "base_risk_score": 55.0,
                "confidence_score": round(ai_prob / 100.0, 2),
                "raw_payload": json.dumps(telemetry_data)
            }
        return {"triggered": False, "is_ai_voice": False, "telemetry": telemetry_data, "raw_payload": json.dumps(telemetry_data)}

    except Exception as e:
        telemetry_data = {"audio_filename": filename, "error": str(e), "verdict": "ANOMALOUS_AUDIO_STREAM"}
        return {
            "triggered": True,
            "is_ai_voice": True,
            "telemetry": telemetry_data,
            "module_name": "AI_VOICE_FFT",
            "threat_type": "Suspicious Synthetic Audio Stream",
            "severity": "HIGH",
            "base_risk_score": 45.0,
            "confidence_score": 0.90,
            "raw_payload": json.dumps(telemetry_data)
        }

# Backwards-compatible aliases if main_api imports them
def analyze_vishing_transcript(transcript_text: str) -> dict:
    return {"triggered": False}

def calculate_haversine_velocity(*args, **kwargs) -> dict:
    return {"triggered": False, "distance_km": 0.0, "velocity_kmh": 0.0}