# sensors/all_detectors.py
import re
import math
import time
import hashlib
import cv2
import numpy as np
from collections import defaultdict
from core_backend.database.models import redis_cache

# --- MODULE 1, 2, 3: NETWORK INTRUSION SENSORS ---
PORT_SCAN_TRACKER = defaultdict(list)  
TRUSTED_ARP_TABLE = {
    "192.168.1.1": "00:11:22:33:44:55",
    "10.0.0.1": "aa:bb:cc:dd:ee:ff"
}

def detect_port_scan(source_ip: str, dst_port: int) -> dict:
    now = time.time()
    PORT_SCAN_TRACKER[source_ip] = [
        (t, p) for (t, p) in PORT_SCAN_TRACKER[source_ip] if now - t <= 5.0
    ]
    PORT_SCAN_TRACKER[source_ip].append((now, dst_port))
    unique_ports = len(set(p for _, p in PORT_SCAN_TRACKER[source_ip]))

    if unique_ports > 15:
        return {
            "triggered": True,
            "module_name": "PORT_SCAN",
            "threat_type": f"Port Scan Detected ({unique_ports} ports in 5s)",
            "severity": "MEDIUM",
            "base_risk_score": 30.0,
            "confidence_score": 0.95,
            "raw_payload": f"Source {source_ip} probed {unique_ports} distinct TCP SYN ports within 5s window."
        }
    return {"triggered": False, "unique_ports_5s": unique_ports}

def detect_dos_flood(source_ip: str, packet_burst_count: int = 1) -> dict:
    key = f"pps:{source_ip}"
    current_pps = 0
    for _ in range(packet_burst_count):
        current_pps = redis_cache.incr_with_ttl(key, ttl_seconds=1)

    if current_pps > 200:
        return {
            "triggered": True,
            "module_name": "DOS_FLOOD",
            "threat_type": "High-Volume DoS / SYN Flood",
            "severity": "CRITICAL",
            "base_risk_score": 50.0,
            "confidence_score": 0.98,
            "raw_payload": f"Traffic spike: {current_pps} packets/sec from {source_ip} (Threshold: 200 PPS)"
        }
    return {"triggered": False, "current_pps": current_pps}

def detect_arp_spoofing(claimed_ip: str, sender_mac: str) -> dict:
    sender_mac_clean = sender_mac.lower().strip()
    if claimed_ip in TRUSTED_ARP_TABLE:
        trusted_mac = TRUSTED_ARP_TABLE[claimed_ip].lower()
        if sender_mac_clean != trusted_mac:
            return {
                "triggered": True,
                "module_name": "ARP_SPOOFING",
                "threat_type": "ARP Cache Poisoning / MITM Detected",
                "severity": "CRITICAL",
                "base_risk_score": 55.0,
                "confidence_score": 1.0,
                "raw_payload": f"Gateway IP {claimed_ip} claimed by unauthorized MAC [{sender_mac_clean}]"
            }
    return {"triggered": False}

# --- MODULE 4 & 5: APPLICATION SECURITY (BRUTE FORCE & SQLi) ---
SQLI_REGEX = re.compile(
    r"(?i)(\bUNION\b.*\bSELECT\b|\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|--|;\s*DROP\s+TABLE|\bSLEEP\s*\(|\bBENCHMARK\s*\()"
)

def detect_sqli(payload_text: str) -> dict:
    match = SQLI_REGEX.search(payload_text)
    if match:
        return {
            "triggered": True,
            "module_name": "SQL_INJECTION",
            "threat_type": "SQL Injection (SQLi) Payload Blocked",
            "severity": "HIGH",
            "base_risk_score": 45.0,
            "confidence_score": 0.96,
            "raw_payload": f"Matched SQLi signature [{match.group(0)}] in input: {payload_text[:100]}"
        }
    return {"triggered": False}

def track_brute_force(source_ip: str, username: str) -> dict:
    key = f"bf:{source_ip}:{username}"
    attempts = redis_cache.incr_with_ttl(key, ttl_seconds=60)
    if attempts >= 5:
        return {
            "triggered": True,
            "module_name": "BRUTE_FORCE",
            "threat_type": "Credential Stuffing / Brute Force Attack",
            "severity": "MEDIUM",
            "base_risk_score": 25.0,
            "confidence_score": 0.90,
            "raw_payload": f"{attempts} failed login attempts for user '{username}' from {source_ip} in 60s."
        }
    return {"triggered": False, "attempts": attempts}

# --- MODULE 6, 7, 8: IDENTITY, KEYSTROKE BIOMETRICS & OPENCV FACE ---
def calculate_haversine_velocity(lat1: float, lon1: float, lat2: float, lon2: float, elapsed_hours: float) -> dict:
    R = 6371.0  
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    distance_km = round(R * c, 2)
    safe_hours = max(elapsed_hours, 0.05)  
    velocity_kmh = round(distance_km / safe_hours, 2)

    if velocity_kmh > 800.0 and distance_km > 100.0:
        return {
            "triggered": True,
            "distance_km": distance_km,
            "velocity_kmh": velocity_kmh,
            "module_name": "IMPOSSIBLE_TRAVEL",
            "threat_type": "Impossible Travel / Geo-Velocity Anomaly",
            "severity": "HIGH",
            "base_risk_score": 40.0,
            "confidence_score": 0.94,
            "raw_payload": f"Login jump of {distance_km} km (Required speed: {velocity_kmh} km/h > 800 km/h limit)"
        }
    return {"triggered": False, "distance_km": distance_km, "velocity_kmh": velocity_kmh}

def analyze_keystroke_biometrics(
    dwell_list: list[float], flight_list: list[float],
    base_dwell: float = 85.0, std_dwell: float = 15.0,
    base_flight: float = 120.0, std_flight: float = 25.0
) -> dict:
    if not dwell_list or not flight_list:
        return {"triggered": False, "z_score": 0.0}

    mean_d = sum(dwell_list) / len(dwell_list)
    mean_f = sum(flight_list) / len(flight_list)

    z_dwell = abs(mean_d - base_dwell) / max(std_dwell, 1.0)
    z_flight = abs(mean_f - base_flight) / max(std_flight, 1.0)
    max_z = round(max(z_dwell, z_flight), 2)

    if max_z > 2.5:
        return {
            "triggered": True,
            "z_score": max_z,
            "module_name": "KEYSTROKE_BIOMETRICS",
            "threat_type": "Behavioral Keystroke Rhythm Anomaly",
            "severity": "MEDIUM",
            "base_risk_score": 35.0,
            "confidence_score": min(round(max_z / 4.0, 2), 0.99),
            "raw_payload": f"Typing rhythm anomaly! Max Z-Score={max_z}"
        }
    return {"triggered": False, "z_score": max_z}

def verify_webcam_face_bytes(image_bytes: bytes) -> dict:
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return {
            "triggered": True,
            "faces_detected": 0,
            "module_name": "FACE_VERIFICATION",
            "threat_type": "Invalid / Corrupted Camera Frame",
            "severity": "HIGH",
            "base_risk_score": 45.0,
            "confidence_score": 0.90,
            "raw_payload": "Failed to decode webcam image frame during biometric check."
        }

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    face_cascade = cv2.CascadeClassifier(cascade_path)
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))

    if len(faces) == 0:
        return {
            "triggered": True,
            "faces_detected": 0,
            "module_name": "FACE_VERIFICATION",
            "threat_type": "Face Verification Failed (No Live Face Present)",
            "severity": "HIGH",
            "base_risk_score": 45.0,
            "confidence_score": 0.92,
            "raw_payload": "OpenCV Haar Cascade detected 0 faces in login frame."
        }
    return {"triggered": False, "faces_detected": int(len(faces))}

# --- MODULE 9: ENDPOINT SHA-256 FILE HASH CHECK ---
def compute_file_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

# --- MODULE 10a: AI VISHING URGENCY & SCAM ANALYZER ---
VISHING_URGENCY_PATTERNS = [
    "share otp", "share your otp", "one time password", "account suspended",
    "immediate wire transfer", "urgent bank verification", "install anydesk",
    "remote access", "cvv number", "kyc blocked", "police complaint"
]

def analyze_vishing_transcript(transcript_text: str) -> dict:
    lower_text = transcript_text.lower()
    matched_phrases = [p for p in VISHING_URGENCY_PATTERNS if p in lower_text]

    if len(matched_phrases) >= 2:
        return {
            "triggered": True,
            "matched_keywords": matched_phrases,
            "module_name": "VISHING_DETECTION",
            "threat_type": "AI Vishing (Voice Phishing) Social Engineering",
            "severity": "HIGH",
            "base_risk_score": 45.0,
            "confidence_score": min(0.75 + 0.08 * len(matched_phrases), 0.99),
            "raw_payload": f"Detected {len(matched_phrases)} high-urgency scam cues {matched_phrases}"
        }
    return {"triggered": False, "matched_keywords": matched_phrases}