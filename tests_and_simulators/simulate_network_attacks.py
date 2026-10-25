# tests_and_simulators/simulate_network_attacks.py
import requests
import json
import time
import os

API_URL = "http://127.0.0.1:8000/api/ingest-telemetry"

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=====================================================================")
    print(" 🔴 RED TEAM ADVERSARY EMULATION CONSOLE (MITRE ATT&CK SIMULATOR) 🔴 ")
    print("=====================================================================")
    print(" Target Blue-Team API : http://127.0.0.1:8000/api/ingest-telemetry")
    print(" Target SOC Dashboard : http://localhost:8501")
    print("=====================================================================")

def fire_attack(attack_title, module_name, threat_type, severity, base_risk, source_ip, telemetry_dict, ioc_val=None):
    print(f"\n[⚔️ RED TEAM] Initializing Attack Vector: {attack_title}...")
    time.sleep(0.4)
    print(f"[📡 PACKET TX] Spoofing Source IP: {source_ip}")
    print(f"[📦 PAYLOAD ] Injecting Telemetry: {json.dumps(telemetry_dict, indent=2)}")
    
    event_data = {
        "user_id": 1,
        "session_id": "sess_pune_01",
        "source_ip": source_ip,
        "indicator_value": ioc_val or source_ip,
        "module_name": module_name,
        "threat_type": threat_type,
        "severity": severity,
        "base_risk_score": base_risk,
        "confidence_score": 0.98,
        "raw_payload": json.dumps(telemetry_dict)
    }

    try:
        response = requests.post(API_URL, json=event_data, timeout=5)
        res = response.json()
        print("\n---------------------------------------------------------------------")
        print(" 🛡️  BLUE TEAM SOC RESPONSE INTERCEPTED:")
        print("---------------------------------------------------------------------")
        print(f"  [🚨 Alert ID Logged]       : #{res.get('alert_id')}")
        print(f"  [📈 Cumulative Risk Score] : {res.get('cumulative_session_risk')} / 100")
        print(f"  [🤖 Automated SOAR Action] : {res.get('automated_soar_action')}")
        if res.get("ioc_enriched"):
            print(f"  [🕵️ Threat Intel Hit]      : {res.get('ioc_details')}")
        print("---------------------------------------------------------------------")
    except Exception as e:
        print(f"\n[❌ ERROR] Could not reach Blue Team FastAPI Server on Port 8000!")
        print(f"           Make sure Terminal 1 is running: python -m uvicorn core_backend.main_api:app --reload --port 8000")

def main():
    while True:
        print_banner()
        print(" SELECT RED-TEAM ATTACK VECTOR TO LAUNCH:")
        print(" -------------------------------------------------------------------")
        print("  [1] 🕵️  Reconnaissance : Nmap TCP SYN Stealth Port Sweep (19 Ports)")
        print("  [2] 🌊  Volumetric DoS : Mirai Botnet Flood (450 Packets/Sec)")
        print("  [3] 🔌  LAN MITM       : Gratuitous ARP Cache Poisoning (Gateway Hijack)")
        print("  [4] 🔑  Credential Atk : Hydra SSH/Web Brute-Force (6 Rapid Failures)")
        print("  [5] 💉  Web Exploit    : UNION SELECT SQL Injection Database Dump")
        print("  [6] ⌨️  Behavioral     : Keystroke Dynamics Intruder Rhythm Anomaly")
        print("  [7] 📸  Physical Security: Shoulder-Surfing (Multiple Faces in Frame)")
        print("  [8] 🎙️  AI Deepfake    : Synthetic FFT Vocoder Audio Injection")
        print("  [9] 🦠  Endpoint Drop  : LockBit PE Binary (.EXE) SHA-256 Dropper")
        print("  [10] 💀 FULL KILL-CHAIN: Launch Automated Multi-Stage Cyber Attack!")
        print("  [0] ❌  Exit Red-Team Console")
        print("=====================================================================")

        choice = input("\nroot@kali-redteam:~# ").strip()

        if choice == '1':
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8000, 8080]
            fire_attack(
                "Nmap TCP SYN Stealth Sweep", "PORT_SCAN",
                f"Port Scan ({len(ports)} Ports Attacked)", "HIGH", 35.0, "45.155.205.233",
                {
                    "source_ip": "45.155.205.233",
                    "ports_attacked_count": len(ports),
                    "ports_attacked_list": ports,
                    "services_probed": "21 (FTP), 22 (SSH), 23 (Telnet), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 3389 (RDP)...",
                    "scan_type": "TCP SYN Stealth Sweep"
                }
            )
            input("\nPress ENTER to continue...")

        elif choice == '2':
            fire_attack(
                "Mirai Botnet Volumetric SYN Flood", "DOS_FLOOD",
                "DoS Flood (450 PPS via TCP SYN Flood)", "CRITICAL", 50.0, "198.51.100.77",
                {
                    "source_ip": "198.51.100.77",
                    "packets_per_second": 450,
                    "threshold_pps": 200,
                    "protocol_vector": "TCP SYN / UDP Volumetric Flood",
                    "estimated_bandwidth_mbps": 1.84
                }
            )
            input("\nPress ENTER to continue...")

        elif choice == '3':
            fire_attack(
                "LAN Man-in-the-Middle ARP Poisoning", "ARP_SPOOFING",
                "ARP Spoofing (192.168.1.1 -> de:ad:be:ef:99:99)", "CRITICAL", 55.0, "192.168.1.55",
                {
                    "target_ip_address": "192.168.1.1",
                    "trusted_legit_mac": "00:11:22:33:44:55",
                    "attacker_spoofed_mac": "de:ad:be:ef:99:99",
                    "arp_packet_type": "Gratuitous ARP Reply (op=2)",
                    "connection_status": "MITM HIJACKED",
                    "target_device_role": "Default Wi-Fi Gateway Router"
                }
            )
            input("\nPress ENTER to continue...")

        elif choice == '4':
            fire_attack(
                "Credential Stuffing & Brute-Force Lockout", "BRUTE_FORCE",
                "Brute Force Lockout (6 Failed Attempts)", "HIGH", 30.0, "185.220.101.45",
                {
                    "source_ip": "185.220.101.45",
                    "target_username": "aditya_admin",
                    "failed_attempts_count": 6,
                    "lockout_threshold": 5,
                    "lockout_timer_seconds": 30
                }
            )
            input("\nPress ENTER to continue...")

        elif choice == '5':
            cmd = "admin' OR '1'='1' UNION SELECT username, password_hash FROM users; --"
            fire_attack(
                "SQL Injection Authentication Bypass & Dump", "SQL_INJECTION",
                "SQLi Blocked (UNION-Based Data Extraction)", "HIGH", 45.0, "185.220.101.45",
                {
                    "attacker_command_used": cmd,
                    "matched_sqli_signatures": ["UNION SELECT", "OR '1'='1", "--"],
                    "sqli_attack_classification": "UNION-Based Data Extraction, Boolean Tautology Auth Bypass",
                    "target_endpoint": "/api/zero-trust-login",
                    "Action": "BLOCKED_BEFORE_DB_EXECUTION"
                }
            )
            input("\nPress ENTER to continue...")

        elif choice == '6':
            fire_attack(
                "Keystroke Biometric Imposter Anomaly", "KEYSTROKE_BIOMETRICS",
                "Keystroke Anomaly (Z-Score=7.6)", "MEDIUM", 35.0, "185.220.101.45",
                {
                    "measured_dwell_ms": 195.0,
                    "baseline_dwell_ms": 85.0,
                    "measured_flight_ms": 310.0,
                    "baseline_flight_ms": 120.0,
                    "biometric_z_score": 7.6
                }
            )
            input("\nPress ENTER to continue...")

        elif choice == '7':
            fire_attack(
                "Physical Shoulder-Surfing / Multi-Person Alert", "FACE_VERIFICATION",
                "Multiple Persons Detected (2 Faces - Shoulder Surfing!)", "HIGH", 40.0, "103.21.125.10",
                {
                    "faces_detected_count": 2,
                    "camera_brightness": 118.4,
                    "camera_contrast": 48.2,
                    "detection_engine": "OpenCV Haar Cascade",
                    "security_notifications": ["🚨 SHOULDER-SURFING ALERT: 2 people detected in camera frame!"],
                    "status": "Multiple Persons Detected (2 Faces - Shoulder Surfing!)"
                }
            )
            input("\nPress ENTER to continue...")

        elif choice == '8':
            fire_attack(
                "AI Deepfake Voice Clone (FFT Spectral Anomaly)", "AI_VOICE_FFT",
                "AI Voice Deepfake Detected via FFT (96.2% Confidence)", "CRITICAL", 55.0, "185.220.101.45",
                {
                    "audio_filename": "ai_clone_random_speech.wav",
                    "dsp_engine": "Fast Fourier Transform (np.fft.rfft)",
                    "fft_spectral_centroid_hz": 312.45,
                    "fft_spectral_flatness": 0.00184,
                    "pitch_jitter_variance": 0.00012,
                    "ai_deepfake_probability_pct": 96.2,
                    "verdict": "SYNTHETIC_AI_VOICE_CLONE"
                },
                ioc_val="secure-bank-otp-verify.com"
            )
            input("\nPress ENTER to continue...")

        elif choice == '9':
            # Uses the exact empty/LockBit hash seeded in seed_db.py
            lockbit_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            fire_attack(
                "LockBit Ransomware Binary Dropper", "MALWARE_HASH",
                "Malware SHA-256 Match (Ransomware.LockBit.Dropper)", "CRITICAL", 60.0, "103.21.125.10",
                {
                    "filename": "ransomware_dropper_sim.exe",
                    "sha256": lockbit_sha,
                    "threat_actor": "Ransomware.LockBit.Dropper",
                    "quarantine_path": "quarantine/QUARANTINED_ransomware_dropper_sim.exe"
                },
                ioc_val=lockbit_sha
            )
            input("\nPress ENTER to continue...")

        elif choice == '10':
            print("\n[💀 AUTO-PWN] Launching 3-Stage APT Cyber Kill-Chain...")
            # Stage 1: Recon
            ports = [21, 22, 80, 443, 3306, 3389, 8000, 8080]
            fire_attack("Stage 1: Port Recon", "PORT_SCAN", "Port Scan (8 Ports Attacked)", "MEDIUM", 25.0, "45.155.205.233",
                        {"source_ip": "45.155.205.233", "ports_attacked_count": 8, "ports_attacked_list": ports, "services_probed": "21, 22, 80, 443, 3306, 3389, 8000, 8080"})
            time.sleep(1.5)
            # Stage 2: SQLi Exploit
            fire_attack("Stage 2: SQLi Auth Bypass", "SQL_INJECTION", "SQLi Blocked (Auth Bypass)", "HIGH", 45.0, "185.220.101.45",
                        {"attacker_command_used": "admin' OR 1=1 --", "matched_sqli_signatures": ["OR 1=1", "--"], "sqli_attack_classification": "Auth Bypass"})
            time.sleep(1.5)
            # Stage 3: DoS Flood
            fire_attack("Stage 3: Volumetric DoS Flood", "DOS_FLOOD", "DoS Flood (520 PPS)", "CRITICAL", 50.0, "198.51.100.77",
                        {"source_ip": "198.51.100.77", "packets_per_second": 520, "protocol_vector": "TCP SYN Flood", "estimated_bandwidth_mbps": 2.13})
            input("\n[✅ KILL-CHAIN COMPLETE] Check your Blue Team Dashboard! Press ENTER...")

        elif choice == '0':
            print("Exiting Red Team Console...")
            break

if __name__ == "__main__":
    main()