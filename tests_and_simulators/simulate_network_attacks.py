# tests_and_simulators/simulate_network_attacks.py
import requests
import time
import os

API_URL = "http://127.0.0.1:8000/api/ingest-telemetry"

def fire_attack(name, module, threat, severity, risk, ip, payload, ioc=None):
    print(f"\n[🚀] LAUNCHING ATTACK: {name}")
    time.sleep(1)
    
    data = {
        "user_id": 1,
        "session_id": "sess_pune_01",
        "source_ip": ip,
        "indicator_value": ioc or ip,
        "module_name": module,
        "threat_type": threat,
        "severity": severity,
        "base_risk_score": risk,
        "confidence_score": 0.98,
        "raw_payload": payload
    }
    
    try:
        response = requests.post(API_URL, json=data)
        res_data = response.json()
        print(f"  [+] Target Hit! Current Session Risk: {res_data['cumulative_session_risk']}/100")
        print(f"  [+] Target SOC Response: {res_data['automated_soar_action']}")
        if res_data.get('ioc_enriched'):
            print(f"  [!] Threat Intel Alert: {res_data['ioc_details']}")
    except Exception as e:
        print(f"  [-] Connection Failed. Is your FastAPI server running on port 8000?")
        
    input("\nPress ENTER to return to the Red Team menu...")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=========================================")
        print(" 🔴 RED TEAM ATTACK SIMULATOR (CLI) 🔴 ")
        print("=========================================")
        print("1. Fire Port Scan (Nmap)")
        print("2. Fire DoS Flood")
        print("3. Fire ARP Spoofing (MITM)")
        print("4. Fire SQL Injection Payload")
        print("5. Fire Impossible Travel / Tor Login")
        print("0. Exit")
        print("=========================================")
        
        choice = input("Select an attack to launch (0-5): ")
        
        if choice == '1':
            fire_attack("Port Scan", "PORT_SCAN", "Port Scan Detected", "MEDIUM", 30.0, "45.155.205.233", "Probed 20 TCP ports in 5s")
        elif choice == '2':
            fire_attack("DoS Flood", "DOS_FLOOD", "High-Volume DoS Flood", "CRITICAL", 50.0, "198.51.100.77", "Traffic spike: 350 PPS")
        elif choice == '3':
            fire_attack("ARP Spoofing", "ARP_SPOOFING", "ARP Cache Poisoning", "CRITICAL", 55.0, "192.168.1.55", "Gateway MAC address hijacked")
        elif choice == '4':
            fire_attack("SQL Injection", "SQL_INJECTION", "SQLi Payload", "HIGH", 45.0, "185.220.101.45", "Payload: admin' OR '1'='1")
        elif choice == '5':
            fire_attack("Impossible Travel", "IMPOSSIBLE_TRAVEL", "Geo-Velocity Anomaly", "HIGH", 40.0, "185.220.101.45", "Login jump of 7000km in 15 mins")
        elif choice == '0':
            break

if __name__ == "__main__":
    main()