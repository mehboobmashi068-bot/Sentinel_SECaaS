import sys
import json
import re
import asyncio
import websockets
import time

# --- THREAT SIGNATURES ---
# Regex patterns for common web-based attack vectors
PATTERNS = {
    "SQL_INJECTION": re.compile(r"(SELECT|UNION|INSERT|DELETE|DROP|UPDATE|OR\s+1=1|--|#)", re.IGNORECASE),
    "XSS": re.compile(r"(<script|alert\(|onerror|onload|javascript:)", re.IGNORECASE),
    "PATH_TRAVERSAL": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/system32|/boot\.ini)", re.IGNORECASE)
}

# Dashboard connection settings
DASHBOARD_URL = "ws://localhost:3000"

def calculate_threat_score(payload):
    """
    Analyzes the payload for dangerous keywords and returns a tuple (score, top_threat).
    """
    total_findings = 0
    top_threat = "HEURISTIC_MATCH"
    
    if not payload:
        return 0, ""

    detected_types = []
    for attack_type, pattern in PATTERNS.items():
        matches = pattern.findall(payload)
        if matches:
            total_findings += len(matches)
            detected_types.append(attack_type)
            print(f"[!] Intelligence Match: {attack_type} detected ({len(matches)} occurrences)")

    if detected_types:
        top_threat = detected_types[0]

    # Scoring algorithm: Base score + intensity
    score = 0
    if total_findings > 0:
        score = min(10, 2 + (total_findings * 1.5))
    
    return round(score, 1), top_threat

async def process_telemetry():
    """
    Reads JSON telemetry from stdin (piped from interceptor.py) and processes threats.
    """
    print("--- SENTINEL_THREAT_INTEL v1.2 ---")
    print(f"[*] Connecting to Kernel Bridge: {DASHBOARD_URL}")
    
    try:
        async with websockets.connect(DASHBOARD_URL) as websocket:
            print("[+] INTEL_LINK_ESTABLISHED: Monitoring telemetry stream.")
            
            # Read from stdin line by line
            for line in sys.stdin:
                try:
                    packet_data = json.loads(line)
                    src_ip = packet_data.get("source_ip")
                    payload = packet_data.get("payload", "")
                    
                    threat_score, attack_type = calculate_threat_score(payload)
                    
                    if threat_score > 0:
                        print(f"[*] IP: {src_ip} | Threat Level: {threat_score}/10")
                        
                        # Trigger alert for Dashboard
                        alert_payload = {
                            "type": "SYSTEM",
                            "msg": f"[INTEL] {attack_type} Detected from {src_ip}. Score: {threat_score}. Analyzing payload...",
                            "timestamp": int(time.time() * 1000)
                        }
                        await websocket.send(json.dumps(alert_payload))

                        # If score is CRITICAL (> 7), trigger Enforcement
                        if threat_score > 7:
                            print(f"[!!!] CRITICAL THREAT: Initiating Enforcer signal for {src_ip}...")
                            
                            enforce_payload = {
                                "type": "SYSTEM",
                                "msg": f"[TRIGGER] Malicious IP {src_ip} marked for KERNEL_BLOCK. Reason: {attack_type}",
                                "timestamp": int(time.time() * 1000),
                                "action": "BLOCK_REQUEST",
                                "target_ip": src_ip,
                                "attack_type": attack_type
                            }
                            await websocket.send(json.dumps(enforce_payload))
                            
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"[!] Processing Error: {e}")

    except Exception as e:
        print(f"[!] Intel Fatal Failure: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(process_telemetry())
    except KeyboardInterrupt:
        print("\n[!] Threat Intelligence module stopped.")
