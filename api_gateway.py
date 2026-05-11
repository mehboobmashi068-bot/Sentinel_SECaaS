import os
import re
import json
import time
import requests
import threading
import asyncio
import websockets
import sqlite3
from flask import Flask, request, jsonify

# --- SENTINEL SECaaS GATEWAY CONFIG ---
app = Flask(__name__)
PORT = 5000
DASHBOARD_WS = "ws://localhost:3000/ws"
DB_NAME = "ThreatVault.db"
RISK_THRESHOLD = 80

def initialize_registry():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Risk_Registry (
            identifier TEXT PRIMARY KEY, 
            cumulative_score INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            last_seen INTEGER,
            type TEXT DEFAULT 'IP'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Deception_Logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT,
            payload TEXT,
            path TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

initialize_registry()

# Threat Signatures (Regex-based Heuristics)
SIGNATURES = {
    "SQL_INJECTION": re.compile(r"(SELECT|UNION|INSERT|DELETE|DROP|UPDATE|OR\s+1=1|--|#|['\";]\s*OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.IGNORECASE),
    "XSS": re.compile(r"(<script|alert\(|onerror|onload|javascript:|eval\(|document\.cookie)", re.IGNORECASE),
    "SUSPICIOUS_PROBE": re.compile(r"(admin|config|root|passwd|shadow)", re.IGNORECASE),
    "COMMAND_GUESSING": re.compile(r"(woke up guard|delete baby)", re.IGNORECASE)
}

def normalize_payload_py(payload):
    normalized = str(payload)
    # 1. Recursive Decoding
    for _ in range(3):
        previous = normalized
        try:
            from urllib.parse import unquote
            normalized = unquote(normalized)
        except:
            break
        if normalized == previous:
            break
    
    normalized = normalized.lower()
    # 2. Dialect Cleaner
    normalized = re.sub(r'[`\[\]]', '', normalized)
    # 3. Comments & Spaces
    normalized = re.sub(r'/\*.*?\*/', '', normalized, flags=re.DOTALL)
    normalized = re.sub(r'<!--.*?-->', '', normalized, flags=re.DOTALL)
    normalized = re.sub(r'\s+', ' ', normalized)
    return normalized.strip()

def update_risk_registry(identifier, score, id_type="IP"):
    """Atomically updates risk and checks for ban."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Get existing
        cursor.execute("SELECT cumulative_score, is_banned FROM Risk_Registry WHERE identifier = ?", (identifier,))
        row = cursor.fetchone()
        
        new_score = (row[0] if row else 0) + score
        
        # Mirror Room Threshold (90-100)
        verdict = "ALLOW"
        is_banned = 0
        if (row and row[1] == 1) or new_score >= 100:
            is_banned = 1
            verdict = "DENY"
        elif new_score >= 90:
            verdict = "REDIRECT_TO_SANDBOX"

        cursor.execute("""
            INSERT INTO Risk_Registry (identifier, cumulative_score, is_banned, last_seen, type)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(identifier) DO UPDATE SET
            cumulative_score = excluded.cumulative_score,
            is_banned = excluded.is_banned,
            last_seen = excluded.last_seen
        """, (identifier, new_score, is_banned, int(time.time() * 1000), id_type))
        
        conn.commit()
        conn.close()
        return {"total_risk": new_score, "is_banned": is_banned == 1, "verdict": verdict}
    except Exception as e:
        print(f"[!] [REGISTRY] Score Update Error: {e}")
        return {"total_risk": score, "is_banned": False}

def validate_key_against_db(api_key):
    """Checks if the provided API key exists in the persistent database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT client_name FROM Authorized_Clients WHERE api_key = ?", (api_key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except Exception as e:
        print(f"[!] [GATEWAY] Auth Database Error: {e}")
        return None

def get_geo_data(ip):
    """Performs an async-style lookup using a synchronous library (requests)."""
    try:
        # Using ip-api.com for lightweight geographical telemetry
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data.get('status') == 'success':
            return {
                "country": data.get('country', 'Unknown'),
                "city": data.get('city', 'Unknown'),
                "isp": data.get('isp', 'Unknown')
            }
    except Exception as e:
        print(f"[!] [GEO] Lookup Error: {e}")
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

async def broadcast_threat(payload):
    """Sends threat telemetry to the Dashboard bridge via WebSockets."""
    try:
        async with websockets.connect(DASHBOARD_WS) as ws:
            await ws.send(json.dumps(payload))
    except Exception as e:
        print(f"[!] [BRIDGE] Failed to sync with Dashboard: {e}")

def trigger_enforcement(payload):
    """Helper to run the async broadcast in a separate thread context."""
    asyncio.run(broadcast_threat(payload))

@app.route('/api/v1/shield/validate', methods=['POST'])
def validate_traffic():
    # 1. API Key Security Check
    client_key = request.headers.get('X-API-KEY')
    fingerprint = request.headers.get('X-FINGERPRINT')
    client_name = validate_key_against_db(client_key)
    
    if not client_name:
        return jsonify({"verdict": "DENY", "reason": "INVALID_API_KEY"}), 401

    data = request.get_json()
    if not data or 'visitor_ip' not in data or 'payload' not in data:
        return jsonify({"error": "Malformed request"}), 400

    visitor_ip = data['visitor_ip']
    user_payload = data['payload']
    primary_id = fingerprint if fingerprint else visitor_ip
    
    # 2. Pre-check Banned State
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT is_banned FROM Risk_Registry WHERE identifier = ?", (primary_id,))
        banned_check = cursor.fetchone()
        conn.close()
        if banned_check and banned_check[0] == 1:
            return jsonify({"verdict": "DENY", "reason": "SECURITY_REGISTRY_BAN"}), 403
    except:
        pass

    # 3. Normalization & Scoring
    normalized = normalize_payload_py(user_payload)
    score = 0
    threats = []
    
    if SIGNATURES["SQL_INJECTION"].search(normalized):
        score += 55
        threats.append("SQL_INJECTION")
    if SIGNATURES["XSS"].search(normalized):
        score += 45
        threats.append("XSS")
    if SIGNATURES["SUSPICIOUS_PROBE"].search(normalized):
        score += 15
        threats.append("SUSPICIOUS_PROBE")
    if SIGNATURES["COMMAND_GUESSING"].search(normalized):
        score += 30
        threats.append("COMMAND_GUESSING")

    # 4. Update Risk Registry
    id_type = "FINGERPRINT" if fingerprint else "IP"
    registry_status = update_risk_registry(primary_id, score, id_type)
    
    if registry_status["verdict"] == "REDIRECT_TO_SANDBOX":
        # Log to Deception Logs
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO Deception_Logs (identifier, payload, path) VALUES (?, ?, ?)", 
                           (primary_id, json.dumps(user_payload), "/api/v1/shield/validate"))
            conn.commit()
            conn.close()
        except:
            pass
            
        telemetry = {
            "type": "SANDBOX_EVENT",
            "msg": f"[DECEPTION] Identity {primary_id} moved to Mirror Room. Risk: {registry_status['total_risk']}",
            "timestamp": int(time.time() * 1000),
            "ip": visitor_ip,
            "fingerprint": fingerprint
        }
        threading.Thread(target=trigger_enforcement, args=(telemetry,)).start()
        
        return jsonify({
            "verdict": "REDIRECT_TO_SANDBOX",
            "score": score,
            "cumulative_risk": registry_status["total_risk"],
            "message": "ACCESS_GRANTED_DEFERRED",
            "sandbox_mode": True
        }), 200

    if registry_status["is_banned"]:
        geo = get_geo_data(visitor_ip)
        telemetry = {
            "type": "SYSTEM",
            "msg": f"[REGISTRY-BAN] Identity {primary_id} permanently flagged. Cumulative Risk: {registry_status['total_risk']}",
            "timestamp": int(time.time() * 1000),
            "action": "BLOCK_REQUEST",
            "target_ip": visitor_ip,
            "attack_type": "REGISTRY_THRESHOLD_BREACH",
            "geo": geo
        }
        threading.Thread(target=trigger_enforcement, args=(telemetry,)).start()
        return jsonify({
            "verdict": "DENY",
            "threat_level": "CRITICAL",
            "cumulative_risk": registry_status["total_risk"],
            "geo": geo
        }), 403

    if score >= 50:
        return jsonify({
            "verdict": "DENY",
            "score": score,
            "threats": threats,
            "cumulative_risk": registry_status["total_risk"]
        }), 403

    return jsonify({
        "verdict": "ALLOW",
        "score": score,
        "cumulative_risk": registry_status["total_risk"]
    }), 200

# --- Mirror Room API ---
@app.route('/api/v1/mirror/vault', methods=['GET'])
def mirror_vault():
    client_key = request.headers.get('X-API-KEY')
    fingerprint = request.headers.get('X-FINGERPRINT')
    visitor_ip = request.remote_addr
    primary_id = fingerprint if fingerprint else visitor_ip

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Deception_Logs (identifier, payload, path) VALUES (?, ?, ?)", 
                       (primary_id, "READ_VAULT", "/api/v1/mirror/vault"))
        conn.commit()
        conn.close()
    except:
        pass

    return jsonify({
      "status": "SUCCESS",
      "vault_data": [
        { "id": "cc_84221", "number": "4532-****-****-1102", "cvv": "***", "exp": "12/28", "bank": "Global Reserve" },
        { "id": "admin_log_01", "entry": "Failed login attempt from user: root" }
      ]
    })

@app.route('/api/v1/mirror/download', methods=['GET'])
def mirror_download():
    fingerprint = request.headers.get('X-FINGERPRINT')
    visitor_ip = request.remote_addr
    primary_id = fingerprint if fingerprint else visitor_ip

    telemetry = {
        "type": "HONE_HOOKED",
        "msg": f"ALERT: Hacker {primary_id} downloaded poisoned file. Canary Token TRIPPED.",
        "timestamp": int(time.time() * 1000),
        "ip": visitor_ip,
        "fingerprint": fingerprint
    }
    threading.Thread(target=trigger_enforcement, args=(telemetry,)).start()

    return "-- SENTINEL CANARY TOKEN DETECTED --\n# [ CANARY_ID: 88219-X ]\n", 200, {
        'Content-Type': 'text/plain',
        'Content-Disposition': 'attachment; filename=db_dump_2026.sql.gz'
    }

if __name__ == "__main__":
    print(f"--- SENTINEL_SECaaS_GATEWAY v1.0.4 ---")
    print(f"[*] Gateway active on 0.0.0.0:{PORT}")
    print(f"[*] Monitoring endpoints: /api/v1/shield/validate")
    
    # Threaded mode enabled for handling multiple client requests concurrently
    app.run(host='0.0.0.0', port=PORT, threaded=True, debug=False)
