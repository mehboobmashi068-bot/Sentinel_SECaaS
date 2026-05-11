import sqlite3
import subprocess
import time
import json
import asyncio
import websockets
import os

# --- CONFIGURATION ---
DB_NAME = "ThreatVault.db"
DASHBOARD_URL = "ws://localhost:3000"

def init_db():
    """Initializes the ThreatVault SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            attack_type TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def log_block(ip, attack_type):
    """Records the neutralized IP and attack context to the local Vault."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO blocks (ip_address, attack_type) VALUES (?, ?)', (ip, attack_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Database Write Error: {e}")

def block_ip(ip):
    """Executes the kernel-level blocking command using iptables."""
    try:
        # -I (Insert) at index 1 to override existing permissive rules
        print(f"[*] SEVERING CONNECTION: {ip}")
        cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"[!] Kernel Intervention Error: {e}")
        return False

def unblock_ip(ip):
    """Lifts the kernel-level block for the specified IP."""
    try:
        # -D (Delete) the specific rule
        print(f"[*] RESTORING CONNECTION: {ip}")
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"[!] Kernel Restoration Error: {e}")
        return False

async def run_active_defense():
    """Synchronizes with the Dashboard and processes inbound threat signals."""
    init_db()
    print("--- SENTINEL_ACTIVE_DEFENSE v1.0.2 ---")
    print(f"[*] ThreatVault Active: {os.path.abspath(DB_NAME)}")
    
    try:
        async with websockets.connect(DASHBOARD_URL) as websocket:
            print("[+] SHIELD_READY: Linked to Sentinel_SECaaS Command Center.")
            
            while True:
                message = await websocket.recv()
                data = json.loads(message)
                
                # Listen for Automated Block Requests from Threat Intel
                if data.get("action") == "BLOCK_REQUEST":
                    target_ip = data.get("target_ip")
                    attack_type = data.get("attack_type", "High-Threat Behavior")
                    
                    if block_ip(target_ip):
                        log_block(target_ip, attack_type)
                        
                        # Send success telemetry to Dashboard
                        success_payload = {
                            "type": "SYSTEM",
                            "msg": f"[DEFENSE-ACTIVE] IP {target_ip} neutralized. Type: {attack_type}. Logged to ThreatVault.db",
                            "timestamp": int(time.time() * 1000)
                        }
                        await websocket.send(json.dumps(success_payload))
                        print(f"[+] Success: {target_ip} documented and blocked.")
                    else:
                        # Report failure (likely permissions or duplicate rule)
                        fail_payload = {
                            "type": "SYSTEM",
                            "msg": f"[DEFENSE-ERROR] IP {target_ip} block failed at Kernel level.",
                            "timestamp": int(time.time() * 1000)
                        }
                        await websocket.send(json.dumps(fail_payload))

    except websockets.exceptions.ConnectionClosed:
        print("[!] Logic Link Terminated.")
    except Exception as e:
        print(f"[!] Defense Logic Failure: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(run_active_defense())
    except KeyboardInterrupt:
        print("\n[!] Disengaging Active Defense Protocols.")
