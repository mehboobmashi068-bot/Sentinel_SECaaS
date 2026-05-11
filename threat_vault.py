import sqlite3
import subprocess
import time
import json
import asyncio
import websockets
import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# --- THREAT VAULT CONFIGURATION ---
DB_NAME = "ThreatVault.db"
DASHBOARD_URL = "ws://localhost:3000/ws"

# Thread pool for non-blocking HTTP lookups
executor = ThreadPoolExecutor(max_workers=5)

def initialize_vault():
    """Initializes the Threat Vault SQLite database with enrichment fields."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Updated Schema: id, ip_address, attack_type, timestamp, country, city, isp
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            country TEXT DEFAULT 'Pending Scan',
            city TEXT DEFAULT 'Pending Scan',
            isp TEXT DEFAULT 'Unknown'
        )
    ''')
    
    # Authorized Clients Table: Persistent API Keys
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Authorized_Clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT UNIQUE NOT NULL,
            client_name TEXT NOT NULL,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print(f"[*] [VAULT] Database Initialized: {DB_NAME}")

def get_ip_location_sync(ip):
    """Synchronous lookup for IP-API.com."""
    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data['status'] == 'success':
                return {
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "isp": data.get('isp', 'Unknown')
                }
    except Exception as e:
        print(f"[!] [GEO] Lookup failed for {ip}: {e}")
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

async def get_ip_location(ip):
    """Wrapper to run the sync lookup in a thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, get_ip_location_sync, ip)

def archive_threat(ip, attack_type, geo_data=None):
    """Inserts or updates a threat record with geographical data."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        country = geo_data.get('country', 'Unknown') if geo_data else 'Pending Scan'
        city = geo_data.get('city', 'Unknown') if geo_data else 'Pending Scan'
        isp = geo_data.get('isp', 'Unknown') if geo_data else 'Unknown'

        # Check if record exists to update it (if geo scan finishes later)
        cursor.execute('SELECT id FROM blocked_entities WHERE ip_address = ?', (ip,))
        result = cursor.fetchone()

        if result:
            cursor.execute(
                'UPDATE blocked_entities SET country = ?, city = ?, isp = ? WHERE ip_address = ?',
                (country, city, isp, ip)
            )
        else:
            cursor.execute(
                'INSERT INTO blocked_entities (ip_address, attack_type, country, city, isp) VALUES (?, ?, ?, ?, ?)', 
                (ip, attack_type, country, city, isp)
            )
        
        conn.commit()
        conn.close()
        print(f"[VAULT] IP {ip} archived in Blacklist ({city}, {country}).")
    except Exception as e:
        print(f"[!] [VAULT] Archive Failure: {e}")

def execute_kernel_kill(ip):
    """Physically severs the connection using iptables."""
    try:
        print(f"[*] [KERNEL] Executing KILL command for {ip}...")
        cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"[!] [KERNEL] System Command Error: {e}")
        return False

async def handle_block_request(websocket, data):
    """Handles the block logic: Kill -> Async Geo Lookup -> Archive."""
    ip = data.get("target_ip")
    attack_type = data.get("attack_type", "Manual Kill")
    
    # 1. IMMEDIATE: Execute kernel block
    if execute_kernel_kill(ip):
        # 2. Record initial entry (Pending Scan)
        archive_threat(ip, attack_type)
        
        # 3. ASYNC: Perform Geo-IP lookup without blocking the loop
        geo_data = await get_ip_location(ip)
        
        # 4. Update the archive with Geo data
        archive_threat(ip, attack_type, geo_data)
        
        # 5. DASHBOARD ALERT
        alert_msg = f"[ALERT] Neutralized threat from {geo_data['city']}, {geo_data['country']} (ISP: {geo_data['isp']}). Target IP: {ip}"
        await websocket.send(json.dumps({
            "type": "SYSTEM",
            "msg": alert_msg,
            "timestamp": int(time.time() * 1000)
        }))
        
        # Confirmation of success
        await websocket.send(json.dumps({
            "type": "SYSTEM",
            "msg": f"[SUCCESS] IP {ip} neutralized and archived in ThreatVault.db",
            "timestamp": int(time.time() * 1000)
        }))
    else:
        await websocket.send(json.dumps({
            "type": "SYSTEM",
            "msg": f"[ERROR] Failed to execute Kernel block for {ip}.",
            "timestamp": int(time.time() * 1000)
        }))

async def run_vault_listener():
    """Connects to the bridge and listens for commands."""
    initialize_vault()
    print("--- SENTINEL_THREAT_VAULT v5.0 (Geo-Enhanced) ---")
    
    try:
        async with websockets.connect(DASHBOARD_URL) as websocket:
            print("[+] [VAULT] Bridge Active. Tracking global telemetry.")
            
            await websocket.send(json.dumps({
                "type": "SYSTEM",
                "msg": "[VAULT] Geo-IP Tracking Module Online. Monitoring Intercepts.",
                "timestamp": int(time.time() * 1000)
            }))

            while True:
                message = await websocket.recv()
                data = json.loads(message)
                
                if data.get("action") == "BLOCK_REQUEST":
                    # Fire and forget or await depending on needs; 
                    # here we await so we can send the Alert based on lookup
                    asyncio.create_task(handle_block_request(websocket, data))

    except websockets.exceptions.ConnectionClosed:
        print("[!] [VAULT] Connection lost.")
    except Exception as e:
        print(f"[!] [VAULT] Fatal Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(run_vault_listener())
    except KeyboardInterrupt:
        print("\n[!] [VAULT] Module Terminated.")
