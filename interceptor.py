import sys
import json
import time
from scapy.all import sniff, IP, TCP, Raw

def get_payload_str(packet):
    """Safely extracts and decodes the raw payload from a packet."""
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            # Attempt UTF-8 decoding, fallback to latin-1 or hex representation
            return payload.decode('utf-8', errors='replace')
        except Exception:
            return payload.hex()
    return ""

def process_packet(packet):
    """Callback function to process each captured packet."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        payload_data = get_payload_str(packet)
        
        # Prepare the data as a dictionary
        packet_info = {
            "timestamp": time.time(),
            "source_ip": src_ip,
            "destination_port": dst_port,
            "protocol": "TCP",
            "payload": payload_data
        }
        
        # Output as clean JSON for secondary parsing
        print(json.dumps(packet_info))
        sys.stdout.flush()

def main():
    # Specify the interface to listen on
    # In many security environments, eth0 is the primary interface.
    interface = "eth0"
    
    print(f"[*] SENTINEL_INTERCEPTOR v3.0.1 active on {interface}")
    print("[*] Filtering for TCP/IP traffic... Press Ctrl+C to stop.")
    
    try:
        # sniff() parameters:
        # iface: Network interface to listen on
        # prn: Function to apply to each packet
        # store: Set to 0 to prevent memory consumption for long captures
        # filter: BPF filter to capture only TCP packets
        sniff(iface=interface, prn=process_packet, filter="tcp", store=0)
        
    except PermissionError:
        print("[!] FATAL: Root privileges required for packet interception.")
        print("[!] Run with: 'sudo python3 interceptor.py'")
    except Exception as e:
        print(f"[!] INTERCEPT_FAILURE: {str(e)}")

if __name__ == "__main__":
    main()
