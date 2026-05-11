from scapy.all import sniff, IP, TCP, UDP
import sys

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
        
        dst_port = ""
        if packet.haslayer(TCP):
            dst_port = f" -> Port: {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            dst_port = f" -> Port: {packet[UDP].dport}"
            
        log_msg = f"[REAL-TIME] Source: {src_ip}{dst_port}"
        print(log_msg)
        sys.stdout.flush()

def main():
    print("# SENTINEL_SNIFFER v1.0.4 started on interface: eth0")
    print("# Awaiting network traffic...")
    try:
        # Note: Sniffing requires root privileges on real systems.
        # In this environment, we provide the script for your local deployment.
        sniff(iface="eth0", prn=packet_callback, store=0)
    except PermissionError:
        print("[ERROR] Permissions denied. Run with sudo: 'sudo python3 sniffer.py'")
    except Exception as e:
        print(f"[ERROR] Sniffer failure: {e}")

if __name__ == "__main__":
    main()
