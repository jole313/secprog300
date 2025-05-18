import scapy.all as scapy
from detection import load_rules, detect_anomalies, check_rules
from packet_logging import log_packet, log_malicious
import socket
import sys
import binascii

# Get local machine IP for filtering
LOCAL_IP = socket.gethostbyname(socket.gethostname())
LOOPBACK_IP = "127.0.0.1"
rules = load_rules()

def find_loopback_interface():
    """Find the loopback interface"""
    interfaces = scapy.get_if_list()
    loopback = None
    
    log_packet("\nSearching for loopback interface...")
    for iface in interfaces:
        try:
            ip = scapy.get_if_addr(iface)
            log_packet(f"Interface {iface}: {ip}")
            if ip == LOOPBACK_IP or "loopback" in iface.lower() or "lo" in iface.lower():
                loopback = iface
                log_packet(f"Found loopback interface: {iface}")
                break
        except Exception as e:
            log_packet(f"Error checking interface {iface}: {str(e)}")
    
    return loopback

def format_payload(payload):
    """Format payload for logging, handling binary data appropriately"""
    try:
        # Try to decode as UTF-8 first
        decoded = payload.decode('utf-8', errors='backslashreplace')
        if any(ord(c) < 32 and c not in '\r\n\t' for c in decoded):
            # If we have control characters (except newlines and tabs), use hex
            return f"(hex) {binascii.hexlify(payload).decode('ascii')}"
        return f"(text) {decoded}"
    except:
        # If decoding fails, return hex representation
        return f"(hex) {binascii.hexlify(payload).decode('ascii')}"

def packet_handler(packet):
    if packet.haslayer(scapy.IP):
        ip = packet[scapy.IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        payload = None
        
        # Get port information if available
        src_port = dst_port = "N/A"
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
        elif packet.haslayer(scapy.ICMP):
            log_packet(f"ICMP packet detected from {src} to {dst}")

        # Log packet info with more details
        log_str = f"Packet: {src}:{src_port} -> {dst}:{dst_port}, " \
                 f"Proto: {'TCP' if packet.haslayer(scapy.TCP) else 'UDP' if packet.haslayer(scapy.UDP) else 'ICMP' if packet.haslayer(scapy.ICMP) else 'Other'}"
        
        if payload:
            log_str += f"\nPayload Size: {len(payload)} bytes"
            log_str += f"\nPayload: {format_payload(payload)}"
        
        log_packet(log_str)

        # Check for anomalies and rule matches
        if detect_anomalies(src):
            return  # Skip rule checking if rate limit exceeded
        
        if payload:
            check_rules(payload, rules, src, dst)

def start_capture():
    log_packet("Starting packet capture...")
    
    # Find loopback interface
    loopback_iface = find_loopback_interface()
    
    # Set up capture filter - focus on loopback traffic
    filter_str = f"host {LOOPBACK_IP}"
    log_packet(f"\nCapture filter: {filter_str}")
    log_packet(f"Focusing on loopback traffic (127.0.0.1)")
    
    try:
        if loopback_iface:
            log_packet(f"\nStarting capture on loopback interface: {loopback_iface}")
            scapy.sniff(iface=loopback_iface, filter=filter_str, prn=packet_handler, store=False)
        else:
            log_packet("\nNo loopback interface found, trying default capture...")
            scapy.sniff(filter=filter_str, prn=packet_handler, store=False)
    except Exception as e:
        log_packet(f"Error in capture: {str(e)}")
        if "permission" in str(e).lower():
            log_packet("\nPermission error detected. Please make sure you're running as Administrator.")
        raise
