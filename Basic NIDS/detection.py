import time
from packet_logging import log_packet, log_malicious

RATE_LIMIT = 100
packet_count = {}

# Load rule patterns from file
def load_rules():
    """Load rule patterns from file"""
    try:
        with open("rules.txt", "r") as f:
            return [r.strip() for r in f if r.strip()]  # Keep original case
    except FileNotFoundError:
        log_packet("Error: rules.txt not found.")
        return []

# Detect if a source IP exceeds packet rate limit
def detect_anomalies(src_ip):
    """Detect if a source IP exceeds packet rate limit"""
    current_time = int(time.time())
    if src_ip not in packet_count:
        packet_count[src_ip] = {"count": 1, "time": current_time}
    elif packet_count[src_ip]["time"] == current_time:
        packet_count[src_ip]["count"] += 1
    else:
        packet_count[src_ip] = {"count": 1, "time": current_time}

    if packet_count[src_ip]["count"] > RATE_LIMIT:
        log_malicious(f"[ALERT] Rate limit exceeded by {src_ip}")
        return True
    return False

# Check payload against rules
def check_rules(payload, rules, src, dst):
    """Check payload against rules"""
    if not payload:
        return
        
    # Convert payload to string if it's bytes
    if isinstance(payload, bytes):
        try:
            payload_str = payload.decode(errors='ignore')
        except:
            payload_str = str(payload)
    else:
        payload_str = str(payload)

    # Convert to lowercase for case-insensitive matching
    payload_lower = payload_str.lower()

    for rule in rules:
        if rule.lower() in payload_lower:  # Case-insensitive matching
            log_malicious(f"[ALERT] Rule match: '{rule}' from {src} to {dst}")
            log_malicious(f"[PAYLOAD] {payload_str[:200]}")  # Log part of the matching payload
