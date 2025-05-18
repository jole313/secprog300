import hashlib
import time
import logging
import codecs
import sys
import os

# Initialize logging with default settings
PACKET_LOG_FILE = "packet.log"
MALICIOUS_LOG_FILE = "malicious.log"

# Configure general packet logger
packet_logger = logging.getLogger("packet")
packet_logger.setLevel(logging.INFO)
packet_handler = logging.FileHandler(PACKET_LOG_FILE)
packet_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
packet_logger.addHandler(packet_handler)

# Configure malicious packet logger
malicious_logger = logging.getLogger("malicious")
malicious_logger.setLevel(logging.INFO)
malicious_handler = logging.FileHandler(MALICIOUS_LOG_FILE)
malicious_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
malicious_logger.addHandler(malicious_handler)

def sanitize_for_log(message):
    """Sanitize message for logging, handling binary and non-ASCII data"""
    if isinstance(message, bytes):
        try:
            return message.decode('utf-8', errors='backslashreplace')
        except:
            return repr(message)
    elif isinstance(message, str):
        try:
            return message.encode('utf-8', errors='backslashreplace').decode('utf-8')
        except:
            return repr(message)
    return str(message)

def log_packet(message):
    """Log general packet information"""
    safe_message = sanitize_for_log(message)
    packet_logger.info(safe_message)

def log_malicious(message):
    """Log malicious packet information"""
    safe_message = sanitize_for_log(message)
    print(safe_message)  # Also print to console
    malicious_logger.info(safe_message)

def read_log(filename):
    """Read a log file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading log: {str(e)}"

def hash_logs():
    """Calculate hash of both log files"""
    hash_obj = hashlib.sha256()
    try:
        with open("packet.log", "rb") as f:
            hash_obj.update(f.read())
        with open("malicious.log", "rb") as f:
            hash_obj.update(f.read())
    except FileNotFoundError:
        return "No log files found"
    return hash_obj.hexdigest()
