# Basic NIDS (Network Intrusion Detection System)

A simple Network Intrusion Detection System that monitors network traffic and detects potential security threats.

## Features

- Real-time network traffic monitoring
- Detection of various security threats including:
  - SQL Injection attempts
  - XSS attacks
  - Port scanning
  - Suspicious network patterns
  - And more...
- Encrypted log storage
- User authentication system
- GUI interface for monitoring

## Requirements

- Python 3.8 or higher
- Administrator/root privileges (required for packet capture)
- Windows, Linux, or macOS

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/BasicNIDSproject.git
cd BasicNIDSproject
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application with administrator/root privileges:
```bash
# Windows (PowerShell as Administrator)
python main.py

# Linux/macOS
sudo python3 main.py
```

2. Login with default credentials:
   - Username: admin
   - Password: admin123

3. The GUI will show:
   - Real-time network traffic
   - Detected malicious activities
   - System status

## Project Structure

- `main.py` - Application entry point
- `capture.py` - Network packet capture
- `detection.py` - Threat detection logic
- `gui.py` - User interface
- `login.py` - Authentication system
- `packet_logging.py` - Log management
- `log_encryption.py` - Log encryption
- `users.py` - User management
- `rules.txt` - Detection rules
- `packet_test.py` - Test suite for packet analysis

## Security Note

This is a basic NIDS implementation for educational purposes. For production use, consider:
- Implementing more sophisticated detection rules
- Adding more security features
- Using established security libraries
- Regular updates and maintenance

## License

[Your chosen license]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 