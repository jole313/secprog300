import bcrypt
import json
import os

USERS_FILE = "users.json"

def init_users():
    """Initialize users file if it doesn't exist"""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def add_user(username, password):
    """Add a new user with hashed password"""
    init_users()
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    
    if username in users:
        return False, "Username already exists"
    
    # Hash the password
    hashed = hash_password(password)
    
    # Store the user
    users[username] = hashed.decode('utf-8')  # Convert bytes to string for JSON storage
    
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)
    
    return True, "User created successfully"

def verify_user(username, password):
    """Verify user credentials"""
    init_users()
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    
    if username not in users:
        return False, "Invalid username or password"
    
    stored_hash = users[username].encode('utf-8')  # Convert string back to bytes
    
    if verify_password(password, stored_hash):
        return True, "Login successful"
    
    return False, "Invalid username or password"

# Create default admin user if no users exist
def ensure_admin_exists():
    """Ensure at least one admin user exists"""
    init_users()
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    
    if not users:
        add_user("admin", "admin123")  # Default credentials
        print("Default admin user created. Please change password after first login.") 