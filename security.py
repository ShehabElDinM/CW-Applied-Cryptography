# security.py
import hashlib

def hash_password(password):
    """Hash a password using MD5."""
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    """Verify a provided password against the stored hashed password."""
    return stored_password == hash_password(provided_password)
