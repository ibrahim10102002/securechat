"""
Helper signatures: now_ms, b64e, b64d, sha256_hex.
Extended to include salt generation and password hashing.
"""

import base64
import hashlib
import os
import time


def now_ms() -> int:
    """Return current UTC timestamp in milliseconds."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Encode bytes to a Base64 string."""
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    """Decode a Base64 string back to bytes."""
    return base64.b64decode(s.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of given bytes."""
    return hashlib.sha256(data).hexdigest()


def generate_salt(length: int = 16) -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(length)


def hash_password(password: str, salt: bytes) -> str:
    """
    Compute SHA-256 hash of password + salt.
    Returns the hash as a hex string.
    """
    return sha256_hex(password.encode() + salt)


def verify_password(stored_hash: str, password_attempt: str, salt: bytes) -> bool:
    """Verify whether a password attempt matches the stored hash."""
    attempt_hash = hash_password(password_attempt, salt)
    return stored_hash == attempt_hash


# Optional test harness — won't affect program behavior
if __name__ == "__main__":
    print("Now (ms):", now_ms())
    msg = b"Hello SecureChat"
    encoded = b64e(msg)
    print("Base64 Encoded:", encoded)
    print("Base64 Decoded:", b64d(encoded))
    print("SHA-256 of 'Hello SecureChat':", sha256_hex(msg))
    salt = generate_salt()
    hashed = hash_password("mypassword123", salt)
    print(f"Salt (hex): {salt.hex()}")
    print(f"Password Hash: {hashed}")
    print("Password verified:", verify_password(hashed, "mypassword123", salt))
