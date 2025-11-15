"""
AES helpers for SecureChat.

Provides:
- aes_encrypt(key: bytes, plaintext: bytes) -> (iv: bytes, ciphertext: bytes)
- aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> plaintext: bytes
- aes_encrypt_b64(...) and aes_decrypt_b64(...) convenience wrappers using base64.

Key requirements:
- key must be exactly 16 bytes (AES-128). Caller should derive Ksession as 16 bytes.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
from typing import Tuple
from app.common.utils import b64e, b64d

BLOCK_SIZE_BITS = 128
IV_LEN = 16
AES_KEY_LEN = 16  # AES-128


def _validate_key(key: bytes):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes")
    if len(key) != AES_KEY_LEN:
        raise ValueError(f"AES key must be {AES_KEY_LEN} bytes long (got {len(key)})")


def aes_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-128-CBC with PKCS#7 padding.
    Returns (iv, ciphertext) as raw bytes.
    """
    _validate_key(key)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    # PKCS7 padding
    padder = sym_padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(IV_LEN)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv, ct


def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-CBC with PKCS#7 padding.
    Returns plaintext bytes (unpadded).
    """
    _validate_key(key)
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != IV_LEN:
        raise ValueError(f"IV must be {IV_LEN} bytes")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = sym_padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext


# ------------- convenience b64 wrappers -------------
def aes_encrypt_b64(key: bytes, plaintext: bytes) -> dict:
    """
    Encrypt and return a dict with base64-encoded iv and ciphertext:
    { "iv_b64": "...", "ct_b64": "..." }
    Useful for JSON messages.
    """
    iv, ct = aes_encrypt(key, plaintext)
    return {"iv_b64": b64e(iv), "ct_b64": b64e(ct)}


def aes_decrypt_b64(key: bytes, iv_b64: str, ct_b64: str) -> bytes:
    """
    Accept base64-encoded iv and ciphertext, return plaintext bytes.
    """
    iv = b64d(iv_b64)
    ct = b64d(ct_b64)
    return aes_decrypt(key, iv, ct)


# ---------------------- test harness ----------------------
if __name__ == "__main__":
    # quick self-test
    test_key = b"0123456789abcdef"  # 16 bytes
    test_plain = b"The quick brown fox jumps over the lazy dog"

    print("Test key length:", len(test_key))
    iv, ct = aes_encrypt(test_key, test_plain)
    print("IV (hex):", iv.hex())
    print("CT (hex):", ct.hex())

    pt = aes_decrypt(test_key, iv, ct)
    print("Recovered plaintext:", pt)

    # b64 wrappers test
    obj = aes_encrypt_b64(test_key, test_plain)
    print("IV b64:", obj["iv_b64"])
    print("CT b64:", obj["ct_b64"])

    recovered = aes_decrypt_b64(test_key, obj["iv_b64"], obj["ct_b64"])
    print("Recovered via b64:", recovered)

    assert recovered == test_plain
    print("✅ AES round-trip OK")
