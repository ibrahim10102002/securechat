"""
Diffie-Hellman helpers.

Provides:
- get_default_parameters() -> DHParameters (cached)
- generate_private_key(params) -> DHPrivateKey
- pubkey_bytes_b64(private_key) -> base64 of public bytes (PEM-like raw)
- load_peer_pubkey_from_b64(b64) -> DHPublicKey
- compute_shared_secret_bytes(priv_key, peer_pubkey) -> raw shared bytes
- derive_aes_key_from_shared_secret(shared_bytes) -> 16-byte AES key as bytes
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
from app.common.utils import b64e, b64d
from typing import Tuple
import threading

# Cache for parameters so we don't regenerate each time
_PARAM_CACHE = {}
_PARAM_LOCK = threading.Lock()


def get_default_parameters(key_size: int = 2048) -> dh.DHParameters:
    """
    Return shared DH parameters (generate on first call and cache).
    key_size: 2048 by default (secure). Generating params is expensive.
    """
    global _PARAM_CACHE
    key = f"dh_params_{key_size}"
    with _PARAM_LOCK:
        if key not in _PARAM_CACHE:
            _PARAM_CACHE[key] = dh.generate_parameters(generator=2, key_size=key_size)
        return _PARAM_CACHE[key]


def generate_private_key(params: dh.DHParameters = None) -> dh.DHPrivateKey:
    """Generate a DH private key using provided params or default params."""
    if params is None:
        params = get_default_parameters()
    return params.generate_private_key()


def public_key_bytes(priv: dh.DHPrivateKey) -> bytes:
    """
    Return the public key bytes in SubjectPublicKeyInfo (DER) form.
    This is convenient for transmission.
    """
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def dh_parameters_bytes(priv: dh.DHPrivateKey) -> bytes:
    """Return the DH parameters (p, g) in DER format from a private key."""
    params = priv.parameters()
    return params.parameter_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.ParameterFormat.PKCS3
    )


def public_key_bytes_b64(priv: dh.DHPrivateKey) -> str:
    """Return base64-encoded public key bytes (DER)."""
    return b64e(public_key_bytes(priv))


def load_peer_public_key_from_b64(b64: str) -> dh.DHPublicKey:
    """Load a peer's public key from base64 DER bytes."""
    der = b64d(b64)
    return serialization.load_der_public_key(der)


def dh_parameters_b64(priv: dh.DHPrivateKey) -> str:
    """Return base64-encoded DH parameters from a private key."""
    params = priv.parameters()
    params_bytes = params.parameter_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.ParameterFormat.PKCS3
    )
    return b64e(params_bytes)


def load_dh_parameters_from_b64(b64: str) -> dh.DHParameters:
    """Load DH parameters from base64 DER bytes."""
    der = b64d(b64)
    return serialization.load_der_parameters(der)


def generate_private_key_with_params(params: dh.DHParameters) -> dh.DHPrivateKey:
    """Generate a DH private key using provided parameters."""
    return params.generate_private_key()


def compute_shared_secret_bytes(priv: dh.DHPrivateKey, peer_pub: dh.DHPublicKey) -> bytes:
    """
    Compute the raw shared key (bytes) using private key and peer public key.
    The returned bytes are the raw shared bytes produced by DH (big-endian).
    """
    shared = priv.exchange(peer_pub)
    # shared is bytes; we return it directly for hashing
    return shared


def derive_aes_key_from_shared_secret(shared_bytes: bytes) -> bytes:
    """
    Derive AES-128 key from shared secret:
    K = Trunc16( SHA256( big-endian(shared_bytes) ) )
    Returns 16 bytes.
    """
    h = hashlib.sha256(shared_bytes).digest()
    return h[:16]


# ------------------ Test harness ------------------
if __name__ == "__main__":
    # quick local test for DH round-trip and key derivation
    params = get_default_parameters(2048)
    a = generate_private_key(params)
    b = generate_private_key(params)

    a_pub_b64 = public_key_bytes_b64(a)
    b_pub_b64 = public_key_bytes_b64(b)

    # load peer public keys
    a_peer_pub = load_peer_public_key_from_b64(b_pub_b64)
    b_peer_pub = load_peer_public_key_from_b64(a_pub_b64)

    # compute shared secrets
    s1 = compute_shared_secret_bytes(a, a_peer_pub)
    s2 = compute_shared_secret_bytes(b, b_peer_pub)

    assert s1 == s2, "Shared secrets must match"
    key1 = derive_aes_key_from_shared_secret(s1)
    key2 = derive_aes_key_from_shared_secret(s2)
    print("Shared secret length:", len(s1))
    print("Derived AES key (hex):", key1.hex())
    assert key1 == key2
    print("✅ DH round-trip and AES key derivation OK")
