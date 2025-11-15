"""
Signing helpers: RSA sign and verify utilities.

Provides:
- load_private_key(path_or_bytes, password=None) -> private key object
- load_public_key_from_cert(pem_or_path) -> public key object (from certificate)
- sign_bytes_rsa_pss(private_key, message_bytes) -> signature bytes
- verify_bytes_rsa_pss(pubkey, message_bytes, signature_bytes) -> True/raise
- convenience base64 wrappers: sign_b64(...), verify_b64(...)
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from app.common.utils import b64e, b64d
from typing import Union


def load_private_key(pem: Union[bytes, str], password: bytes = None):
    """Load a private key from PEM bytes or path."""
    if isinstance(pem, str):
        with open(pem, "rb") as f:
            pemb = f.read()
    else:
        pemb = pem
    return serialization.load_pem_private_key(pemb, password=password)


def load_public_key_from_cert(cert_pem: Union[bytes, str]):
    """Extract public key object from a certificate PEM (bytes or path)."""
    if isinstance(cert_pem, str):
        with open(cert_pem, "rb") as f:
            certb = f.read()
    else:
        certb = cert_pem
    cert = x509.load_pem_x509_certificate(certb)
    return cert.public_key()


def sign_bytes_rsa_pss(priv_key, message: bytes) -> bytes:
    """
    Sign message bytes using RSA-PSS with SHA-256.
    priv_key is a private key object (from load_private_key).
    """
    sig = priv_key.sign(
        message,
        asympadding.PSS(
            mgf=asympadding.MGF1(hashes.SHA256()),
            salt_length=asympadding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig


def verify_bytes_rsa_pss(pub_key, message: bytes, signature: bytes) -> bool:
    """
    Verify RSA-PSS signature. Raises an exception on failure.
    Return True on success.
    """
    pub_key.verify(
        signature,
        message,
        asympadding.PSS(
            mgf=asympadding.MGF1(hashes.SHA256()),
            salt_length=asympadding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return True


# ------------- base64 convenience -------------
def sign_b64(priv_key_pem_or_path: Union[bytes, str], message: bytes) -> str:
    priv = load_private_key(priv_key_pem_or_path)
    sig = sign_bytes_rsa_pss(priv, message)
    return b64e(sig)


def verify_b64(pub_cert_pem_or_path: Union[bytes, str], message: bytes, sig_b64: str) -> bool:
    pub = load_public_key_from_cert(pub_cert_pem_or_path)
    sig = b64d(sig_b64)
    return verify_bytes_rsa_pss(pub, message, sig)


# ------------------ Test harness ------------------
if __name__ == "__main__":
    # quick test: sign and verify using keys in certs/ if present
    import os
    base = os.path.join(os.getcwd(), "certs")
    priv_path = os.path.join(base, "server_key.pem")
    cert_path = os.path.join(base, "server_cert.pem")
    if os.path.exists(priv_path) and os.path.exists(cert_path):
        priv = load_private_key(priv_path)
        msg = b"Hello, this is a test message"
        sig = sign_bytes_rsa_pss(priv, msg)
        print("SIG b64:", b64e(sig))
        pub = load_public_key_from_cert(cert_path)
        ok = verify_bytes_rsa_pss(pub, msg, sig)
        print("Verified:", ok)
    else:
        print("No server_key.pem or server_cert.pem found in certs/ — place files to test.")
