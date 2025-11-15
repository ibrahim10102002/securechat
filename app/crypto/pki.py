"""
PKI helpers: certificate loading, verification (chain and validity checks), CN check, fingerprint.

Functions:
- load_cert_from_pem(pem_bytes_or_path) -> x509.Certificate
- verify_cert_chain(cert, ca_cert) -> raises Exception on failure or returns True
- cert_valid_dates(cert) -> tuple(not_before, not_after)
- cert_cn(cert) -> common name string
- cert_fingerprint_hex(cert) -> sha256 fingerprint hex
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from datetime import datetime
from cryptography.exceptions import InvalidSignature


def load_cert_from_pem(pem: bytes or str) -> x509.Certificate:
    """
    Accepts either bytes (PEM) or a file path string, returns x509.Certificate.
    """
    if isinstance(pem, str):
        # treat as path
        with open(pem, "rb") as f:
            pem_bytes = f.read()
    else:
        pem_bytes = pem
    return x509.load_pem_x509_certificate(pem_bytes)


def load_ca_cert(ca_pem: bytes or str) -> x509.Certificate:
    return load_cert_from_pem(ca_pem)


def verify_cert_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify that 'cert' was signed by 'ca_cert'.
    This checks the signature on 'cert' using the CA public key and also checks validity dates.
    Raises an Exception on failure.
    """
    # 1) Check validity period
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise ValueError("Certificate is not valid at current time (expired or not yet valid)")

    # 2) Verify signature: verify cert.signature using ca_cert.public_key()
    pub = ca_cert.public_key()
    try:
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            # signature and hash algorithm are taken from cert.signature_algorithm_oid,
            # but cryptography needs the right padding/hash. We infer using cert.signature_hash_algorithm
            padding=cert.signature_hash_algorithm._padding if hasattr(cert.signature_hash_algorithm, "_padding") else None
        )
    except Exception:
        # fallback manual verification using public_key.verify with typical parameters
        # We'll attempt to verify using the public key verify with reasonable defaults.
        try:
            ca_pub = ca_cert.public_key()
            # Use public_key.verify with PKCS1v15 and cert.signature_hash_algorithm
            from cryptography.hazmat.primitives.asymmetric import padding as asympadding
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                asympadding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            raise InvalidSignature(f"Certificate signature verification failed: {e}")

    return True


def cert_cn(cert: x509.Certificate) -> str:
    """Return the Subject Common Name (CN) if present, else empty string."""
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if names:
            return names[0].value
    except Exception:
        pass
    return ""


def cert_valid_dates(cert: x509.Certificate):
    """Return (not_valid_before, not_valid_after) datetimes."""
    return cert.not_valid_before, cert.not_valid_after


def cert_fingerprint_hex(cert: x509.Certificate) -> str:
    """Return SHA-256 fingerprint of certificate as hex string."""
    fp = cert.fingerprint(hashes.SHA256())
    return fp.hex()


# ------------------ Test harness ------------------
if __name__ == "__main__":
    # quick smoke test using cert files if present in certs/
    import os
    base = os.path.join(os.getcwd(), "certs")
    ca_path = os.path.join(base, "ca_cert.pem")
    server_path = os.path.join(base, "server_cert.pem")
    if os.path.exists(ca_path) and os.path.exists(server_path):
        ca = load_ca_cert(ca_path)
        srv = load_cert_from_pem(server_path)
        print("CA CN:", cert_cn(ca))
        print("Server CN:", cert_cn(srv))
        print("Server valid from/to:", cert_valid_dates(srv))
        print("Fingerprint:", cert_fingerprint_hex(srv))
        try:
            ok = verify_cert_chain(srv, ca)
            print("Chain verification:", ok)
        except Exception as e:
            print("Chain verification failed:", e)
    else:
        print("No cert files found in certs/ — place ca_cert.pem and server_cert.pem to test.")
