from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os, sys

def generate_user_cert(username):
    ca_cert = x509.load_pem_x509_certificate(open("certs/ca_cert.pem", "rb").read())
    ca_key = serialization.load_pem_private_key(open("certs/ca_key.pem", "rb").read(), password=None)

    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat User"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    os.makedirs(f"certs/{username}", exist_ok=True)

    with open(f"certs/{username}/{username}_key.pem", "wb") as f:
        f.write(user_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(f"certs/{username}/{username}_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"=> Certificate and key generated for user '{username}' in certs/{username}/")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scripts/gen_cert.py <username>")
        sys.exit(1)
    generate_user_cert(sys.argv[1])
