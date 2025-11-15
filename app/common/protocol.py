"""
Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.
These define the structure of all messages exchanged between client and server.
"""

from pydantic import BaseModel, Field
from typing import Optional


# ---------------------------------------
# ! Handshake messages
# ---------------------------------------
class Hello(BaseModel):
    """Initial message from client to server."""
    username: str
    client_version: str = Field(default="1.0")


class ServerHello(BaseModel):
    """Server's acknowledgment message to client."""
    server_version: str = Field(default="1.0")
    motd: str = Field(default="Welcome to SecureChat!")


# ---------------------------------------
# ! Registration and Login
# ---------------------------------------
class Register(BaseModel):
    """Client registration request."""
    email: str
    username: str
    password_hash: str   # SHA256(password + salt)
    salt_b64: str        # Base64-encoded salt


class Login(BaseModel):
    """Client login request."""
    username: str
    password_hash: str   # SHA256(password + salt)


# ---------------------------------------
# ! Diffie–Hellman key exchange
# ---------------------------------------
class DHClient(BaseModel):
    """Client sends DH public key and cert."""
    username: str
    client_pubkey_b64: str
    client_cert_b64: Optional[str] = None  # Optional X.509 certificate


class DHServer(BaseModel):
    """Server sends DH public key and signature."""
    server_pubkey_b64: str
    signature_b64: str


# ---------------------------------------
# ! Messaging protocol
# ---------------------------------------
class Msg(BaseModel):
    """Encrypted chat message."""
    sender: str
    recipient: str
    ciphertext_b64: str
    timestamp: int
    msg_id: Optional[str] = None
    seqno: int = 0  # sequence number for replay protection
    sig: str = ""  # base64-encoded RSA-PSS signature
    type: str = Field(default="msg")  # message type


class Receipt(BaseModel):
    """Acknowledgement for received message."""
    msg_id: str
    status: str = Field(default="delivered")  # could be 'read', 'delivered', etc.
    type: str = Field(default="receipt")  # receipt type


# ---------------------------------------
# ! Optional: Testing helper
# ---------------------------------------
if __name__ == "__main__":
    print("🔍 Testing Pydantic models...\n")

    h = Hello(username="alice")
    print("Hello:", h.model_dump())

    r = Register(
        email="alice@example.com",
        username="alice",
        password_hash="aabbccddeeff...",
        salt_b64="U29tZUJhc2U2NFNhbHQ=",
    )
    print("Register:", r.model_dump())

    m = Msg(
        sender="alice",
        recipient="bob",
        ciphertext_b64="QmFzZTY0RW5jcnlwdGVkTWVzc2FnZQ==",
        timestamp=1731400212123,
    )
    print("Msg:", m.model_dump())
