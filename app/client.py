"""
SecureChat client (complete implementation for assignment).

Client flow:
- Connect to server and send Hello including client_cert PEM
- Receive ServerHello (including server cert PEM)
- Verify server cert using CA
- Ephemeral DH for registration/login (derive Ktmp and send encrypted payload)
- Session DH for Ksession (verify server signature on server session pub)
- Send messages: seqno, ts, ciphertext (iv:ct), sig over SHA256(seq||ts||ct)
- Receive receipts and final session receipt
"""

import socket
import json
import struct
import time
import getpass

from app.common.protocol import Hello, ServerHello, Register, Login, DHClient, DHServer, Msg, Receipt
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.pki import load_ca_cert, load_cert_from_pem, verify_cert_chain, cert_cn
from app.crypto.dh import (
    generate_private_key,
    public_key_bytes_b64,
    load_peer_public_key_from_b64,
    compute_shared_secret_bytes,
    derive_aes_key_from_shared_secret,
    load_dh_parameters_from_b64,
    generate_private_key_with_params
)
from app.crypto.aes import aes_encrypt_b64, aes_decrypt_b64
from app.crypto.sign import load_private_key, sign_bytes_rsa_pss, verify_bytes_rsa_pss, load_public_key_from_cert, sign_b64, verify_b64

# Config
SERVER_ADDR = ("127.0.0.1", 5000)
CERTS_DIR = "certs"
CLIENT_CERT_PATH = "certs/client/client_cert.pem"
CLIENT_KEY_PATH = "certs/client/client_key.pem"
CA_CERT_PATH = f"{CERTS_DIR}/ca_cert.pem"


# -------------------------
# Socket helpers (line-delimited JSON)
# -------------------------
def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj).encode() + b"\n"
    sock.sendall(data)


def recv_json(sock: socket.socket):
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            try:
                return json.loads(line.decode())
            except Exception as e:
                raise ValueError(f"Invalid JSON received: {e}")


# -------------------------
# Low-level helpers
# -------------------------
def make_digest_bytes(seqno: int, ts_ms: int, ct_bytes: bytes) -> bytes:
    return struct.pack(">Q", seqno) + struct.pack(">Q", ts_ms) + ct_bytes


def pack_ct(iv_bytes: bytes, ct_bytes: bytes) -> str:
    return f"{b64e(iv_bytes)}:{b64e(ct_bytes)}"


def parse_ct_field(ct_field: str):
    iv_b64, ct_b64 = ct_field.split(":")
    return b64d(iv_b64), b64d(ct_b64)


# -------------------------
# Client main
# -------------------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SERVER_ADDR)
    print(f"[CLIENT] Connected to {SERVER_ADDR}")

    # Load CA and client cert
    CA = load_ca_cert(CA_CERT_PATH)
    client_cert_pem = open(CLIENT_CERT_PATH, "r").read()
    client_key = load_private_key(CLIENT_KEY_PATH)

    # derive username from client certificate CN (use cert CN as default username)
    client_cert = load_cert_from_pem(client_cert_pem.encode())
    username = cert_cn(client_cert) or "client"

    # -------------------------
    # 1) Send Hello + client cert PEM
    # -------------------------
    hello = Hello(username=username).model_dump()
    hello["client_cert_pem"] = client_cert_pem
    send_json(sock, hello)

    # Receive ServerHello (with server cert)
    server_hello = recv_json(sock)
    if "server_cert_pem" not in server_hello:
        print("[CLIENT] Server did not provide certificate. Aborting.")
        sock.close()
        return

    server_cert_pem = server_hello["server_cert_pem"].encode()
    server_cert = load_cert_from_pem(server_cert_pem)
    # Verify server cert using CA
    try:
        verify_cert_chain(server_cert, CA)
    except Exception as e:
        print("[CLIENT] Server certificate verification failed:", e)
        sock.close()
        return

    print("[CLIENT] Server certificate verified. CN =", cert_cn(server_cert))

    # -------------------------
    # 2) Ephemeral DH for registration/login (Ktmp)
    # -------------------------
    # First, receive server's DH parameters
    params_msg = recv_json(sock)
    server_params_b64 = params_msg["server_params_b64"]
    print(f"[CLIENT] Received server DH params (b64 len={len(server_params_b64)})")
    
    # Load those parameters so both sides use identical params
    server_params = load_dh_parameters_from_b64(server_params_b64)
    print(f"[CLIENT] Loaded server DH parameters")
    
    # Generate client ephemeral DH using server's parameters
    client_temp_priv = generate_private_key_with_params(server_params)
    print(f"[CLIENT] Generated client private key using server's parameters")
    client_temp_pub_b64 = public_key_bytes_b64(client_temp_priv)
    send_json(sock, {
    "username": username,
    "client_pubkey_b64": client_temp_pub_b64
    })

    # receive server temp pub
    resp = recv_json(sock)
    server_temp_pub_b64 = resp["server_pubkey_b64"]
    server_temp_pub = load_peer_public_key_from_b64(server_temp_pub_b64)

    shared_temp = compute_shared_secret_bytes(client_temp_priv, server_temp_pub)
    Ktmp = derive_aes_key_from_shared_secret(shared_temp)

    # Ask user to register or login
    choice = input("Do you want to (r)egister or (l)ogin? [r/l]: ").strip().lower()
    username = input("username: ").strip()
    password = getpass.getpass("password: ")

    if choice == "r":
        payload = {"email": f"{username}@example.com", "username": username, "password": password}
        enc = aes_encrypt_b64(Ktmp, json.dumps(payload).encode())
        send_json(sock, {"type": "register_encrypted", "iv_b64": enc["iv_b64"], "ct_b64": enc["ct_b64"]})
        resp = recv_json(sock)
        print("[CLIENT] Register response:", resp)
        if resp.get("status") != "registered":
            print("[CLIENT] Registration failed.")
            sock.close()
            return
    else:
        payload = {"username": username, "password": password}
        enc = aes_encrypt_b64(Ktmp, json.dumps(payload).encode())
        send_json(sock, {"type": "login_encrypted", "iv_b64": enc["iv_b64"], "ct_b64": enc["ct_b64"]})
        resp = recv_json(sock)
        print("[CLIENT] Login response:", resp)
        if resp.get("status") != "ok":
            print("[CLIENT] Login failed.")
            sock.close()
            return

    # -------------------------
    # 3) Session DH (fresh) and verify server signature
    # -------------------------
    # First, receive server's session DH parameters
    session_params_msg = recv_json(sock)
    server_session_params_b64 = session_params_msg["server_params_b64"]
    print(f"[CLIENT] Received server session DH params (b64 len={len(server_session_params_b64)})")
    
    # Load those parameters so both sides use identical params
    server_session_params = load_dh_parameters_from_b64(server_session_params_b64)
    print(f"[CLIENT] Loaded server session DH parameters")
    
    # Generate client session DH using server's parameters
    client_session_priv = generate_private_key_with_params(server_session_params)
    print(f"[CLIENT] Generated client session private key using server's parameters")
    client_session_pub_b64 = public_key_bytes_b64(client_session_priv)
    send_json(sock, {
    "username": username,
    "client_pubkey_b64": client_session_pub_b64
    })

    resp = recv_json(sock)
    server_session_pub_b64 = resp["server_pubkey_b64"]
    signature_b64 = resp["signature_b64"]

    # verify signature over server_session_pub_b64 using server_cert
    try:
        # verify signature over server session pub using server certificate provided
        verify_b64(server_cert_pem, server_session_pub_b64.encode(), signature_b64)
    except Exception:
        # fallback: directly verify using loaded server public key
        server_pubkey = load_public_key_from_cert(server_cert_pem)
        try:
            verify_bytes_rsa_pss(server_pubkey, server_session_pub_b64.encode(), b64d(signature_b64))
        except Exception as e2:
            print("[CLIENT] Server session pub verification failed:", e2)
            sock.close()
            return

    server_session_pub = load_peer_public_key_from_b64(server_session_pub_b64)
    shared_session = compute_shared_secret_bytes(client_session_priv, server_session_pub)
    Ksession = derive_aes_key_from_shared_secret(shared_session)
    print("[CLIENT] Session key established.")

    # -------------------------
    # 4) Messaging loop (seqno, ts, signature)
    # -------------------------
    seqno = 0
    while True:
        text = input("You: ")
        if text.strip().lower() in ("quit", "exit"):
            break
        seqno += 1
        ts = now_ms()
        # encrypt
        enc = aes_encrypt_b64(Ksession, text.encode())
        iv_b64 = enc["iv_b64"]
        ct_b64 = enc["ct_b64"]
        ct_combined = f"{iv_b64}:{ct_b64}"
        # compute digest bytes: seq||ts||ct_bytes
        iv_bytes, ct_bytes = b64d(iv_b64), b64d(ct_b64)
        digest_input = make_digest_bytes(seqno, ts, ct_bytes)
        # sign using client private key
        sig = sign_bytes_rsa_pss(client_key, digest_input)
        sig_b64 = b64e(sig)

        message = {
            "sender": username,
            "recipient": "server",
            "ciphertext_b64": ct_combined,
            "timestamp": ts,
            "msg_id": str(ts),
            "seqno": seqno,
            "sig": sig_b64,
            "type": "msg"
        }
        send_json(sock, message)

        # await receipt
        rec = recv_json(sock)
        print("[CLIENT] Receipt:", rec)

    # After exiting loop, wait for final receipt if server sends it
    try:
        final = recv_json(sock)
        if final.get("type") == "receipt":
            print("[CLIENT] Received session receipt:", final)
    except Exception:
        pass

    sock.close()
    print("[CLIENT] Disconnected.")


if __name__ == "__main__":
    main()
