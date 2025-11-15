"""
SecureChat server (complete implementation for assignment).

Features implemented:
- Certificate exchange & verification (client -> server, server -> client)
- Ephemeral DH for encrypted registration/login (Ktemp)
- Registration: server salts and stores pwd_hash = SHA256(salt || password)
- Login: server verifies password using stored salt + SHA256
- Session DH for Ksession derivation (Trunc16(SHA256(shared)))
- Per-message AES-128-CBC encryption (iv + ct) and RSA-PSS signatures over SHA256(seq||ts||ct)
  where seq and ts are encoded as 8-byte big-endian integers and ct is raw ciphertext bytes.
- Replay protection using strictly-increasing seqno
- Append-only transcript and signed SessionReceipt on disconnect
"""

import socket
import json
import struct
import traceback

from app.common.protocol import Hello, ServerHello, Register, Login, DHClient, DHServer, Msg, Receipt
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.storage.db import Database
from app.storage.transcript import Transcript

from app.crypto.pki import load_ca_cert, load_cert_from_pem, verify_cert_chain, cert_fingerprint_hex, cert_cn
from app.crypto.dh import (
    generate_private_key,
    public_key_bytes_b64,
    load_peer_public_key_from_b64,
    compute_shared_secret_bytes,
    derive_aes_key_from_shared_secret,
    dh_parameters_b64
)
from app.crypto.sign import sign_b64, load_private_key, verify_bytes_rsa_pss, load_public_key_from_cert
from app.crypto.aes import aes_encrypt_b64, aes_decrypt_b64

# Config
HOST = "0.0.0.0"
PORT = 5000
CERTS_DIR = "certs"
SERVER_CERT_PATH = "certs/server/server_cert.pem"
SERVER_KEY_PATH  = "certs/server/server_key.pem"
CA_CERT_PATH = f"{CERTS_DIR}/ca_cert.pem"


# -------------------------
# Socket helpers (line-delimited JSON)
# -------------------------
def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj).encode() + b"\n"
    sock.sendall(data)


def recv_json(sock: socket.socket):
    # Read until newline
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            # Note: rest is discarded (simple single-message frame)
            try:
                return json.loads(line.decode())
            except Exception as e:
                raise ValueError(f"Invalid JSON received: {e}")


# -------------------------
# Low-level helpers
# -------------------------
def make_digest_bytes(seqno: int, ts_ms: int, ct_bytes: bytes) -> bytes:
    """Construct digest input as: 8-byte big-endian seq || 8-byte big-endian ts || ct_bytes"""
    seq_b = struct.pack(">Q", seqno)
    ts_b = struct.pack(">Q", ts_ms)
    return seq_b + ts_b + ct_bytes


def parse_ct_field(ct_field: str):
    """ct_field expected as 'iv_b64:ct_b64' -> returns (iv_bytes, ct_bytes)"""
    try:
        iv_b64, ct_b64 = ct_field.split(":")
        return b64d(iv_b64), b64d(ct_b64)
    except Exception as e:
        raise ValueError("Invalid ciphertext field format. Expected 'iv_b64:ct_b64'") from e


# -------------------------
# Server main
# -------------------------
def main():
    print("[SERVER] Starting SecureChat server...")
    db = Database()
    transcript = Transcript("server_transcript.log")

    # Load PKI
    CA = load_ca_cert(CA_CERT_PATH)
    server_cert = load_cert_from_pem(SERVER_CERT_PATH)
    server_priv = load_private_key(SERVER_KEY_PATH)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print(f"[SERVER] Listening on {HOST}:{PORT}")

    conn, addr = sock.accept()
    print(f"[SERVER] Connection from {addr}")
    transcript.append(f"Client connected from {addr}")

    try:
        # -------------------------
        # 1) Receive Hello with client cert PEM
        # -------------------------
        obj = recv_json(conn)
        # Expect Hello JSON plus "client_cert_pem" field
        if "client_cert_pem" not in obj:
            send_json(conn, {"error": "BAD CERT", "reason": "missing client_cert_pem"})
            conn.close()
            return

        client_cert_pem = obj["client_cert_pem"].encode()
        client_cert = load_cert_from_pem(client_cert_pem)
        # Verify client cert with CA
        try:
            verify_cert_chain(client_cert, CA)
        except Exception as e:
            send_json(conn, {"error": "BAD CERT", "reason": str(e)})
            conn.close()
            return

        print("[SERVER] Client certificate verified. CN =", cert_cn(client_cert))
        transcript.append(f"Client cert verified CN={cert_cn(client_cert)} fp={cert_fingerprint_hex(client_cert)}")

        # Send ServerHello with server cert PEM
        print(f"[SERVER] Loading server cert from {SERVER_CERT_PATH}")
        try:
            with open(SERVER_CERT_PATH, "r") as f:
                server_cert_pem_content = f.read()
            print(f"[SERVER] Loaded server cert ({len(server_cert_pem_content)} bytes)")
        except Exception as e:
            print(f"[SERVER] ERROR loading server cert: {e}")
            send_json(conn, {"error": "CERT_ERROR", "reason": str(e)})
            conn.close()
            return

        server_hello = ServerHello().model_dump()
        server_hello["server_cert_pem"] = server_cert_pem_content
        print(f"[SERVER] Sending ServerHello")
        send_json(conn, server_hello)
        print(f"[SERVER] Sent ServerHello")

        # -------------------------
        # 2) Ephemeral DH for registration/login (temp AES Ktmp)
        # Protocol:
        # - Server generates DH params and sends them to client (so both use same params)
        # - Client generates priv key using those params, sends pub
        # - Server generates its priv key using same params (cached), sends pub
        # - Both compute shared secret
        # -------------------------
        server_priv = generate_private_key()
        server_params_b64 = dh_parameters_b64(server_priv)
        print(f"[SERVER] Generated DH params (b64 len={len(server_params_b64)})")
        # Send params first so client can use same ones
        send_json(conn, {"server_params_b64": server_params_b64})
        print(f"[SERVER] Sent DH params to client")

        # Now wait for client's public key
        obj = recv_json(conn)
        dhc = DHClient(**obj)
        print(f"[SERVER] Received DHClient: username={dhc.username}, pubkey_b64 length={len(dhc.client_pubkey_b64)}")
        try:
            client_pub = load_peer_public_key_from_b64(dhc.client_pubkey_b64)
            print(f"[SERVER] Loaded client pub key")
        except Exception as e:
            print(f"[SERVER] Failed to load client pub: {e}")
            raise

        # Generate server's public key
        server_pub_b64 = public_key_bytes_b64(server_priv)
        print(f"[SERVER] Server pub b64 length: {len(server_pub_b64)}")
        # send server's DH pub
        send_json(conn, {"server_pubkey_b64": server_pub_b64})
        print(f"[SERVER] Sent server pub to client")

        try:
            shared = compute_shared_secret_bytes(server_priv, client_pub)
            print(f"[SERVER] Computed shared secret (len={len(shared)})")
        except Exception as e:
            print(f"[SERVER] ERROR computing shared secret: {e}")
            raise
        Ktmp = derive_aes_key_from_shared_secret(shared)

        # Now expect encrypted register or login
        enc_obj = recv_json(conn)
        if enc_obj.get("type") == "register_encrypted":
            iv_b64 = enc_obj["iv_b64"]
            ct_b64 = enc_obj["ct_b64"]
            plaintext = aes_decrypt_b64(Ktmp, iv_b64, ct_b64)
            payload = json.loads(plaintext.decode())
            email = payload["email"]
            username = payload["username"]
            password = payload["password"]  # server will salt+hash
            db.register_user(email, username, password)
            transcript.append(f"Registered user {username}")
            send_json(conn, {"status": "registered"})
        elif enc_obj.get("type") == "login_encrypted":
            iv_b64 = enc_obj["iv_b64"]
            ct_b64 = enc_obj["ct_b64"]
            plaintext = aes_decrypt_b64(Ktmp, iv_b64, ct_b64)
            payload = json.loads(plaintext.decode())
            username = payload["username"]
            password = payload["password"]
            ok = db.authenticate_user(username, password)
            transcript.append(f"Login attempt user={username} ok={ok}")
            send_json(conn, {"status": "ok" if ok else "fail"})
            if not ok:
                conn.close()
                return
        else:
            send_json(conn, {"error": "expected register_encrypted or login_encrypted"})
            conn.close()
            return

        # -------------------------
        # 3) Session DH (fresh) -> derive Ksession and sign server pub with server key
        # Same protocol as ephemeral DH: send params first, then receive client pub, then send server pub
        # -------------------------
        server_session_priv = generate_private_key()
        server_session_params_b64 = dh_parameters_b64(server_session_priv)
        print(f"[SERVER] Generated session DH params (b64 len={len(server_session_params_b64)})")
        send_json(conn, {"server_params_b64": server_session_params_b64})
        print(f"[SERVER] Sent session DH params to client")

        # Wait for client's session public key
        obj = recv_json(conn)
        dhc2 = DHClient(**obj)
        print(f"[SERVER] Received client session pubkey (len={len(dhc2.client_pubkey_b64)})")
        client_session_pub = load_peer_public_key_from_b64(dhc2.client_pubkey_b64)

        # Generate and send server's session public key
        server_session_pub_b64 = public_key_bytes_b64(server_session_priv)
        # sign server session pub to prove identity
        sig_b64 = sign_b64(SERVER_KEY_PATH, server_session_pub_b64.encode())
        send_json(conn, {"server_pubkey_b64": server_session_pub_b64, "signature_b64": sig_b64})
        print(f"[SERVER] Sent session pub and signature to client")

        try:
            shared2 = compute_shared_secret_bytes(server_session_priv, client_session_pub)
            print(f"[SERVER] Computed session shared secret (len={len(shared2)})")
        except Exception as e:
            print(f"[SERVER] ERROR computing session shared secret: {e}")
            raise
        Ksession = derive_aes_key_from_shared_secret(shared2)
        transcript.append("Session key established")

        # -------------------------
        # 4) Messaging loop
        # -------------------------
        last_seq = 0
        first_seq = None
        while True:
            try:
                obj = recv_json(conn)
            except ConnectionError:
                break
            except Exception:
                traceback.print_exc()
                break

            if "type" not in obj:
                # older message format may not include 'type'; assume Msg
                pass

            try:
                msg = Msg(**obj)
            except Exception:
                # tolerate if fields directly present
                msg = Msg(**obj)

            # parse ct -> iv, ct_bytes
            try:
                iv, ct_bytes = parse_ct_field(msg.ciphertext_b64)
            except Exception as e:
                send_json(conn, {"error": "invalid ciphertext format"})
                continue

            # verify signature: compute digest bytes = seq||ts||ct_bytes
            digest_input = make_digest_bytes(msg.seqno, msg.timestamp, ct_bytes)
            # load client's pubkey from certificate we received earlier
            client_pubkey = load_public_key_from_cert(client_cert_pem)
            try:
                verify_bytes_rsa_pss(client_pubkey, digest_input, b64d(msg.sig))
            except Exception:
                # signature fail
                transcript.append(f"SIG FAIL seq={msg.seqno}")
                send_json(conn, {"error": "SIG FAIL"})
                continue

            # replay protection
            if msg.seqno <= last_seq:
                transcript.append(f"REPLAY detected seq={msg.seqno} last={last_seq}")
                send_json(conn, {"error": "REPLAY"})
                continue

            # decrypt
            try:
                plaintext = aes_decrypt_b64(Ksession, b64e(iv), b64e(ct_bytes))
            except Exception:
                transcript.append(f"DECRYPT FAIL seq={msg.seqno}")
                send_json(conn, {"error": "DECRYPT FAIL"})
                continue

            # record transcript line as requested by spec:
            peer_fp = cert_fingerprint_hex(client_cert)
            ct_b64_combined = f"{b64e(iv)}:{b64e(ct_bytes)}"
            entry_line = f"{msg.seqno}|{msg.timestamp}|{ct_b64_combined}|{msg.sig}|{peer_fp}"
            transcript.append(entry_line)

            # update seq counters
            last_seq = msg.seqno
            if first_seq is None:
                first_seq = msg.seqno

            print(f"[SERVER] Received msg seq={msg.seqno} from {msg.sender}: {plaintext.decode(errors='replace')}")
            # send receipt
            send_json(conn, Receipt(msg_id=msg.msg_id).model_dump())

        # session ended — create and sign session receipt
        final_hash = transcript.get_final_hash()
        receipt_sig_b64 = sign_b64(SERVER_KEY_PATH, final_hash.encode())
        receipt = {
            "type": "receipt",
            "peer": "server",
            "first_seq": first_seq or 0,
            "last_seq": last_seq,
            "transcript_sha256": final_hash,
            "sig": receipt_sig_b64,
        }
        with open("server_receipt.json", "w") as f:
            json.dump(receipt, f, indent=2)

        # Optionally send receipt to client
        try:
            send_json(conn, receipt)
        except Exception:
            pass

    finally:
        transcript.append("Client disconnected")
        db.close()
        conn.close()
        sock.close()
        print("[SERVER] Shutdown.")


if __name__ == "__main__":
    main()
