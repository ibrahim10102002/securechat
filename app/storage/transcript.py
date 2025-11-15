"""
Append-only transcript with hash chaining.

Each entry appended to the transcript is stored as:

SEQ || TIMESTAMP || EVENT || HASH(prev_entry) → hashed to produce new state

This provides:
- tamper detection
- ordering
- end-of-session transcript hash

Public API:
- Transcript(path)
- append(event: str) -> dict
- get_final_hash() -> str
"""

import os
import json
import hashlib
from app.common.utils import now_ms, sha256_hex


class Transcript:
    def __init__(self, path="transcript.log"):
        self.path = path
        self.state_hash = "0" * 64  # initial hash

        if os.path.exists(self.path):
            self._load_last_hash()

    def _load_last_hash(self):
        last = None
        with open(self.path, "r") as f:
            for line in f:
                last = line.strip()
        if last:
            try:
                obj = json.loads(last)
                self.state_hash = obj["entry_hash"]
            except:
                pass

    def append(self, event: str):
        """
        Append a new transcript entry.
        event: string describing what happened
        Returns the JSON entry as dict
        """
        ts = now_ms()
        data = f"{self.state_hash}|{ts}|{event}"
        new_hash = sha256_hex(data.encode())

        entry = {
            "prev_hash": self.state_hash,
            "timestamp": ts,
            "event": event,
            "entry_hash": new_hash,
        }

        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        self.state_hash = new_hash
        return entry

    def get_final_hash(self):
        """Return the final transcript hash."""
        return self.state_hash


# ---------- test ----------
if __name__ == "__main__":
    t = Transcript("test_transcript.log")
    t.append("Client connected")
    t.append("Performed DH key exchange")
    t.append("Message sent: hello world")
    print("Final hash:", t.get_final_hash())
