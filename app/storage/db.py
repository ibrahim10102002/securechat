"""
Database layer for SecureChat.
Handles PostgreSQL connection, user registration, and authentication.
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from app.common.utils import generate_salt, hash_password, verify_password
import psycopg2
from app.common.utils import sha256_hex, b64e
from os import environ

DB_URL = environ.get("DATABASE_URL", "postgresql://postgres:password@localhost/securechat")

def get_conn():
    return psycopg2.connect(DB_URL)

def create_user(username: str, email: str, password: str):
    salt = b64e(password.encode())[:16]  # simple salt for demo
    pwd_hash = sha256_hex(salt + password.encode())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, email, salt, pwd_hash) VALUES (%s,%s,%s,%s) RETURNING id",
                (username, email, salt, pwd_hash)
            )
            return cur.fetchone()[0]

def get_user_by_username(username: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, salt, pwd_hash FROM users WHERE username=%s", (username,))
            return cur.fetchone()

load_dotenv()


class Database:
    def __init__(self):
        try:
            self.conn = psycopg2.connect(
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                database=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASS"),
                cursor_factory=RealDictCursor
            )
            self.cursor = self.conn.cursor()
            print("=> Connected to PostgreSQL successfully!")
        except Exception as e:
            print("=> Database connection failed:", e)
            self.conn = None
            self.cursor = None

    def close(self):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
            print("=> Database connection closed.")

    # -------------------------------
    # User Registration
    # -------------------------------
    def register_user(self, email: str, username: str, password: str):
        """Register a new user with salted password hash."""
        try:
            salt = generate_salt()
            pwd_hash = hash_password(password, salt)

            query = """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
            RETURNING id;
            """
            self.cursor.execute(query, (email, username, salt, pwd_hash))
            self.conn.commit()
            user_id = self.cursor.fetchone()["id"]
            print(f"=> User '{username}' registered successfully with id={user_id}.")
            return user_id

        except Exception as e:
            self.conn.rollback()
            print("=> Registration failed:", e)
            return None

    # -------------------------------
    # User Authentication
    # -------------------------------
    def authenticate_user(self, username: str, password_attempt: str) -> bool:
        """Verify if the given credentials are valid."""
        try:
            self.cursor.execute(
                "SELECT salt, pwd_hash FROM users WHERE username = %s;", (username,)
            )
            user = self.cursor.fetchone()
            if not user:
                print("=> No such user.")
                return False

            salt, stored_hash = user["salt"], user["pwd_hash"]

            if verify_password(stored_hash, password_attempt, salt):
                print(f"=> Authentication successful for user '{username}'.")
                return True
            else:
                print("=> Invalid password.")
                return False

        except Exception as e:
            print("=> Authentication error:", e)
            return False


# -------------------------------
# Test harness (for manual testing)
# -------------------------------
if __name__ == "__main__":
    db = Database()
    if db.conn:

        # --- Register a new user ---
        db.register_user("secondtest@example.com", "bob", "secondmypassword123")

        # --- Authenticate a user ---
        db.authenticate_user("bob", "secondmypassword123")

        db.close()
