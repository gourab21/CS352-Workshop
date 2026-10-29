"""
storage.py
===========
User registry and per-user secure key storage.

Layout on disk (all under BASE_DIR, default: project root):

    users.csv                       <- master registry (one row per user)
    users/<username>/public_key.pem        <- cleartext (public keys are not secret)
    users/<username>/private_key.enc       <- Fernet-encrypted private key PEM

The private key is NEVER written to disk in cleartext. It is encrypted with
a key derived from the user's login password via PBKDF2-HMAC-SHA256, using a
salt stored only in users.csv. Password verification uses a SEPARATE
PBKDF2 derivation (different salt) from the one used to derive the
key-encryption key, so the value checked at login time is not the same
secret that protects the private key.

This module does no RSA/AES *cryptographic protocol* work itself (that is
crypto_core.py) — it only manages identities, credentials, and secure
key-at-rest storage.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa

from core import crypto_core as cc

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_DIR = os.path.join(BASE_DIR, "users")
REGISTRY_CSV = os.path.join(BASE_DIR, "users.csv")

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16

CSV_FIELDS = ["username", "auth_salt", "auth_hash", "kek_salt", "created_at"]


class StorageError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Registry (CSV) helpers
# --------------------------------------------------------------------------- #

def _ensure_registry() -> None:
    os.makedirs(USERS_DIR, exist_ok=True)
    if not os.path.exists(REGISTRY_CSV):
        with open(REGISTRY_CSV, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_FIELDS).writeheader()


def _read_registry() -> dict[str, dict]:
    _ensure_registry()
    rows: dict[str, dict] = {}
    with open(REGISTRY_CSV, "r", newline="") as f:
        for row in csv.DictReader(f):
            rows[row["username"]] = row
    return rows


def _append_registry(row: dict) -> None:
    _ensure_registry()
    with open(REGISTRY_CSV, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=CSV_FIELDS).writerow(row)


def user_exists(username: str) -> bool:
    return username in _read_registry()


def list_users(exclude: Optional[str] = None) -> list[str]:
    names = sorted(_read_registry().keys())
    if exclude:
        names = [n for n in names if n != exclude]
    return names


# --------------------------------------------------------------------------- #
# Password derivation
# --------------------------------------------------------------------------- #

def _pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, dklen=32)


def _fernet_key_from_kek(kek: bytes) -> bytes:
    return base64.urlsafe_b64encode(kek)


# --------------------------------------------------------------------------- #
# User creation / authentication
# --------------------------------------------------------------------------- #

def _user_dir(username: str) -> str:
    return os.path.join(USERS_DIR, username)


def create_user(username: str, password: str) -> None:
    """
    Register a new user:
      1. generate an RSA keypair for them (large key size, see crypto_core),
      2. encrypt the private key at rest with a password-derived key,
      3. store a (separate) salted password hash for login checks,
      4. record everything in the master registry.
    """
    if not username or not password:
        raise StorageError("Username and password are required.")
    if user_exists(username):
        raise StorageError(f"User '{username}' already exists.")

    user_dir = _user_dir(username)
    os.makedirs(user_dir, exist_ok=False)

    # RSA keypair for this user (3072-bit, see crypto_core.RSA_KEY_SIZE_BITS)
    priv, pub = cc.generate_rsa_keypair()

    # Two independent PBKDF2 derivations from the same password:
    auth_salt = os.urandom(SALT_SIZE)
    auth_hash = _pbkdf2(password, auth_salt)

    kek_salt = os.urandom(SALT_SIZE)
    kek = _pbkdf2(password, kek_salt)

    # Public key: cleartext PEM (this is what gets "exchanged through a
    # trusted channel" with other users).
    with open(os.path.join(user_dir, "public_key.pem"), "wb") as f:
        f.write(cc.public_key_to_pem(pub))

    # Private key: encrypted at rest with Fernet under the password-derived KEK.
    priv_pem = cc.private_key_to_pem(priv)
    fernet = Fernet(_fernet_key_from_kek(kek))
    enc_priv = fernet.encrypt(priv_pem)
    priv_path = os.path.join(user_dir, "private_key.enc")
    with open(priv_path, "wb") as f:
        f.write(enc_priv)
    os.chmod(priv_path, 0o600)

    _append_registry({
        "username": username,
        "auth_salt": auth_salt.hex(),
        "auth_hash": auth_hash.hex(),
        "kek_salt": kek_salt.hex(),
        "created_at": str(int(time.time())),
    })


def authenticate_user(username: str, password: str) -> bool:
    rows = _read_registry()
    row = rows.get(username)
    if row is None:
        return False
    auth_salt = bytes.fromhex(row["auth_salt"])
    expected = bytes.fromhex(row["auth_hash"])
    candidate = _pbkdf2(password, auth_salt)
    return hmac.compare_digest(expected, candidate)


def load_public_key(username: str) -> rsa.RSAPublicKey:
    path = os.path.join(_user_dir(username), "public_key.pem")
    if not os.path.exists(path):
        raise StorageError(f"No public key on file for '{username}'.")
    return cc.load_public_key(path)


def load_private_key(username: str, password: str) -> rsa.RSAPrivateKey:
    """
    Decrypt and return the user's RSA private key.
    Requires the correct login password (used to re-derive the KEK) —
    this is the "unlock" step after a successful login.
    """
    rows = _read_registry()
    row = rows.get(username)
    if row is None:
        raise StorageError(f"Unknown user '{username}'.")
    kek_salt = bytes.fromhex(row["kek_salt"])
    kek = _pbkdf2(password, kek_salt)
    fernet = Fernet(_fernet_key_from_kek(kek))

    enc_path = os.path.join(_user_dir(username), "private_key.enc")
    with open(enc_path, "rb") as f:
        enc_priv = f.read()
    try:
        priv_pem = fernet.decrypt(enc_priv)
    except InvalidToken as exc:
        raise StorageError("Could not unlock private key — wrong password?") from exc
    return cc.private_key_from_pem(priv_pem)
