"""
crypto_core.py
================
Pure cryptographic functions for the secure exam-paper exchange system.
Every function here maps directly onto a step in the sequence diagram:

    Phase 1 (Session Key Exchange, once per session)
        K        <- generate_session_key()
        EncK     <- rsa_oaep_encrypt(Pub_R, K)
        Sig1     <- rsa_pss_sign(Pr_S, pack_session_payload(sid, EncK))
        ...      verify_signature(Pub_S, Sig1, payload)
        K        <- rsa_oaep_decrypt(Pr_R, EncK)

    Phase 2 (File Transfer, repeatable i = 1..n)
        N_i          <- generate_nonce()
        (C_i, T_i)   <- aes_gcm_encrypt(K, N_i, M_i, aad)
        P_i          <- pack_file_payload(sid, i, N_i, C_i, T_i, metadata)
        Sig_i        <- rsa_pss_sign(Pr_S, P_i)
        ...          verify_signature(Pub_S, Sig_i, P_i)
        M_i          <- aes_gcm_decrypt(K, N_i, C_i, T_i, aad)

No file I/O, no networking, no user interaction lives in this module —
it is deliberately a library of small, testable, single-purpose functions.
"""

from __future__ import annotations

import json
import os
import struct
import uuid
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Constants (requirement: "use large key size")
# --------------------------------------------------------------------------- #
RSA_KEY_SIZE_BITS = 3072          # large RSA modulus (NIST-recommended >= 2048;
                                   # we use 3072 for comfortable long-term margin)
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_SIZE_BYTES = 32           # AES-256
GCM_NONCE_SIZE_BYTES = 12         # 96-bit nonce, standard for AES-GCM


class CryptoError(Exception):
    """Raised for any failure that must NOT release plaintext (bad sig, bad tag, etc.)."""


# --------------------------------------------------------------------------- #
# 1. RSA key generation / (de)serialization
# --------------------------------------------------------------------------- #

def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a fresh RSA keypair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE_BITS,
    )
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> bytes:
    """Serialize a private key to PEM. If `password` is given, the PEM is encrypted."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def private_key_from_pem(pem_bytes: bytes, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=password)


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(pem_bytes: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem_bytes)


def save_keypair(private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey,
                  priv_path: str, pub_path: str, password: Optional[bytes] = None) -> None:
    """Persist a keypair to disk as PEM files (0600 permissions on the private key)."""
    with open(priv_path, "wb") as f:
        f.write(private_key_to_pem(private_key, password=password))
    os.chmod(priv_path, 0o600)
    with open(pub_path, "wb") as f:
        f.write(public_key_to_pem(public_key))


def load_private_key(priv_path: str, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    with open(priv_path, "rb") as f:
        return private_key_from_pem(f.read(), password=password)


def load_public_key(pub_path: str) -> rsa.RSAPublicKey:
    with open(pub_path, "rb") as f:
        return public_key_from_pem(f.read())


# --------------------------------------------------------------------------- #
# 2. Randomness helpers: session id, session key K, nonce N_i
# --------------------------------------------------------------------------- #

def generate_session_id() -> str:
    """sid: a fresh random session identifier."""
    return uuid.uuid4().hex


def generate_session_key() -> bytes:
    """K: a fresh random 256-bit AES session key."""
    return os.urandom(AES_KEY_SIZE_BYTES)


def generate_nonce() -> bytes:
    """N_i: a fresh random 96-bit GCM nonce. Call once per AES-GCM encryption."""
    return os.urandom(GCM_NONCE_SIZE_BYTES)


# --------------------------------------------------------------------------- #
# 3. RSA-OAEP(SHA-256): wrap/unwrap the AES session key K
# --------------------------------------------------------------------------- #

def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    """EncK <- OAEP_SHA256(Pub, K)"""
    return public_key.encrypt(data, _oaep_padding())


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """K <- OAEP_SHA256^-1(Pr, EncK). Raises CryptoError on failure (never leaks plaintext)."""
    try:
        return private_key.decrypt(ciphertext, _oaep_padding())
    except ValueError as exc:
        raise CryptoError(f"RSA-OAEP decryption failed: {exc}") from exc


# --------------------------------------------------------------------------- #
# 4. RSA-PSS(SHA-256): sign/verify a package
# --------------------------------------------------------------------------- #

def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def rsa_pss_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """Sig <- PSS_SHA256(Pr, message)"""
    return private_key.sign(message, _pss_padding(), hashes.SHA256())


def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> None:
    """Verify(Pub, Sig, message). Raises CryptoError on failure — caller must abort, not proceed."""
    try:
        public_key.verify(signature, message, _pss_padding(), hashes.SHA256())
    except InvalidSignature as exc:
        raise CryptoError("Signature verification failed — package rejected.") from exc


# --------------------------------------------------------------------------- #
# 5. AES-256-GCM: encrypt/decrypt the file under session key K
# --------------------------------------------------------------------------- #

def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                     aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    (C, T) <- AESGCM(K, N, M, aad)
    The `cryptography` AESGCM API returns ciphertext with the tag appended;
    we split it here so C_i and T_i are explicit, separate fields in the
    package exactly as the sequence diagram shows them.
    """
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad if aad else None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return ciphertext, tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                     aad: bytes = b"") -> bytes:
    """
    M <- AESGCM^-1(K, N, C, T, aad)
    Raises CryptoError (tag/auth failure) WITHOUT ever returning partial
    plaintext — this is the fail-closed guarantee from the sequence diagram.
    """
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, aad if aad else None)
    except InvalidTag as exc:
        raise CryptoError("AES-GCM authentication tag invalid — file rejected.") from exc


# --------------------------------------------------------------------------- #
# 6. Canonical package assembly (what actually gets signed)
#
#    Length-prefixing every field removes any ambiguity about where one
#    field ends and the next begins, so there is exactly one byte-string
#    that "P_i" can mean for a given set of field values.
# --------------------------------------------------------------------------- #

def _lp(field: bytes) -> bytes:
    """Length-prefix a byte field: 4-byte big-endian length + the bytes."""
    return struct.pack(">I", len(field)) + field


def pack_session_payload(sid: str, enc_k: bytes) -> bytes:
    """The exact bytes that get PSS-signed in Phase 1: Sig1 <- PSS(Pr_S, payload)."""
    return _lp(sid.encode()) + _lp(enc_k)


def pack_file_payload(sid: str, seq_no: int, nonce: bytes, ciphertext: bytes,
                       tag: bytes, metadata: dict) -> bytes:
    """
    P_i, the exact bytes that get PSS-signed in Phase 2:
        P_i = {sid, i, N_i, C_i, T_i, metadata}
        Sig_i <- PSS(Pr_S, P_i)
    `metadata` (filename, mime-type, timestamp, ...) is canonicalized as
    sorted-key JSON so the byte representation is deterministic.
    """
    meta_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    return (
        _lp(sid.encode())
        + _lp(struct.pack(">I", seq_no))
        + _lp(nonce)
        + _lp(ciphertext)
        + _lp(tag)
        + _lp(meta_bytes)
    )


# --------------------------------------------------------------------------- #
# 7. High-level helpers that mirror the two diagram phases end-to-end
# --------------------------------------------------------------------------- #

@dataclass
class SessionInitPackage:
    sid: str
    enc_k: bytes
    signature: bytes

    def to_dict(self) -> dict:
        return {
            "type": "session_init",
            "sid": self.sid,
            "enc_k": self.enc_k.hex(),
            "signature": self.signature.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "SessionInitPackage":
        return SessionInitPackage(
            sid=d["sid"], enc_k=bytes.fromhex(d["enc_k"]), signature=bytes.fromhex(d["signature"])
        )


@dataclass
class FilePackage:
    sid: str
    seq_no: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    metadata: dict
    signature: bytes

    def to_dict(self) -> dict:
        return {
            "type": "file",
            "sid": self.sid,
            "seq_no": self.seq_no,
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag.hex(),
            "metadata": self.metadata,
            "signature": self.signature.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "FilePackage":
        return FilePackage(
            sid=d["sid"],
            seq_no=d["seq_no"],
            nonce=bytes.fromhex(d["nonce"]),
            ciphertext=bytes.fromhex(d["ciphertext"]),
            tag=bytes.fromhex(d["tag"]),
            metadata=d["metadata"],
            signature=bytes.fromhex(d["signature"]),
        )


def build_session_init_package(sender_priv: rsa.RSAPrivateKey, recipient_pub: rsa.RSAPublicKey,
                                session_key: bytes, sid: str) -> SessionInitPackage:
    """Phase 1, sender side: wrap K for the recipient and sign {sid, EncK}."""
    enc_k = rsa_oaep_encrypt(recipient_pub, session_key)
    payload = pack_session_payload(sid, enc_k)
    signature = rsa_pss_sign(sender_priv, payload)
    return SessionInitPackage(sid=sid, enc_k=enc_k, signature=signature)


def open_session_init_package(pkg: SessionInitPackage, sender_pub: rsa.RSAPublicKey,
                               recipient_priv: rsa.RSAPrivateKey) -> bytes:
    """
    Phase 1, recipient side: verify Sig1 then unwrap K.
    Returns K. Raises CryptoError on any failure (nothing is accepted).
    """
    payload = pack_session_payload(pkg.sid, pkg.enc_k)
    verify_signature(sender_pub, pkg.signature, payload)   # abort-on-fail happens inside
    return rsa_oaep_decrypt(recipient_priv, pkg.enc_k)


def build_file_package(sender_priv: rsa.RSAPrivateKey, session_key: bytes, sid: str,
                        seq_no: int, plaintext: bytes, metadata: dict) -> FilePackage:
    """Phase 2, sender side: encrypt the file under K and sign the whole package P_i."""
    nonce = generate_nonce()
    ciphertext, tag = aes_gcm_encrypt(session_key, nonce, plaintext)
    payload = pack_file_payload(sid, seq_no, nonce, ciphertext, tag, metadata)
    signature = rsa_pss_sign(sender_priv, payload)
    return FilePackage(
        sid=sid, seq_no=seq_no, nonce=nonce, ciphertext=ciphertext,
        tag=tag, metadata=metadata, signature=signature,
    )


def open_file_package(pkg: FilePackage, sender_pub: rsa.RSAPublicKey, session_key: bytes) -> bytes:
    """
    Phase 2, recipient side: verify Sig_i over the whole package, then AES-GCM
    decrypt + verify the tag. Returns plaintext ONLY if both checks pass.
    """
    payload = pack_file_payload(pkg.sid, pkg.seq_no, pkg.nonce, pkg.ciphertext, pkg.tag, pkg.metadata)
    verify_signature(sender_pub, pkg.signature, payload)
    return aes_gcm_decrypt(session_key, pkg.nonce, pkg.ciphertext, pkg.tag)
