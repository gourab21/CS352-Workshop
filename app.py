#!/usr/bin/env python3
"""
app.py — CLI dashboard for the secure exam-paper exchange system.

Run this in two separate terminals (one per user) from the project root:

    python3 app.py

Each terminal process:
  - Register / Login against the shared `users.csv` registry + `users/` folder.
  - After login: Send (pick a recipient -> establish session -> send a file)
                  or Receive (refresh the inbox -> accept a session -> get files).
  - The AES session key for each peer lives ONLY in this process's memory
    (the `sessions` dict below) and is gone the moment the program exits —
    nothing session-related is ever written to disk.

Communication between the two terminals happens only through `core/channel.py`,
a shared folder on disk that stands in for the untrusted network channel.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import sys
import time

from core import channel as ch
from core import crypto_core as cc
from core import storage as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def pause():
    input("\n[press Enter to continue] ")


def read_file_bytes(prompt_label: str = "Path to file to send") -> tuple[bytes, str]:
    while True:
        path = input(f"{prompt_label}: ").strip()
        if not path:
            print("  (cancelled)")
            return b"", ""
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            print(f"  No such file: {path}")
            continue
        with open(path, "rb") as f:
            data = f.read()
        return data, os.path.basename(path)


# --------------------------------------------------------------------------- #
# Verbose logging helpers — everything sent/received is printed so the
# protocol's actual bytes-on-the-wire can be followed step by step. Long
# binary fields are shortened to their "initials" (head...tail) rather than
# dumped in full.
# --------------------------------------------------------------------------- #

def brief(data: bytes, head: int = 10) -> str:
    """Hex preview of a byte string; shortened to head+tail if it's long."""
    h = data.hex()
    if len(h) <= head * 2 + 3:
        return h
    return f"{h[:head*2]}…{h[-head*2:]}  ({len(data)} bytes)"


def brief_text(data: bytes, n: int = 60) -> str:
    """Preview of plaintext content: decoded text if possible, else hex."""
    try:
        s = data.decode("utf-8")
        return s if len(s) <= n else f"{s[:n]}…  ({len(data)} chars)"
    except UnicodeDecodeError:
        return brief(data)


def show_session_package(tag: str, peer: str, sid: str, enc_k: bytes, sig: bytes) -> None:
    print(f"  [{tag}] SESSION-INIT package  (peer: {peer})")
    print(f"      sid        = {sid}")
    print(f"      EncK       = {brief(enc_k)}")
    print(f"      signature  = {brief(sig)}")


def show_file_package(tag: str, peer: str, sid: str, seq: int, nonce: bytes,
                       ciphertext: bytes, tag_bytes: bytes, metadata: dict, sig: bytes) -> None:
    print(f"  [{tag}] FILE package  (peer: {peer})")
    print(f"      sid        = {sid}")
    print(f"      seq (i)    = {seq}")
    print(f"      nonce N_i  = {brief(nonce)}")
    print(f"      ciphertext = {brief(ciphertext)}")
    print(f"      auth tag   = {brief(tag_bytes)}")
    print(f"      metadata   = {metadata}")
    print(f"      signature  = {brief(sig)}")


# --------------------------------------------------------------------------- #
# Registration / login
# --------------------------------------------------------------------------- #

def register_flow() -> None:
    print("\n--- Create a new user ---")
    username = input("Choose a username: ").strip()
    if st.user_exists(username):
        print(f"'{username}' already exists. Try logging in instead.")
        return
    password = getpass.getpass("Choose a password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match. Aborted.")
        return
    try:
        st.create_user(username, password)
    except st.StorageError as exc:
        print(f"Could not create user: {exc}")
        return
    print(f"User '{username}' created — RSA-{cc.RSA_KEY_SIZE_BITS} keypair generated and stored.")


def login_flow() -> tuple[str, object] | None:
    print("\n--- Login ---")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    if not st.authenticate_user(username, password):
        print("Invalid username or password.")
        return None
    try:
        private_key = st.load_private_key(username, password)
    except st.StorageError as exc:
        print(f"Login succeeded but key unlock failed: {exc}")
        return None
    print(f"Welcome, {username}.")
    return username, private_key


# --------------------------------------------------------------------------- #
# Send flow  (Phase 1 then Phase 2, sender side)
# --------------------------------------------------------------------------- #

def send_flow(me: str, my_priv, sessions: dict) -> None:
    others = st.list_users(exclude=me)
    if not others:
        print("No other users registered yet.")
        return
    print("\nRegistered users:")
    for i, u in enumerate(others, 1):
        tag = " [session active]" if u in sessions else ""
        print(f"  {i}. {u}{tag}")
    choice = input("Select recipient number (0 to cancel): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(others)):
        print("Cancelled.")
        return
    peer = others[int(choice) - 1]

    print(f"\n--- {peer} ---")
    print("  1. Establish secure session (generate + share AES session key)")
    print("  2. Send document" + ("" if peer in sessions else "  (requires an active session)"))
    print("  0. Back")
    action = input("Choice: ").strip()

    if action == "1":
        try:
            peer_pub = st.load_public_key(peer)
        except st.StorageError as exc:
            print(f"Cannot establish session: {exc}")
            return
        K = cc.generate_session_key()
        sid = cc.generate_session_id()
        print(f"\nGenerated fresh AES-{cc.AES_KEY_SIZE_BYTES*8} session key K = {brief(K)}")
        pkg = cc.build_session_init_package(my_priv, peer_pub, K, sid)
        ch.deliver(to_user=peer, from_user=me, package=pkg.to_dict())
        sessions[peer] = {"sid": sid, "K": K, "next_seq": 1}
        print(f"Session established locally and session-key package SENT to '{peer}':")
        show_session_package("SENT", peer, sid, pkg.enc_k, pkg.signature)
        print(f"  K is held only in memory for this run — never written to disk.")
        print(f"  '{peer}' must Refresh and Accept it on their end before they can receive files.")

    elif action == "2":
        if peer not in sessions:
            print(f"No active session with '{peer}' yet. Establish one first.")
            return
        data, filename = read_file_bytes()
        if not data and not filename:
            return
        state = sessions[peer]
        seq = state["next_seq"]
        metadata = {
            "filename": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
            "sent_at": time.time(),
        }
        print(f"\nPlaintext M_{seq} ('{filename}', {len(data)} bytes): {brief_text(data)}")
        fp = cc.build_file_package(my_priv, state["K"], state["sid"], seq, data, metadata)
        ch.deliver(to_user=peer, from_user=me, package=fp.to_dict())
        state["next_seq"] = seq + 1
        print(f"File package SENT to '{peer}':")
        show_file_package("SENT", peer, fp.sid, fp.seq_no, fp.nonce, fp.ciphertext,
                           fp.tag, fp.metadata, fp.signature)

    else:
        print("Cancelled.")


# --------------------------------------------------------------------------- #
# Receive flow  (Phase 1 accept, then Phase 2 receive, recipient side)
# --------------------------------------------------------------------------- #

def _handle_session_init(me: str, my_priv, sessions: dict, envelope: dict) -> None:
    peer = envelope["from"]
    pkg = cc.SessionInitPackage.from_dict(envelope["package"])
    print(f"\nIncoming SESSION REQUEST from '{peer}'  (envelope {envelope['id']})")
    show_session_package("RECEIVED", peer, pkg.sid, pkg.enc_k, pkg.signature)

    ans = input("  Verify sender signature and accept this session key? [y/N]: ").strip().lower()
    if ans != "y":
        print("  Left pending (not processed).")
        return

    print("  --- Verification ---")
    try:
        peer_pub = st.load_public_key(peer)
    except st.StorageError as exc:
        print(f"  Could not load '{peer}'s public key — {exc}. REJECTED.")
        return

    payload = cc.pack_session_payload(pkg.sid, pkg.enc_k)
    print(f"  Step 1: verify signature over {{sid, EncK}} using {peer}'s public key.")
    try:
        cc.verify_signature(peer_pub, pkg.signature, payload)
    except cc.CryptoError as exc:
        print(f"          -> FAILED: {exc}")
        print("  REJECTED — no session key accepted, no plaintext ever touched.")
        ch.mark_processed(me, envelope["id"])
        return
    print("          -> PASSED: signature is valid, package is authentic and unmodified.")

    print(f"  Step 2: unwrap EncK with our own RSA private key via RSA-OAEP(SHA-256).")
    try:
        K = cc.rsa_oaep_decrypt(my_priv, pkg.enc_k)
    except cc.CryptoError as exc:
        print(f"          -> FAILED: {exc}")
        print("  REJECTED — no session key accepted.")
        ch.mark_processed(me, envelope["id"])
        return
    print(f"          -> PASSED: recovered K = {brief(K)}")

    sessions[peer] = {"sid": pkg.sid, "K": K, "next_seq": 1}
    print(f"  ACCEPTED. Session established with '{peer}' (sid={pkg.sid}). K held in memory only.")
    ch.mark_processed(me, envelope["id"])


def _handle_file(me: str, sessions: dict, envelope: dict) -> None:
    peer = envelope["from"]
    fp = cc.FilePackage.from_dict(envelope["package"])
    filename = (fp.metadata or {}).get("filename", "(unknown)")
    print(f"\nIncoming FILE from '{peer}': '{filename}'  (envelope {envelope['id']})")
    show_file_package("RECEIVED", peer, fp.sid, fp.seq_no, fp.nonce, fp.ciphertext,
                       fp.tag, fp.metadata, fp.signature)

    if peer not in sessions:
        print(f"  No active session with '{peer}' yet — cannot decrypt. Leaving pending; "
              f"accept their session request first, then refresh again.")
        return

    print("  --- Verification ---")
    try:
        peer_pub = st.load_public_key(peer)
    except st.StorageError as exc:
        print(f"  Could not load '{peer}'s public key — {exc}. REJECTED.")
        return

    payload = cc.pack_file_payload(fp.sid, fp.seq_no, fp.nonce, fp.ciphertext, fp.tag, fp.metadata)
    print(f"  Step 1: verify signature over the full package P_{fp.seq_no} "
          f"= {{sid, i, N_i, C_i, T_i, metadata}} using {peer}'s public key.")
    try:
        cc.verify_signature(peer_pub, fp.signature, payload)
    except cc.CryptoError as exc:
        print(f"          -> FAILED: {exc}")
        print("  REJECTED — no plaintext released.")
        ch.mark_processed(me, envelope["id"])
        return
    print("          -> PASSED: signature is valid, package is authentic and unmodified.")

    print(f"  Step 2: AES-256-GCM decrypt with session key K and nonce N_{fp.seq_no}, "
          f"checking auth tag T_{fp.seq_no}.")
    try:
        plaintext = cc.aes_gcm_decrypt(sessions[peer]["K"], fp.nonce, fp.ciphertext, fp.tag)
    except cc.CryptoError as exc:
        print(f"          -> FAILED: {exc}")
        print("  REJECTED — no plaintext released.")
        ch.mark_processed(me, envelope["id"])
        return
    print(f"          -> PASSED: tag verified, plaintext recovered ({len(plaintext)} bytes).")
    print(f"  Plaintext M_{fp.seq_no}: {brief_text(plaintext)}")

    received_dir = os.path.join(BASE_DIR, "users", me, "received")
    os.makedirs(received_dir, exist_ok=True)
    out_path = os.path.join(received_dir, filename)
    with open(out_path, "wb") as f:
        f.write(plaintext)

    expected_hash = (fp.metadata or {}).get("sha256")
    actual_hash = hashlib.sha256(plaintext).hexdigest()
    hash_note = "match" if expected_hash == actual_hash else "MISMATCH"
    print(f"  Saved to: {out_path}")
    print(f"  sha256 {hash_note} (metadata={expected_hash}, computed={actual_hash})")
    ch.mark_processed(me, envelope["id"])


def receive_flow(me: str, my_priv, sessions: dict) -> None:
    pending = ch.list_pending(me)
    if not pending:
        print("Inbox empty (refreshed).")
        return
    print(f"\n{len(pending)} pending item(s) in inbox:")
    for i, env in enumerate(pending, 1):
        if env.get("_corrupt"):
            print(f"  {i}. [UNPARSEABLE / corrupted envelope: {env['_corrupt']}]")
        else:
            ptype = (env.get("package") or {}).get("type", "?")
            print(f"  {i}. from '{env['from']}'  type={ptype}  id={env['id']}")

    choice = input("Process which item? (number, or 0 to go back): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(pending)):
        print("Back to dashboard.")
        return
    envelope = pending[int(choice) - 1]

    if envelope.get("_corrupt"):
        print("  This envelope could not even be parsed as JSON — treating as a tampered/"
              "corrupted message and discarding.")
        ch.mark_processed(me, envelope["id"])
        return

    ptype = (envelope.get("package") or {}).get("type")
    if ptype == "session_init":
        _handle_session_init(me, my_priv, sessions, envelope)
    elif ptype == "file":
        _handle_file(me, sessions, envelope)
    else:
        print(f"  Unknown package type '{ptype}' — discarding.")
        ch.mark_processed(me, envelope["id"])


# --------------------------------------------------------------------------- #
# Dashboard / main loop
# --------------------------------------------------------------------------- #

def dashboard(me: str, my_priv) -> None:
    sessions: dict = {}   # peer_username -> {"sid":..., "K":..., "next_seq":...}
                          # lives only in this process's memory; gone on exit.
    while True:
        active = ", ".join(sessions.keys()) if sessions else "(none)"
        print(f"\n=== Dashboard: {me} ===  active sessions with: {active}")
        print("  1. Send")
        print("  2. Receive (refresh inbox)")
        print("  3. Logout")
        print("\n" * 7, end="")
        choice = input("Choice: ").strip()
        if choice == "1":
            send_flow(me, my_priv, sessions)
        elif choice == "2":
            receive_flow(me, my_priv, sessions)
        elif choice == "3":
            print(f"Logging out '{me}'. All in-memory session keys for this run are discarded.")
            return
        else:
            print("Invalid choice.")


def main() -> None:
    print("Secure Exam-Paper Exchange")
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            register_flow()
        elif choice == "2":
            result = login_flow()
            if result:
                me, my_priv = result
                dashboard(me, my_priv)
        elif choice == "3":
            print("Bye.")
            sys.exit(0)
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted. Exiting — in-memory session keys discarded.")
