"""
channel.py
===========
Simulates the UNTRUSTED CHANNEL between the sender and recipient dashboards.

Both dashboard processes run on the same machine (or could run on separate
machines sharing this directory) and communicate only by dropping and
picking up JSON envelopes in a shared folder:

    channel/<username>/<id>.json            <- pending, not yet processed
    channel/<username>/_processed/<id>.json <- already consumed (kept for audit)

This directory plays the role of "Ch" in the sequence diagram: anything
written here is, by assumption, visible to an attacker who can read it,
corrupt it in place, or substitute a different file before the recipient
picks it up. (That's exactly what the tamper tests do: edit the JSON file
sitting in this folder before calling `list_pending` / consuming it.)

Only JSON-serializable envelopes pass through here — the actual
confidentiality/integrity/authenticity work already happened in
crypto_core.py before a package reaches this module.
"""

from __future__ import annotations

import json
import os
import time
import uuid

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHANNEL_DIR = os.path.join(BASE_DIR, "channel")


class ChannelError(Exception):
    pass


def _inbox_dir(username: str) -> str:
    path = os.path.join(CHANNEL_DIR, username)
    os.makedirs(path, exist_ok=True)
    os.makedirs(os.path.join(path, "_processed"), exist_ok=True)
    return path


def deliver(to_user: str, from_user: str, package: dict) -> str:
    """
    Drop an envelope into `to_user`'s inbox folder.
    `package` is whatever dict a crypto_core *Package.to_dict() produced
    (session_init or file). Returns the envelope id.
    """
    inbox = _inbox_dir(to_user)
    msg_id = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
    envelope = {
        "id": msg_id,
        "from": from_user,
        "to": to_user,
        "sent_at": time.time(),
        "package": package,
    }
    path = os.path.join(inbox, f"{msg_id}.json")
    with open(path, "w") as f:
        json.dump(envelope, f, indent=2)
    return msg_id


def list_pending(username: str) -> list[dict]:
    """Return envelopes waiting in `username`'s inbox (not yet processed), oldest first."""
    inbox = _inbox_dir(username)
    envelopes = []
    for name in os.listdir(inbox):
        if not name.endswith(".json"):
            continue
        path = os.path.join(inbox, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r") as f:
                envelopes.append(json.load(f))
        except (json.JSONDecodeError, OSError) as exc:
            # A corrupted/tampered envelope is still "pending" — surface it
            # as a parse failure so the dashboard can show a clear rejection
            # rather than crashing.
            envelopes.append({
                "id": name[:-5],
                "from": "?",
                "to": username,
                "sent_at": 0,
                "package": None,
                "_corrupt": str(exc),
            })
    envelopes.sort(key=lambda e: e.get("sent_at", 0))
    return envelopes


def mark_processed(username: str, msg_id: str) -> None:
    """Move a consumed envelope out of the active inbox (kept for audit, not reprocessed)."""
    inbox = _inbox_dir(username)
    src = os.path.join(inbox, f"{msg_id}.json")
    dst = os.path.join(inbox, "_processed", f"{msg_id}.json")
    if os.path.exists(src):
        os.replace(src, dst)
