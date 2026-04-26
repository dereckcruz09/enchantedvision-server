"""
Storage + crypto helpers for the activation server.

- Keys are stored in SQLite. We never store the raw key; only sha256(key).
- Tokens are short-lived, signed with Ed25519, and bound to a specific HWID.
- Tokens are NOT stored server-side; they're stateless and verified by the
  client using the embedded public key. Revocation is enforced by refusing
  to refresh tokens whose key_id has been revoked.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# ─── Database ────────────────────────────────────────────────────────────────


SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    key_id      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    hwid_hash   TEXT NOT NULL,
    hwid_hint   TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    expires     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_keys_hwid_hash ON keys(hwid_hash);
CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name);
"""


@dataclass
class KeyRecord:
    key_id: str
    name: str
    hwid_hash: str
    hwid_hint: str
    key_hash: str
    expires: str  # ISO date YYYY-MM-DD (UTC)
    created_at: str
    revoked: bool

    def to_public_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "name": self.name,
            "hwid_hint": self.hwid_hint,
            "expires": self.expires,
            "created_at": self.created_at,
            "revoked": self.revoked,
        }


class KeyStore:
    def __init__(self, db_path: str | os.PathLike):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> KeyRecord:
        return KeyRecord(
            key_id=row["key_id"],
            name=row["name"],
            hwid_hash=row["hwid_hash"],
            hwid_hint=row["hwid_hint"],
            key_hash=row["key_hash"],
            expires=row["expires"],
            created_at=row["created_at"],
            revoked=bool(row["revoked"]),
        )

    def insert(self, rec: KeyRecord) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO keys (key_id, name, hwid_hash, hwid_hint, key_hash, "
                "expires, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rec.key_id,
                    rec.name,
                    rec.hwid_hash,
                    rec.hwid_hint,
                    rec.key_hash,
                    rec.expires,
                    rec.created_at,
                    int(rec.revoked),
                ),
            )

    def find_by_hwid(self, hwid: str) -> Optional[KeyRecord]:
        h = sha256_hex(hwid)
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM keys WHERE hwid_hash = ? ORDER BY created_at DESC LIMIT 1",
                (h,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def find_by_key_id(self, key_id: str) -> Optional[KeyRecord]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def search(self, term: str) -> list[KeyRecord]:
        like = f"%{term.lower()}%"
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM keys WHERE LOWER(name) LIKE ? OR LOWER(key_id) LIKE ?",
                (like, like),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def list_all(self) -> list[KeyRecord]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
        return [self._row_to_record(r) for r in rows]

    def revoke(self, key_id: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE keys SET revoked = 1 WHERE key_id = ?", (key_id,)
            )
            return cur.rowcount > 0

    def delete_by_hwid(self, hwid: str) -> int:
        h = sha256_hex(hwid)
        with self._conn() as c:
            cur = c.execute("DELETE FROM keys WHERE hwid_hash = ?", (h,))
            return cur.rowcount


# ─── Hashing / key generation ────────────────────────────────────────────────


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def gen_raw_key() -> str:
    return secrets.token_hex(32)


def gen_key_id() -> str:
    return uuid.uuid4().hex[:8]


def is_valid_hwid(hwid: str) -> bool:
    return len(hwid) == 32 and all(c in "0123456789abcdef" for c in hwid.lower())


def is_expired_iso(expires: str, now_epoch: float | None = None) -> bool:
    """expires is YYYY-MM-DD UTC."""
    try:
        # Treat the whole expiry day as valid (i.e. "expires 2027-04-26" means
        # the key is still valid through 2027-04-26 23:59:59 UTC).
        from datetime import datetime, timezone, timedelta

        d = datetime.strptime(expires, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        cutoff = d + timedelta(days=1)
        now = datetime.fromtimestamp(now_epoch, timezone.utc) if now_epoch else datetime.now(timezone.utc)
        return now >= cutoff
    except Exception:
        return False


# ─── Token signing / verification ────────────────────────────────────────────
#
# Token format (string):  base64url(payload_json) + "." + base64url(signature)
# Payload fields:
#   v       : token version (int, currently 1)
#   hwid    : 32-char hex HWID
#   key_id  : 8-char key id
#   iat     : issued-at unix timestamp (int)
#   exp     : expiry unix timestamp (int)
#   nonce   : random hex string


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def load_private_key(path: str | os.PathLike) -> Ed25519PrivateKey:
    pem = Path(path).read_bytes()
    sk = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise ValueError("Private key is not Ed25519")
    return sk


def public_key_raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def issue_token(
    sk: Ed25519PrivateKey,
    *,
    hwid: str,
    key_id: str,
    ttl_seconds: int,
) -> tuple[str, int]:
    now = int(time.time())
    exp = now + ttl_seconds
    payload = {
        "v": 1,
        "hwid": hwid,
        "key_id": key_id,
        "iat": now,
        "exp": exp,
        "nonce": secrets.token_hex(8),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = sk.sign(payload_bytes)
    token = f"{_b64url(payload_bytes)}.{_b64url(sig)}"
    return token, exp


def verify_token(
    pk: Ed25519PublicKey,
    token: str,
    *,
    expected_hwid: Optional[str] = None,
    now_epoch: Optional[int] = None,
) -> Optional[dict]:
    """Returns the payload dict if valid, else None."""
    try:
        p_b64, s_b64 = token.split(".", 1)
        payload_bytes = _b64url_decode(p_b64)
        sig = _b64url_decode(s_b64)
        pk.verify(sig, payload_bytes)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, InvalidSignature, json.JSONDecodeError):
        return None

    now = now_epoch if now_epoch is not None else int(time.time())
    if not isinstance(payload, dict):
        return None
    if payload.get("v") != 1:
        return None
    if int(payload.get("exp", 0)) <= now:
        return None
    if expected_hwid is not None and not hmac.compare_digest(
        str(payload.get("hwid", "")), expected_hwid
    ):
        return None
    return payload
