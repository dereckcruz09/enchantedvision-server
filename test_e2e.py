"""
End-to-end smoke test for the activation server.

Spins up the FastAPI app in-process via TestClient, generates a key with
the admin endpoint, activates it, then verifies the returned token
client-side using the same logic the desktop app uses.
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

# Configure environment BEFORE importing app, so app picks it up at import.
HERE = Path(__file__).parent
os.environ.setdefault("PRIVATE_KEY_PATH", str(HERE / ".keys" / "private.pem"))
os.environ.setdefault("DB_PATH", str(HERE / ".keys" / "test_e2e.db"))
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key-for-e2e-only")
os.environ.setdefault("TOKEN_TTL_SECONDS", "60")

# Wipe a fresh test DB
db_path = Path(os.environ["DB_PATH"])
if db_path.exists():
    db_path.unlink()

sys.path.insert(0, str(HERE))

from fastapi.testclient import TestClient

import app as server_app  # noqa: E402
from keys import _b64url_decode, public_key_raw  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402

import json
import time


client = TestClient(server_app.app)
HEADERS = {"X-Admin-Key": os.environ["ADMIN_API_KEY"]}
HWID = secrets.token_hex(16)  # 32 hex chars


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True}
    print("✓ /healthz")


def test_activate_with_no_key_fails():
    r = client.post("/activate", json={"hwid": HWID, "key": "0" * 64})
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "no key for this hwid"
    print("✓ /activate without registered key → 403")


def test_genkey_and_activate():
    # Admin issues a key
    r = client.post(
        "/admin/genkey",
        headers=HEADERS,
        json={"name": "smoke", "hwid": HWID, "days": 30},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    raw_key = body["key"]
    key_id = body["key_id"]
    assert len(raw_key) == 64
    print(f"✓ /admin/genkey → key_id={key_id}, expires={body['expires']}")

    # Wrong key for the right HWID → 403
    r = client.post("/activate", json={"hwid": HWID, "key": "deadbeef" * 8})
    assert r.status_code == 403 and r.json()["detail"] == "bad key"
    print("✓ /activate with wrong key → 403")

    # Right key for right HWID → 200 + signed token
    r = client.post("/activate", json={"hwid": HWID, "key": raw_key})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    expires_at = r.json()["expires_at"]
    assert "." in token
    print(f"✓ /activate → token (len={len(token)}), expires_at={expires_at}")

    # Verify the token client-side using the embedded public key flow.
    raw_pub = public_key_raw(server_app.SK)
    pk = Ed25519PublicKey.from_public_bytes(raw_pub)
    p_b64, s_b64 = token.split(".", 1)
    payload_bytes = _b64url_decode(p_b64)
    sig = _b64url_decode(s_b64)
    try:
        pk.verify(sig, payload_bytes)
    except InvalidSignature:
        raise AssertionError("Client-side signature verification failed")
    payload = json.loads(payload_bytes.decode("utf-8"))
    assert payload["hwid"] == HWID
    assert payload["key_id"] == key_id
    assert payload["exp"] > int(time.time())
    print("✓ token signature verified client-side; HWID + key_id + exp OK")


def test_refresh():
    # Issue another key for this test
    hwid2 = secrets.token_hex(16)
    r = client.post(
        "/admin/genkey",
        headers=HEADERS,
        json={"name": "refresh", "hwid": hwid2, "days": 30},
    )
    raw_key = r.json()["key"]
    token = client.post("/activate", json={"hwid": hwid2, "key": raw_key}).json()["token"]

    r = client.post("/refresh", json={"token": token})
    assert r.status_code == 200, r.text
    new_token = r.json()["token"]
    assert new_token != token  # nonce + iat should differ
    print("✓ /refresh returned a fresh token")


def test_revoke_blocks_activation():
    hwid3 = secrets.token_hex(16)
    r = client.post(
        "/admin/genkey",
        headers=HEADERS,
        json={"name": "revoke-target", "hwid": hwid3, "days": 30},
    )
    raw_key = r.json()["key"]
    key_id  = r.json()["key_id"]

    # Activation works first
    assert client.post("/activate", json={"hwid": hwid3, "key": raw_key}).status_code == 200

    # Revoke
    r = client.post("/admin/revoke", headers=HEADERS, json={"key_id": key_id})
    assert r.status_code == 200, r.text

    # Activation now fails
    r = client.post("/activate", json={"hwid": hwid3, "key": raw_key})
    assert r.status_code == 403 and r.json()["detail"] == "key revoked"
    print("✓ revoked key is rejected by /activate")


def test_admin_requires_key():
    r = client.post("/admin/revoke", json={"key_id": "abc"})
    assert r.status_code == 401
    r = client.post("/admin/revoke", headers={"X-Admin-Key": "wrong"},
                    json={"key_id": "abc"})
    assert r.status_code == 401
    print("✓ /admin/* requires correct X-Admin-Key")


if __name__ == "__main__":
    test_healthz()
    test_activate_with_no_key_fails()
    test_genkey_and_activate()
    test_refresh()
    test_revoke_blocks_activation()
    test_admin_requires_key()
    print("\nAll end-to-end checks passed.")
