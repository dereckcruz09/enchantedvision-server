"""
EnchantedVision activation server.

Endpoints
---------
Public (used by the client app):
    POST /activate   {hwid, key}        -> {token, expires_at}
    POST /refresh    {token}            -> {token, expires_at}
    GET  /healthz                       -> {ok: true}

Admin (used by EnchantedKeyGen and the Discord bot, with X-Admin-Key header):
    POST /admin/genkey   {name, hwid, days}  -> {key, key_id, expires}
    POST /admin/revoke   {key_id}             -> {revoked: true}
    GET  /admin/list                          -> [{key_id, name, ...}, ...]
    GET  /admin/search?q=...                  -> [...]

The raw key is returned ONCE at /admin/genkey time and never stored.
"""

from __future__ import annotations

import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from keys import (
    KeyRecord,
    KeyStore,
    gen_key_id,
    gen_raw_key,
    is_expired_iso,
    is_valid_hwid,
    issue_token,
    load_private_key,
    sha256_hex,
)


load_dotenv()


# ─── Config ──────────────────────────────────────────────────────────────────


PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", ".keys/private.pem")
PRIVATE_KEY_PEM_B64 = os.getenv("PRIVATE_KEY_PEM_B64", "")
DB_PATH = os.getenv("DB_PATH", ".keys/keys.db")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", str(7 * 24 * 3600)))
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]


if not ADMIN_API_KEY or ADMIN_API_KEY == "replace-me-with-a-long-random-secret":
    # Loud failure on startup beats silent insecurity.
    raise RuntimeError(
        "ADMIN_API_KEY is not set. Configure it in .env (see .env.example)."
    )


def _load_signing_key():
    """Load the Ed25519 private key.

    Priority:
      1. PRIVATE_KEY_PEM_B64 env var (base64-encoded PEM). Use this on hosts
         without persistent disk (Render free tier, etc.) so the key survives
         restarts as part of the platform's secret store.
      2. PRIVATE_KEY_PATH file (default behaviour for self-hosted / Docker
         volumes / Fly.io with a volume).

    Auto-generates and writes to PRIVATE_KEY_PATH if neither is available
    (dev convenience only; do NOT rely on this in production on ephemeral
    filesystems).
    """
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if PRIVATE_KEY_PEM_B64:
        try:
            pem = base64.b64decode(PRIVATE_KEY_PEM_B64)
            sk = serialization.load_pem_private_key(pem, password=None)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _E
            if not isinstance(sk, _E):
                raise ValueError("PRIVATE_KEY_PEM_B64 is not Ed25519")
            print("[startup] Loaded private key from PRIVATE_KEY_PEM_B64 env var.")
            return sk
        except Exception as e:
            raise RuntimeError(f"Failed to load PRIVATE_KEY_PEM_B64: {e}")

    from pathlib import Path
    p = Path(PRIVATE_KEY_PATH)
    if p.exists():
        print(f"[startup] Loaded private key from file: {p}")
        return load_private_key(p)

    # Last-resort autogeneration. Loud warning so it's obvious in logs.
    print("!" * 60)
    print("WARNING: No PRIVATE_KEY_PEM_B64 and no file at PRIVATE_KEY_PATH.")
    print("Generating a new ephemeral keypair. This will INVALIDATE every")
    print("existing client install on the next restart. Set PRIVATE_KEY_PEM_B64")
    print("as a Render/Fly/etc. secret to make this permanent.")
    print("!" * 60)
    p.parent.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p.write_bytes(pem)
    return sk


SK = _load_signing_key()
STORE = KeyStore(DB_PATH)


app = FastAPI(title="EnchantedVision Activation", version="1.0.0")
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ─── Public key endpoint (debug aid) ────────────────────────────────────────
# Public; lets you compare what the server is signing against what the client
# has embedded. The public key is not secret. Useful when redeploying.


@app.get("/pubkey")
def pubkey():
    from cryptography.hazmat.primitives import serialization
    raw = SK.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"pubkey_hex": raw.hex()}


# ─── Models ──────────────────────────────────────────────────────────────────


class ActivateIn(BaseModel):
    hwid: str = Field(..., min_length=32, max_length=32)
    key: str = Field(..., min_length=8, max_length=256)


class RefreshIn(BaseModel):
    token: str = Field(..., min_length=16, max_length=4096)


class TokenOut(BaseModel):
    token: str
    expires_at: int


class GenKeyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    hwid: str = Field(..., min_length=32, max_length=32)
    days: int = Field(365, ge=1, le=3650)
    overwrite: bool = False


class GenKeyOut(BaseModel):
    key: str
    key_id: str
    expires: str


class RevokeIn(BaseModel):
    key_id: str = Field(..., min_length=1, max_length=64)


# ─── Auth ────────────────────────────────────────────────────────────────────


def require_admin(x_admin_key: Optional[str] = Header(default=None)) -> None:
    if not x_admin_key or not hmac.compare_digest(x_admin_key, ADMIN_API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bad admin key")


# ─── Public endpoints ────────────────────────────────────────────────────────


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/activate", response_model=TokenOut)
def activate(payload: ActivateIn):
    hwid = payload.hwid.strip().lower()
    key = payload.key.strip()

    if not is_valid_hwid(hwid):
        raise HTTPException(status_code=400, detail="invalid hwid")

    rec = STORE.find_by_hwid(hwid)

    if rec is None:
        # HWID may have drifted (e.g. disk reconnect, wmic timeout). Fall back
        # to looking up by key hash so the customer isn't locked out.
        rec = STORE.find_by_key_hash(sha256_hex(key))
        if rec is not None:
            # Verify the key matches before trusting the record.
            if not hmac.compare_digest(rec.key_hash, sha256_hex(key)):
                rec = None
            else:
                # Key is valid — update the stored HWID to the current one so
                # future HWID-based lookups work again.
                STORE.update_hwid(rec.key_id, hwid)

    if rec is None:
        raise HTTPException(status_code=403, detail="no key for this hwid")
    if rec.revoked:
        raise HTTPException(status_code=403, detail="key revoked")
    if is_expired_iso(rec.expires):
        raise HTTPException(status_code=403, detail="key expired")
    if not hmac.compare_digest(rec.key_hash, sha256_hex(key)):
        raise HTTPException(status_code=403, detail="bad key")

    token, exp = issue_token(SK, hwid=hwid, key_id=rec.key_id, ttl_seconds=TOKEN_TTL_SECONDS)
    return TokenOut(token=token, expires_at=exp)


@app.post("/refresh", response_model=TokenOut)
def refresh(payload: RefreshIn):
    """
    Refresh a still-signed-but-old token. We re-verify the signature with our
    public key, then re-check the database (revocation + expiry of the
    underlying key). We do NOT require the token to be currently un-expired,
    so a client can refresh after a short grace period. We DO require it to
    be valid Ed25519 with v=1.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import base64
    import json

    # Local-only verification (don't enforce exp here, we want to allow refresh
    # of recently-expired tokens).
    pk: Ed25519PublicKey = SK.public_key()  # type: ignore[assignment]

    try:
        p_b64, s_b64 = payload.token.split(".", 1)
        pad_p = "=" * (-len(p_b64) % 4)
        pad_s = "=" * (-len(s_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(p_b64 + pad_p)
        sig = base64.urlsafe_b64decode(s_b64 + pad_s)
        pk.verify(sig, payload_bytes)
        body = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, InvalidSignature, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="bad token")

    if not isinstance(body, dict) or body.get("v") != 1:
        raise HTTPException(status_code=400, detail="bad token version")

    hwid = str(body.get("hwid", ""))
    key_id = str(body.get("key_id", ""))
    if not is_valid_hwid(hwid) or not key_id:
        raise HTTPException(status_code=400, detail="bad token payload")

    # Reject tokens older than 30 days even if the underlying key is fine.
    # Forces re-activation so revocation can't be sidestepped indefinitely.
    import time

    iat = int(body.get("iat", 0))
    if iat and (time.time() - iat) > 30 * 24 * 3600:
        raise HTTPException(status_code=403, detail="token too old, re-activate")

    rec = STORE.find_by_key_id(key_id)
    if rec is None or rec.revoked:
        raise HTTPException(status_code=403, detail="key revoked")
    if is_expired_iso(rec.expires):
        raise HTTPException(status_code=403, detail="key expired")
    if rec.hwid_hash != sha256_hex(hwid):
        raise HTTPException(status_code=403, detail="hwid mismatch")

    token, exp = issue_token(SK, hwid=hwid, key_id=key_id, ttl_seconds=TOKEN_TTL_SECONDS)
    return TokenOut(token=token, expires_at=exp)


# ─── Admin endpoints ─────────────────────────────────────────────────────────


@app.post("/admin/genkey", response_model=GenKeyOut, dependencies=[Depends(require_admin)])
def admin_genkey(payload: GenKeyIn):
    hwid = payload.hwid.strip().lower()
    if not is_valid_hwid(hwid):
        raise HTTPException(status_code=400, detail="invalid hwid")

    existing = STORE.find_by_hwid(hwid)
    if existing and not existing.revoked and not is_expired_iso(existing.expires):
        if not payload.overwrite:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "hwid_already_registered",
                    "key_id": existing.key_id,
                    "name": existing.name,
                    "expires": existing.expires,
                },
            )
        # Overwrite: revoke the prior entry then issue a new one.
        STORE.delete_by_hwid(hwid)

    raw = gen_raw_key()
    key_id = gen_key_id()
    expires = (datetime.now(timezone.utc) + timedelta(days=payload.days)).strftime("%Y-%m-%d")
    rec = KeyRecord(
        key_id=key_id,
        name=payload.name.strip(),
        hwid_hash=sha256_hex(hwid),
        hwid_hint=hwid[:8] + "…",
        key_hash=sha256_hex(raw),
        expires=expires,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        revoked=False,
    )
    STORE.insert(rec)
    return GenKeyOut(key=raw, key_id=key_id, expires=expires)


@app.post("/admin/revoke", dependencies=[Depends(require_admin)])
def admin_revoke(payload: RevokeIn):
    ok = STORE.revoke(payload.key_id.strip())
    if not ok:
        raise HTTPException(status_code=404, detail="key_id not found")
    return {"revoked": True}


@app.get("/admin/list", dependencies=[Depends(require_admin)])
def admin_list():
    return [r.to_public_dict() for r in STORE.list_all()]


@app.get("/admin/search", dependencies=[Depends(require_admin)])
def admin_search(q: str):
    return [r.to_public_dict() for r in STORE.search(q.strip())]
