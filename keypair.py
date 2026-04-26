"""
One-shot Ed25519 keypair generator for the EnchantedVision activation server.

Run once:
    python keypair.py

Outputs:
    .keys/private.pem   - server's signing key (KEEP SECRET; never commit)
    .keys/public.raw    - 32-byte raw public key (for reference)
    public_key_python.txt - copy/paste-able Python literal to embed in
                            EnchantedVision.py as ACTIVATION_SERVER_PUBKEY.

The client verifies signed tokens with the embedded public key. The server
holds the private key and never exposes it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).parent
KEYS_DIR = HERE / ".keys"
PRIVATE_PATH = KEYS_DIR / "private.pem"
PUBLIC_RAW_PATH = KEYS_DIR / "public.raw"
PUBLIC_PY_PATH = HERE / "public_key_python.txt"


def main() -> int:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_PATH.exists():
        print(f"Refusing to overwrite existing {PRIVATE_PATH}.")
        print("Delete it manually if you really want a fresh keypair.")
        print("(Note: doing so invalidates every issued token.)")
        return 1

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    # Write PEM-encoded private key (no password; protect via filesystem perms).
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    PRIVATE_PATH.write_bytes(pem)
    try:
        os.chmod(PRIVATE_PATH, 0o600)
    except Exception:
        pass

    raw_pub = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    PUBLIC_RAW_PATH.write_bytes(raw_pub)

    py_literal = "ACTIVATION_SERVER_PUBKEY = bytes.fromhex(\n    \"" + raw_pub.hex() + "\"\n)\n"
    PUBLIC_PY_PATH.write_text(py_literal, encoding="utf-8")

    print("Generated Ed25519 keypair.")
    print(f"  Private key: {PRIVATE_PATH}  (KEEP SECRET)")
    print(f"  Public key:  {PUBLIC_RAW_PATH}")
    print()
    print("Paste the following constant near the top of EnchantedVision.py")
    print("(replacing the existing ACTIVATION_SERVER_PUBKEY placeholder):")
    print()
    print(py_literal)
    return 0


if __name__ == "__main__":
    sys.exit(main())
