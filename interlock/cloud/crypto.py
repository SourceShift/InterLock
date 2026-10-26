"""Per-org preview encryption for the plane (FR-017, FR-018).

A masked preview is still tenant data. The plane stores it encrypted with
AES-256-GCM under a key derived from the operator's preview KEK and the org
id, so the database alone - a backup, a replica, a support dump - never
contains a readable preview:

    key = HKDF-SHA256(IL_CLOUD_PREVIEW_KEK, info=org_id + ":preview", 32)

The stored blob is ``nonce || ciphertext`` (the GCM tag is part of the
``cryptography`` ciphertext), and the AAD binds the org id so a ciphertext
cannot be moved to another tenant.

``cryptography`` is part of the optional cloud extra and is imported lazily
inside the two functions; without it they raise
:class:`~interlock.cloud.db.CloudDependencyMissing` rather than silently
falling back to a weaker construction. HKDF is implemented here with
HMAC-SHA256 so key derivation works on a bare interpreter, which keeps the
dependency error at the one call that actually needs the cipher.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

from .db import INSTALL_HINT, CloudDependencyMissing

#: AES-256 needs a 32-byte key; GCM uses a 12-byte nonce.
KEY_SIZE = 32
NONCE_SIZE = 12


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * hashlib.sha256().digest_size,
                    ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_preview_key(kek: bytes, org_id: str) -> bytes:
    """HKDF-SHA256(kek, info=``org_id + ":preview"``) -> 32 bytes."""
    if not isinstance(kek, (bytes, bytearray)) or not kek:
        raise ValueError("a preview KEK is required")
    prk = _hkdf_extract(b"interlock-preview-kek-v1", bytes(kek))
    return _hkdf_expand(prk, (str(org_id) + ":preview").encode("utf-8"), KEY_SIZE)


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise CloudDependencyMissing(INSTALL_HINT) from None
    return AESGCM


def encrypt_preview(preview: str, *, kek: bytes, org_id: str,
                    nonce: Optional[bytes] = None) -> bytes:
    """Encrypt one preview; returns ``nonce || ciphertext``."""
    if not isinstance(preview, str):
        raise TypeError("a preview is text")
    aesgcm = _aesgcm()
    key = derive_preview_key(kek, org_id)
    nonce = os.urandom(NONCE_SIZE) if nonce is None else bytes(nonce)
    if len(nonce) != NONCE_SIZE:
        raise ValueError("the GCM nonce is 12 bytes")
    sealed = aesgcm(key).encrypt(
        nonce, preview.encode("utf-8"),
        (str(org_id) + ":preview").encode("utf-8"),
    )
    return nonce + sealed


def decrypt_preview(blob: Optional[bytes], *, kek: bytes, org_id: str) -> str:
    """Decrypt a stored preview, raising ``ValueError`` on a bad tag."""
    if not blob:
        return ""
    if len(blob) < NONCE_SIZE + 16:
        raise ValueError("sealed preview is too short")
    aesgcm = _aesgcm()
    key = derive_preview_key(kek, org_id)
    nonce, sealed = bytes(blob[:NONCE_SIZE]), bytes(blob[NONCE_SIZE:])
    try:
        plain = aesgcm(key).decrypt(
            nonce, sealed, (str(org_id) + ":preview").encode("utf-8"))
    except Exception:
        raise ValueError("preview authentication failed") from None
    return plain.decode("utf-8")


def parse_kek(value: str) -> bytes:
    """Parse ``IL_CLOUD_PREVIEW_KEK`` (hex or base64) into raw bytes."""
    import base64

    text = (value or "").strip()
    if not text:
        raise ValueError("a preview KEK is required")
    try:
        raw = bytes.fromhex(text)
        if len(raw) >= 16:
            return raw
    except ValueError:
        pass
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:
        raise ValueError("the preview KEK must be hex or base64") from None
    if len(raw) < 16:
        raise ValueError("the preview KEK must be at least 16 bytes")
    return raw


__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "decrypt_preview",
    "derive_preview_key",
    "encrypt_preview",
    "parse_kek",
]
