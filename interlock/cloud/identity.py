"""Host identity: an Ed25519 seed that never leaves the host.

The plane holds only the public half. The seed is generated on the host at
first enrollment, written to ``cloud.seed`` with mode ``0600`` by the
connector, and is never uploaded (FR-007). The primitive is the in-repo
:mod:`interlock.mesh.ed25519`; no third-party crypto is imported here, so this
module stays importable under ``python3 -I -S``.

``keyid`` is SHA-256 of the public key bytes; it is what the connector and the
plane use to name a host key.
"""
from __future__ import annotations

from typing import Union

from ..receipt_ed25519 import generate_seed, keyid, public_key

#: Ed25519 public keys are 32 bytes, so their hex form is 64 characters.
PUBLIC_KEY_HEX_LENGTH = 64

#: An identity seed is 32 bytes and is written with this mode.
SEED_MODE = 0o600


def generate_host_seed() -> bytes:
    """A fresh 32-byte Ed25519 seed (the private half)."""
    return generate_seed()


def public_key_bytes(seed: bytes) -> bytes:
    """The 32-byte public half for ``seed``."""
    return public_key(seed)


def public_key_hex(seed: bytes) -> str:
    """The public half as lowercase hex, the form the plane stores."""
    return public_key(seed).hex()


def key_id(public: Union[bytes, str]) -> str:
    """The host key id: SHA-256 over the raw public key bytes.

    Accepts either the 32 raw bytes or their 64-character hex encoding, so a
    route can derive the id from the value a connector submitted.
    """
    if isinstance(public, str):
        public = bytes.fromhex(public)
    return keyid(public)


def is_public_key_hex(value: object) -> bool:
    """True for exactly 32 bytes encoded as lowercase or uppercase hex."""
    if not isinstance(value, str) or len(value) != PUBLIC_KEY_HEX_LENGTH:
        return False
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return False
    return len(raw) == 32


__all__ = [
    "PUBLIC_KEY_HEX_LENGTH",
    "SEED_MODE",
    "generate_host_seed",
    "is_public_key_hex",
    "key_id",
    "public_key_bytes",
    "public_key_hex",
]
