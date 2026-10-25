"""Ed25519 signatures for the receipt chain.

The HMAC default proves a log was not changed by someone without the shared
secret. It cannot show *which* holder wrote it, and a third party cannot verify
it without that secret. Ed25519 fixes both: sign with a private seed, hand
verifiers only the public key - the shape ``ChainedSink.verify(verifier=...)``
already accepts.

The primitive is :mod:`interlock.mesh.ed25519` (pure Python, no dependency).
A signature costs a few milliseconds, which is fine for an audit log whose
writes are already serialized behind a file lock, but it is opt-in: the HMAC
default stays cheaper and is the right choice when one party holds both keys.

    from interlock.receipt_ed25519 import ed25519_signer, ed25519_verifier, public_key

    seed = generate_seed()                 # keep this offline
    FileSink(path, signer=ed25519_signer, key=seed)
    sink.verify(verifier=ed25519_verifier(public_key(seed)))

A verifier needs only ``public_key(seed)``; it never sees the seed.
"""
from __future__ import annotations

from typing import Callable

from .mesh.ed25519 import (
    KEY_SIZE,
    SIGNATURE_SIZE,
    generate_seed,
    keyid,
    public_key,
    sign,
    verify,
)

__all__ = [
    "KEY_SIZE",
    "SIGNATURE_SIZE",
    "ed25519_signer",
    "ed25519_verifier",
    "generate_seed",
    "keyid",
    "public_key",
]


def ed25519_signer(key: bytes, message: bytes) -> bytes:
    """Signer seam: ``key`` is the 32-byte private seed, the tag is 64 bytes."""
    return sign(key, message)


def ed25519_verifier(public: bytes) -> Callable[[bytes, bytes], bool]:
    """A ``verifier=`` that checks tags with ``public`` and never sees the seed.

    Malformed signatures return ``False`` rather than raising, so a corrupt
    receipt is reported as the chain's first break by ``verify_chain``.
    """
    if len(public) != KEY_SIZE:
        raise ValueError("an Ed25519 public key is 32 bytes")

    def verifier(message: bytes, tag: bytes) -> bool:
        return verify(public, message, tag)

    return verifier
