"""HPKE base mode for DAP: X25519, HKDF-SHA256, AES-128-GCM (RFC 9180).

Only the single-shot base-mode profile DAP needs is implemented. The public
constants are the suite identifiers DAP-20 negotiates:

    KEM  0x0020  DHKEM(X25519, HKDF-SHA256)
    KDF  0x0001  HKDF-SHA256
    AEAD 0x0001  AES-128-GCM

The X25519 ladder and the AEAD are pure Python and are not constant-time; see
``interlock.mesh.ed25519`` for the same caveat elsewhere in the package.
"""

import hashlib
import hmac
import os
from typing import Optional, Tuple

from ._aesgcm import open_sealed, seal

KEM_X25519_HKDF_SHA256 = 0x0020
KDF_HKDF_SHA256 = 0x0001
AEAD_AES_128_GCM = 0x0001

MODE_BASE = 0x00
_NK = 16
_NN = 12
_NH = 32
_NENC = 32

_P = 2 ** 255 - 19
_A24 = 121665
_BASE_U = 9


def _clamp(scalar: bytes) -> int:
    if len(scalar) != 32:
        raise ValueError("X25519 private key must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar: bytes, u: bytes) -> bytes:
    """RFC 7748 X25519; returns the 32-byte little-endian u-coordinate."""
    if len(u) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    k = _clamp(scalar)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def x25519_base(scalar: bytes) -> bytes:
    return x25519(scalar, _BASE_U.to_bytes(32, "little"))


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return ``(secret, public)`` for a fresh X25519 key pair."""
    secret = os.urandom(32)
    return secret, x25519_base(secret)


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * _NH, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _suite_id(kem_id: int, kdf_id: int, aead_id: int) -> bytes:
    return b"HPKE" + _i2osp(kem_id, 2) + _i2osp(kdf_id, 2) + _i2osp(aead_id, 2)


def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _hkdf_expand(prk, _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info, length)


def _kem_suite_id(kem_id: int = KEM_X25519_HKDF_SHA256) -> bytes:
    return b"KEM" + _i2osp(kem_id, 2)


def _extract_and_expand(dh: bytes, kem_context: bytes, kem_id: int) -> bytes:
    kem_suite = _kem_suite_id(kem_id)
    eae_prk = _labeled_extract(kem_suite, b"", b"eae_prk", dh)
    return _labeled_expand(kem_suite, eae_prk, b"shared_secret", kem_context, _NH)


def _key_schedule(shared_secret: bytes, info: bytes, suite_id: bytes) -> Tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(suite_id, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(suite_id, b"", b"info_hash", info)
    context = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = _labeled_extract(suite_id, shared_secret, b"secret", b"")
    key = _labeled_expand(suite_id, secret, b"key", context, _NK)
    base_nonce = _labeled_expand(suite_id, secret, b"base_nonce", context, _NN)
    return key, base_nonce


def _nonce(base_nonce: bytes, seq: int) -> bytes:
    return bytes(a ^ b for a, b in zip(base_nonce, _i2osp(seq, _NN)))


def seal_base(recipient_public: bytes, info: bytes, plaintext: bytes, aad: bytes = b"",
              *, kem_id: int = KEM_X25519_HKDF_SHA256, kdf_id: int = KDF_HKDF_SHA256,
              aead_id: int = AEAD_AES_128_GCM, encapsulate_with: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """HPKE SealBase. Returns ``(enc, ciphertext)``.

    ``encapsulate_with`` is a deterministic ephemeral secret for test vectors;
    production callers leave it unset and a fresh secret is generated.
    """
    if aead_id != AEAD_AES_128_GCM or kdf_id != KDF_HKDF_SHA256 or kem_id != KEM_X25519_HKDF_SHA256:
        raise ValueError("only the DAP HPKE suite (X25519/HKDF-SHA256/AES-128-GCM) is implemented")
    eph_secret = encapsulate_with or os.urandom(32)
    enc = x25519_base(eph_secret)
    dh = x25519(eph_secret, recipient_public)
    shared_secret = _extract_and_expand(dh, enc + recipient_public, kem_id)
    key, base_nonce = _key_schedule(shared_secret, info, _suite_id(kem_id, kdf_id, aead_id))
    return enc, seal(key, _nonce(base_nonce, 0), plaintext, aad)


def open_base(enc: bytes, recipient_secret: bytes, info: bytes, ciphertext: bytes, aad: bytes = b"",
              *, kem_id: int = KEM_X25519_HKDF_SHA256, kdf_id: int = KDF_HKDF_SHA256,
              aead_id: int = AEAD_AES_128_GCM) -> bytes:
    """HPKE OpenBase; raises :class:`ValueError` on a bad tag or wrong key."""
    if aead_id != AEAD_AES_128_GCM or kdf_id != KDF_HKDF_SHA256 or kem_id != KEM_X25519_HKDF_SHA256:
        raise ValueError("only the DAP HPKE suite (X25519/HKDF-SHA256/AES-128-GCM) is implemented")
    if len(enc) != _NENC:
        raise ValueError("HPKE encapsulated key must be 32 bytes")
    public = x25519_base(recipient_secret)
    dh = x25519(recipient_secret, enc)
    shared_secret = _extract_and_expand(dh, enc + public, kem_id)
    key, base_nonce = _key_schedule(shared_secret, info, _suite_id(kem_id, kdf_id, aead_id))
    return open_sealed(key, _nonce(base_nonce, 0), ciphertext, aad)
