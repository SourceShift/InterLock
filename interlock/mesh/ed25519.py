"""Ed25519 signatures (RFC 8032), in pure Python.

The mesh distributes policy that anyone may verify, so its signatures must be
public-key: the HMAC chain that signs receipts proves only that a holder of a
shared secret wrote them. The standard library has no Ed25519, and interlock
promises zero dependencies, so this module implements the scheme itself.

It is written for correctness and clarity, not throughput: a signature takes a
few milliseconds and a verification about twice that. A subscriber verifies a
handful of signatures per metadata refresh, so that is fine. It is not meant
for signing receipts on the hot path.

Constant-time behaviour is **not** attempted. Python's big integers leak timing
by value, so a private key used here is one an attacker with a very precise
clock on the same host could, in principle, learn. Maintainers' signing keys
should therefore live on machines that run nothing else of the attacker's,
which is also what the metadata design assumes (offline root keys, online
keys that are cheap to rotate).

Verification is strict in the sense of RFC 8032 §5.1.7 plus the check that
``S < L``, so a signature is accepted in exactly one encoding.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Tuple

__all__ = ["KEY_SIZE", "SIGNATURE_SIZE", "generate_seed", "public_key", "sign", "verify",
           "keyid"]

KEY_SIZE = 32
SIGNATURE_SIZE = 64

# Curve25519 in twisted Edwards form: -x^2 + y^2 = 1 + d x^2 y^2 over GF(p).
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1)

# Points are (X, Y, Z, T) in extended coordinates: x = X/Z, y = Y/Z, T = XY/Z.
_Point = Tuple[int, int, int, int]
_IDENTITY: _Point = (0, 1, 1, 0)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int:
    """The x coordinate with the given low bit for a y on the curve, or raise."""
    if y >= _P:
        raise ValueError("point not on curve")
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        if sign:
            raise ValueError("point not on curve")
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        raise ValueError("point not on curve")
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(p: _Point, q: _Point) -> _Point:
    # "add-2008-hwcd-3" for a = -1 (the Ed25519 twist), complete for all inputs.
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _double(p: _Point) -> _Point:
    return _add(p, p)


def _mul(s: int, p: _Point) -> _Point:
    result = _IDENTITY
    while s > 0:
        if s & 1:
            result = _add(result, p)
        p = _double(p)
        s >>= 1
    return result


def _equal(p: _Point, q: _Point) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _encode(p: _Point) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(raw: bytes) -> _Point:
    if len(raw) != 32:
        raise ValueError("a point is 32 bytes")
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _P)


_BASE_Y = 4 * _inv(5) % _P
_BASE: _Point = (_recover_x(_BASE_Y, 0), _BASE_Y, 1, _recover_x(_BASE_Y, 0) * _BASE_Y % _P)


def _clamp(h: bytes) -> int:
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(bytes(a), "little")


def generate_seed() -> bytes:
    """A fresh 32-byte private key (the RFC calls it the seed)."""
    return secrets.token_bytes(KEY_SIZE)


def public_key(seed: bytes) -> bytes:
    """The 32-byte public key for ``seed``."""
    if len(seed) != KEY_SIZE:
        raise ValueError("an Ed25519 private key is 32 bytes")
    a = _clamp(hashlib.sha512(seed).digest())
    return _encode(_mul(a, _BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign ``message`` with ``seed``; returns the 64-byte signature."""
    if len(seed) != KEY_SIZE:
        raise ValueError("an Ed25519 private key is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    prefix = h[32:]
    pub = _encode(_mul(a, _BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_point = _encode(_mul(r, _BASE))
    k = int.from_bytes(hashlib.sha512(r_point + pub + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return r_point + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True when ``signature`` is a valid signature of ``message`` under ``public``.

    Never raises on malformed input: a wrong length, a point off the curve, or
    an unreduced scalar all return False.
    """
    try:
        if len(public) != KEY_SIZE or len(signature) != SIGNATURE_SIZE:
            return False
        a_point = _decode(public)
        r_point = _decode(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
        left = _mul(s, _BASE)
        right = _add(r_point, _mul(k, a_point))
        return _equal(left, right)
    except (ValueError, TypeError):
        return False


def keyid(public: bytes) -> str:
    """The identifier metadata uses for a public key: SHA-256 of its bytes."""
    return hashlib.sha256(public).hexdigest()
