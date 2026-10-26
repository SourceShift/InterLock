"""Step-up authentication: RFC 6238 TOTP and WebAuthn (FR-052).

TOTP is always available and works on a bare interpreter. Its AES-256-GCM
sealing uses ``cryptography`` when installed and a small standard-library
FIPS-197 implementation otherwise, reusing the GHASH/CTR primitives already
shipped in :mod:`interlock.mesh._aesgcm`. WebAuthn delegates CBOR/COSE to the
optional ``webauthn`` package and raises
:class:`~interlock.cloud.db.CloudDependencyMissing` when it is absent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

from ..db import CloudDependencyMissing, INSTALL_HINT
from ...mesh import _aesgcm
from ...mesh.hpke import _hkdf_expand, _hkdf_extract

DIGITS = 6
PERIOD = 30
WINDOW = 1
REPLAY_SECONDS = 90
CHALLENGE_TTL = 300


class StepUpError(Exception):
    """A challenge is missing, expired, already used or unverifiable."""

    def __init__(self, code: str = "step_up_required",
                 message: str = "step-up required") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# -- AES-256-GCM --------------------------------------------------------
#
# The mesh module implements AES-128 only. TOTP secrets are sealed under a
# 32-byte HKDF-derived key, so this adds the FIPS-197 AES-256 block cipher and
# reuses the existing GHASH/CTR/tag construction. It is fallback-only: the
# cryptography package is used whenever it is importable.

_AES_SBOX = _aesgcm._SBOX
_AES_RCON = _aesgcm._RCON
_AES_XTIME = _aesgcm._xtime


class AES256:
    """AES-256 block encryption (FIPS 197); decryption is not needed for GCM."""

    block_size = 16

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 needs a 32-byte key")
        words = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 32, 4)]
        for i in range(8, 60):
            temp = words[i - 1]
            if i % 8 == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ (
                    _AES_RCON[i // 8 - 1] << 24
                )
            elif i % 8 == 4:
                temp = self._sub_word(temp)
            words.append(words[i - 8] ^ temp)
        self._round_keys = words

    @staticmethod
    def _rot_word(word: int) -> int:
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

    @staticmethod
    def _sub_word(word: int) -> int:
        return int.from_bytes(
            bytes(_AES_SBOX[b] for b in word.to_bytes(4, "big")), "big"
        )

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, 0)
        for rnd in range(1, 14):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, rnd)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, 14)
        return bytes(state)

    def _add_round_key(self, state: list, rnd: int) -> None:
        for col in range(4):
            word = self._round_keys[4 * rnd + col]
            for row in range(4):
                state[4 * col + row] ^= (word >> (24 - 8 * row)) & 0xFF

    @staticmethod
    def _sub_bytes(state: list) -> None:
        for i in range(16):
            state[i] = _AES_SBOX[state[i]]

    @staticmethod
    def _shift_rows(state: list) -> None:
        for row in range(1, 4):
            values = [state[4 * col + row] for col in range(4)]
            for col in range(4):
                state[4 * col + row] = values[(col + row) % 4]

    @staticmethod
    def _mix_columns(state: list) -> None:
        for col in range(4):
            a = state[4 * col:4 * col + 4]
            total = a[0] ^ a[1] ^ a[2] ^ a[3]
            state[4 * col + 0] ^= total ^ _AES_XTIME(a[0] ^ a[1])
            state[4 * col + 1] ^= total ^ _AES_XTIME(a[1] ^ a[2])
            state[4 * col + 2] ^= total ^ _AES_XTIME(a[2] ^ a[3])
            state[4 * col + 3] ^= total ^ _AES_XTIME(a[3] ^ a[0])


def _fallback_seal(key: bytes, nonce: bytes, plaintext: bytes,
                   aad: bytes) -> bytes:
    cipher = AES256(key)
    ciphertext = _aesgcm._ctr(cipher, nonce, plaintext)
    return ciphertext + _aesgcm._gcm_tag(cipher, nonce, aad, ciphertext)


def _fallback_open(key: bytes, nonce: bytes, sealed: bytes,
                   aad: bytes) -> bytes:
    if len(sealed) < 16:
        raise ValueError("ciphertext is shorter than its tag")
    cipher = AES256(key)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    expected = _aesgcm._gcm_tag(cipher, nonce, aad, ciphertext)
    if not _aesgcm._constant_time_equal(expected, tag):
        raise ValueError("GCM authentication failed")
    return _aesgcm._ctr(cipher, nonce, ciphertext)


def aes_gcm_seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM encrypt; returns ``nonce || ciphertext || tag``."""
    nonce = secrets.token_bytes(12)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return nonce + _fallback_seal(key, nonce, plaintext, aad)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_open(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM decrypt; raises :class:`ValueError` on a bad tag."""
    if len(blob) < 12 + 16:
        raise ValueError("sealed value is too short")
    nonce, sealed = blob[:12], blob[12:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return _fallback_open(key, nonce, sealed, aad)
    try:
        return AESGCM(key).decrypt(nonce, sealed, aad)
    except Exception:
        raise ValueError("GCM authentication failed") from None


def _derive_key(key_material: bytes) -> bytes:
    prk = _hkdf_extract(b"interlock-totp", key_material)
    return _hkdf_expand(prk, b"interlock-totp-secret-v1", 32)


def _b32(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


class Totp:
    """RFC 6238 TOTP with a replay guard, plus encrypted enrollment secrets."""

    def __init__(self, key: Any, *, clock: Any = time.time) -> None:
        if isinstance(key, str):
            key = key.encode("utf-8")
        self.key = _derive_key(bytes(key))
        self.clock = clock
        self._enrollments: Dict[str, bytes] = {}
        self._used: "OrderedDict[Tuple[str, str], float]" = OrderedDict()

    # -- enrollment -----------------------------------------------------
    def enroll(self, user_id: str) -> Tuple[bytes, str]:
        """Generate and remember a 20-byte secret; return it and its URI."""
        secret = secrets.token_bytes(20)
        self._enrollments[user_id] = secret
        return secret, self.otpauth_uri(user_id, secret)

    def otpauth_uri(self, user_id: str, secret: bytes) -> str:
        label = quote("interlock:{}".format(user_id), safe=":")
        return (
            "otpauth://totp/{}?secret={}&issuer=interlock"
            "&algorithm=SHA256&digits={}&period={}".format(
                label, _b32(secret), DIGITS, PERIOD
            )
        )

    def secret_for(self, user_id: str) -> Optional[bytes]:
        return self._enrollments.get(user_id)

    # -- sealing --------------------------------------------------------
    def sealed_secret(self, secret: bytes) -> str:
        """Encrypt a TOTP secret for the ``totp_secrets.secret_enc`` column."""
        blob = aes_gcm_seal(self.key, secret, aad=b"interlock-totp-secret")
        return base64.b64encode(blob).decode("ascii")

    def open_secret(self, sealed: str) -> bytes:
        return aes_gcm_open(self.key, base64.b64decode(sealed),
                            aad=b"interlock-totp-secret")

    # -- codes ----------------------------------------------------------
    @staticmethod
    def hotp(secret: bytes, counter: int) -> str:
        digest = hmac.new(secret, counter.to_bytes(8, "big"),
                          hashlib.sha256).digest()
        offset = digest[-1] & 0x0F
        value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
        return "{:0{}d}".format(value % (10 ** DIGITS), DIGITS)

    def code_at(self, secret: bytes, timestamp: float) -> str:
        return self.hotp(secret, int(timestamp) // PERIOD)

    def verify(self, *args: Any, now: Optional[float] = None,
               **kwargs: Any) -> bool:
        """Accept ``verify(user_id, code, now=...)`` or ``verify(code, ...)``.

        The code-only form is the documented one and needs a single active
        enrollment; the two-argument form names the user explicitly. Both
        may also be passed by keyword. A replay of a code accepted within
        :data:`REPLAY_SECONDS` raises :class:`StepUpError`; a wrong code
        returns ``False``.
        """
        user_id = kwargs.pop("user_id", None)
        code = kwargs.pop("code", None)
        if kwargs:
            raise TypeError(
                "verify() got an unexpected keyword argument "
                "{!r}".format(sorted(kwargs)[0])
            )
        if len(args) == 1:
            if code is not None:
                raise TypeError("verify() got multiple values for 'code'")
            code = args[0]
        elif len(args) == 2:
            if code is not None:
                raise TypeError("verify() got multiple values for 'code'")
            user_id, code = args[0], args[1]
        elif len(args) > 2:
            raise TypeError("verify expects (code) or (user_id, code)")
        if code is None:
            raise TypeError("verify() needs a code")
        if isinstance(code, int):
            code = "{:0{}d}".format(code, DIGITS)
        if not isinstance(code, str):
            return False

        timestamp = self.clock() if now is None else float(now)
        if user_id is None:
            if len(self._enrollments) != 1:
                raise StepUpError(
                    "step_up_required",
                    "a user id is required when several enrollments are active",
                )
            user_id = next(iter(self._enrollments))
        secret = self._enrollments.get(user_id)
        if secret is None:
            return False

        self._expire_replays(timestamp)
        step = int(timestamp) // PERIOD
        matched = False
        for offset in range(-WINDOW, WINDOW + 1):
            counter = step + offset
            if counter < 0:
                continue
            if hmac.compare_digest(self.hotp(secret, counter), code):
                matched = True
                break
        if not matched:
            return False
        if (user_id, code) in self._used:
            raise StepUpError("step_up_required",
                              "one-time code has already been used")
        self._used[(user_id, code)] = timestamp
        return True

    def confirm(self, code: str, *, now: Optional[float] = None) -> bool:
        """The documented code-only form, for a single active enrollment."""
        return self.verify(code, now=now)

    def _expire_replays(self, now: float) -> None:
        while self._used:
            _key, at = next(iter(self._used.items()))
            if now - at <= REPLAY_SECONDS:
                break
            self._used.popitem(last=False)


class WebAuthnStepUp:
    """WebAuthn registration/assertion, delegating crypto to ``webauthn``."""

    def __init__(self, rp_id: str = "localhost",
                 rp_name: str = "interlock",
                 origin: Optional[str] = None) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin or "https://{}".format(rp_id)

    @staticmethod
    def _base64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def registration_options(self, user_id: str, user_name: str) -> Dict[str, Any]:
        return {
            "challenge": self._base64url(secrets.token_bytes(32)),
            "rp": {"id": self.rp_id, "name": self.rp_name},
            "user": {"id": self._base64url(user_id.encode("utf-8")),
                     "name": user_name, "displayName": user_name},
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ],
            "timeout": 60000,
            "attestation": "none",
        }

    def assertion_options(self, credential_ids: Any) -> Dict[str, Any]:
        return {
            "challenge": self._base64url(secrets.token_bytes(32)),
            "rpId": self.rp_id,
            "allowCredentials": [
                {"type": "public-key", "id": str(cid)} for cid in credential_ids
            ],
            "timeout": 60000,
            "userVerification": "preferred",
        }

    def verify_assertion(self, credential: Any, expected_challenge: str,
                         stored_public_key: Any, *, sign_count: int = 0) -> int:
        """Verify an assertion and return the new sign count.

        A reported sign count that does not advance is refused (a cloned
        authenticator signal). The optional dependency is imported here.
        """
        try:
            import webauthn  # noqa: F401
        except ImportError:
            raise CloudDependencyMissing(INSTALL_HINT) from None
        try:
            result = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=stored_public_key,
                credential_current_sign_count=sign_count,
            )
        except CloudDependencyMissing:
            raise
        except Exception as exc:
            raise StepUpError("step_up_required",
                              "assertion could not be verified") from exc
        new_count = getattr(result, "new_sign_count", sign_count)
        if sign_count and new_count <= sign_count:
            raise StepUpError("step_up_required",
                              "authenticator sign count did not advance")
        return int(new_count)


class StepUpService:
    """Short-lived, single-use step-up challenges and the freshness predicate."""

    def __init__(self, *, totp: Optional[Totp] = None,
                 webauthn: Optional[WebAuthnStepUp] = None,
                 clock: Any = time.time, ttl: int = CHALLENGE_TTL) -> None:
        self.totp = totp
        self.webauthn = webauthn
        self.clock = clock
        self.ttl = int(ttl)
        self._challenges: Dict[str, Dict[str, Any]] = {}

    def begin(self, user_id: str, method: str, *,
              phishing_resistant: bool = False) -> Dict[str, Any]:
        if method not in ("totp", "webauthn"):
            raise StepUpError("step_up_required", "unknown step-up method")
        if method == "totp" and phishing_resistant:
            # FR-052: where the org requires phishing resistance, TOTP is
            # not offered at all.
            raise StepUpError("step_up_required",
                              "this org requires a phishing-resistant method")
        now = self.clock()
        challenge_id = secrets.token_urlsafe(16)
        challenge = {
            "challenge_id": challenge_id,
            "user_id": user_id,
            "method": method,
            "challenge": secrets.token_urlsafe(32),
            "expires": now + self.ttl,
        }
        self._challenges[challenge_id] = challenge
        return {
            "challenge_id": challenge_id,
            "method": method,
            "challenge": challenge["challenge"],
            "expires": challenge["expires"],
        }

    def finish(self, challenge_id: str, assertion: Any, *,
               now: Optional[float] = None) -> Dict[str, Any]:
        # One use: the challenge is consumed even when the assertion fails.
        challenge = self._challenges.pop(challenge_id, None)
        if challenge is None:
            raise StepUpError("step_up_required", "unknown or used challenge")
        at = self.clock() if now is None else float(now)
        if at >= challenge["expires"]:
            raise StepUpError("step_up_required", "challenge expired")

        if challenge["method"] == "totp":
            if self.totp is None:
                raise StepUpError("step_up_required", "TOTP is not configured")
            if not self.totp.verify(challenge["user_id"], assertion, now=at):
                raise StepUpError("step_up_required", "invalid one-time code")
        else:
            if self.webauthn is None:
                raise StepUpError("step_up_required",
                                  "WebAuthn is not configured")
            if not isinstance(assertion, dict):
                raise StepUpError("step_up_required", "malformed assertion")
            self.webauthn.verify_assertion(
                assertion.get("credential"), challenge["challenge"],
                assertion.get("public_key"),
                sign_count=int(assertion.get("sign_count", 0)),
            )
        return {"method": challenge["method"], "at": at}

    @staticmethod
    def fresh(step_up_at: Optional[float], now: Optional[float] = None,
              max_age: int = 300) -> bool:
        if step_up_at is None:
            return False
        at = time.time() if now is None else float(now)
        return 0 <= at - float(step_up_at) <= max_age


__all__ = [
    "AES256",
    "CHALLENGE_TTL",
    "StepUpError",
    "StepUpService",
    "Totp",
    "WebAuthnStepUp",
    "aes_gcm_open",
    "aes_gcm_seal",
]
