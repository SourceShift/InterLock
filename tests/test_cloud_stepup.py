"""TOTP (RFC 6238), secret sealing, challenge semantics and WebAuthn gating."""
from __future__ import annotations

import pytest

from interlock.cloud.auth.stepup import (
    AES256,
    StepUpError,
    StepUpService,
    Totp,
    WebAuthnStepUp,
    aes_gcm_open,
    aes_gcm_seal,
)

# RFC 6238 Appendix B seed for HMAC-SHA256.
RFC_SECRET = b"12345678901234567890123456789012"


def _totp(clock=lambda: 0.0):
    return Totp(b"k" * 32, clock=clock)


# -- TOTP ---------------------------------------------------------------

@pytest.mark.parametrize("timestamp,expected", [
    (59, "119246"),
    (1111111109, "084774"),
    (1111111111, "062674"),
    (1234567890, "819424"),
    (2000000000, "698825"),
    (20000000000, "737706"),
])
def test_totp_matches_rfc6238_sha256_vectors(timestamp, expected):
    counter = int(timestamp) // 30
    assert Totp.hotp(RFC_SECRET, counter) == expected


def test_totp_accepts_the_previous_and_next_step():
    totp = _totp()
    secret, _uri = totp.enroll("u1")
    previous = totp.code_at(secret, 59)   # step 1
    assert totp.verify("u1", previous, now=89)  # step 2, within +-1


def test_totp_rejects_a_code_outside_the_window():
    totp = _totp()
    secret, _uri = totp.enroll("u1")
    old = totp.code_at(secret, 0)         # step 0
    assert totp.verify("u1", old, now=120) is False  # step 4


def test_totp_wrong_code_returns_false():
    totp = _totp()
    totp.enroll("u1")
    assert totp.verify("u1", "000001", now=59) is False


def test_totp_refuses_a_replayed_code():
    totp = _totp()
    secret, _uri = totp.enroll("u1")
    code = totp.code_at(secret, 59)
    assert totp.verify("u1", code, now=59)
    with pytest.raises(StepUpError):
        totp.verify("u1", code, now=59)


def test_totp_code_only_form_works_with_one_enrollment():
    totp = _totp()
    secret, _uri = totp.enroll("u1")
    assert totp.confirm(totp.code_at(secret, 59), now=59)
    assert totp.verify(totp.code_at(secret, 149), now=149)


def test_verify_accepts_the_user_and_code_by_keyword():
    totp = _totp()
    secret, _uri = totp.enroll("u1")
    assert totp.verify(user_id="u1", code=totp.code_at(secret, 59), now=59)


def test_verify_rejects_an_unknown_keyword():
    totp = _totp()
    totp.enroll("u1")
    with pytest.raises(TypeError):
        totp.verify(bogus="u1")


def test_otpauth_uri_is_sha256_six_digit_thirty_second():
    totp = _totp()
    secret, uri = totp.enroll("u1")
    assert uri.startswith("otpauth://totp/interlock:u1?")
    assert "algorithm=SHA256" in uri
    assert "digits=6" in uri
    assert "period=30" in uri
    assert "secret=" in uri


# -- secret sealing -----------------------------------------------------

def test_aes256_fips197_known_answer():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                        "101112131415161718191a1b1c1d1e1f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert AES256(key).encrypt_block(block).hex() == (
        "8ea2b7ca516745bfeafc49904b496089"
    )


def test_sealed_totp_secret_round_trips_and_hides_the_plaintext():
    totp = _totp()
    secret = bytes(range(20))
    sealed = totp.sealed_secret(secret)
    assert totp.open_secret(sealed) == secret
    assert secret.hex() not in sealed
    assert totp.sealed_secret(secret) != sealed  # fresh nonce each time


def test_aes_gcm_refuses_tampering_and_binds_aad():
    key = b"k" * 32
    blob = aes_gcm_seal(key, b"plaintext", aad=b"aad")
    assert aes_gcm_open(key, blob, aad=b"aad") == b"plaintext"
    with pytest.raises(ValueError):
        aes_gcm_open(key, blob, aad=b"other")
    tampered = blob[:-1] + bytes([blob[-1] ^ 0x01])
    with pytest.raises(ValueError):
        aes_gcm_open(key, tampered, aad=b"aad")


# -- challenges ---------------------------------------------------------

def test_challenge_is_single_use():
    now = [0.0]
    totp = Totp(b"k" * 32, clock=lambda: now[0])
    service = StepUpService(totp=totp, clock=lambda: now[0])
    secret, _uri = totp.enroll("u1")

    challenge = service.begin("u1", "totp")
    result = service.finish(challenge["challenge_id"],
                            totp.code_at(secret, 0), now=0)
    assert result == {"method": "totp", "at": 0.0}
    with pytest.raises(StepUpError):
        service.finish(challenge["challenge_id"], totp.code_at(secret, 30),
                       now=30)


def test_challenge_expires_after_five_minutes():
    now = [0.0]
    totp = Totp(b"k" * 32, clock=lambda: now[0])
    service = StepUpService(totp=totp, clock=lambda: now[0])
    secret, _uri = totp.enroll("u1")

    challenge = service.begin("u1", "totp")
    now[0] = 301.0
    with pytest.raises(StepUpError):
        service.finish(challenge["challenge_id"],
                       totp.code_at(secret, 301), now=301)


def test_phishing_resistant_orgs_refuse_totp():
    service = StepUpService()
    with pytest.raises(StepUpError) as exc:
        service.begin("u1", "totp", phishing_resistant=True)
    assert exc.value.code == "step_up_required"
    assert service.begin("u1", "webauthn", phishing_resistant=True)["method"] == (
        "webauthn"
    )


def test_fresh_predicate():
    assert StepUpService.fresh(1000, now=1299) is True
    assert StepUpService.fresh(1000, now=1301) is False
    assert StepUpService.fresh(None, now=1000) is False


# -- WebAuthn -----------------------------------------------------------

def test_webauthn_options_are_offered_without_the_dependency():
    webauthn = WebAuthnStepUp()
    registration = webauthn.registration_options("u1", "a@acme.test")
    assert registration["rp"]["id"] == "localhost"
    assert registration["challenge"]
    assertion = webauthn.assertion_options(["cred-1"])
    assert assertion["allowCredentials"][0]["id"] == "cred-1"


def test_webauthn_assertion_requires_the_optional_dependency():
    pytest.importorskip("webauthn")
    webauthn = WebAuthnStepUp()
    with pytest.raises(StepUpError):
        webauthn.verify_assertion({"id": "cred-1"}, "challenge", b"public-key")
