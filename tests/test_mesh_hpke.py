"""HPKE (RFC 9180) and AES-GCM/X25519 against published vectors."""

import pytest

from interlock.mesh import _aesgcm, hpke


def test_aes128_fips197_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert _aesgcm.AES128(key).encrypt_block(block).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 100])
def test_gcm_round_trip(size):
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = bytes(range(size)) if size < 256 else b"x" * size
    sealed = _aesgcm.seal(key, nonce, plaintext, b"aad")
    assert _aesgcm.open_sealed(key, nonce, sealed, b"aad") == plaintext
    with pytest.raises(ValueError):
        _aesgcm.open_sealed(key, nonce, sealed, b"different aad")


def test_x25519_rfc7748_vectors():
    alice_secret = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    alice_public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_secret = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_public = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert hpke.x25519_base(alice_secret) == alice_public
    assert hpke.x25519_base(bob_secret) == bob_public
    assert hpke.x25519(alice_secret, bob_public) == shared
    assert hpke.x25519(bob_secret, alice_public) == shared


def test_hpke_rfc9180_a_1_1_base_setup():
    # RFC 9180, Appendix A.1.1: DHKEM(X25519, HKDF-SHA256),
    # HKDF-SHA256, AES-128-GCM, mode_base, sequence 0.
    recipient_public = bytes.fromhex(
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
    recipient_secret = bytes.fromhex(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
    ephemeral_secret = bytes.fromhex(
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    aad = bytes.fromhex("436f756e742d30")
    plaintext = bytes.fromhex(
        "4265617574792069732074727574682c20747275746820626561757479")
    expected_enc = bytes.fromhex(
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
    expected_ct = bytes.fromhex(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
        "6d8770ac83d07bea87e13c512a")

    enc, ciphertext = hpke.seal_base(
        recipient_public, info, plaintext, aad, encapsulate_with=ephemeral_secret)
    assert enc == expected_enc
    assert ciphertext == expected_ct
    assert hpke.open_base(enc, recipient_secret, info, ciphertext, aad) == plaintext


def test_hpke_rejects_a_tampered_ciphertext():
    secret, public = hpke.generate_keypair()
    enc, ciphertext = hpke.seal_base(public, b"info", b"secret", b"aad")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    with pytest.raises(ValueError):
        hpke.open_base(enc, secret, b"info", tampered, b"aad")


def test_hpke_rejects_a_wrong_aad():
    secret, public = hpke.generate_keypair()
    enc, ciphertext = hpke.seal_base(public, b"info", b"secret", b"aad")
    with pytest.raises(ValueError):
        hpke.open_base(enc, secret, b"info", ciphertext, b"other aad")
