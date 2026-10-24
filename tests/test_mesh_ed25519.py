"""The pure-Python Ed25519: RFC 8032 test vectors, round trips, and rejection of
every malformed input a verifier can be handed."""
import hashlib

import pytest

from interlock.mesh import ed25519

# RFC 8032 section 7.1 (TEST 1, TEST 2, TEST 3, TEST SHA(abc)).
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     hashlib.sha512(b"abc").hexdigest(),
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]


@pytest.mark.parametrize("seed, public, message, signature", VECTORS)
def test_rfc_8032_vectors(seed, public, message, signature):
    seed_b, public_b, message_b, signature_b = (bytes.fromhex(x) for x in (seed, public, message, signature))
    assert ed25519.public_key(seed_b) == public_b
    assert ed25519.sign(seed_b, message_b) == signature_b
    assert ed25519.verify(public_b, message_b, signature_b)


def test_round_trip_with_a_fresh_key():
    seed = ed25519.generate_seed()
    public = ed25519.public_key(seed)
    message = b"policy pack bytes"
    signature = ed25519.sign(seed, message)
    assert ed25519.verify(public, message, signature)
    assert not ed25519.verify(public, message + b"!", signature)
    assert not ed25519.verify(ed25519.public_key(ed25519.generate_seed()), message, signature)


def test_malformed_inputs_are_rejected_without_raising():
    seed = ed25519.generate_seed()
    public = ed25519.public_key(seed)
    signature = ed25519.sign(seed, b"m")
    assert not ed25519.verify(public[:-1], b"m", signature)
    assert not ed25519.verify(public, b"m", signature[:-1])
    assert not ed25519.verify(b"\xff" * 32, b"m", signature)
    # An unreduced scalar (S + L) encodes the same group element but must be
    # refused: one signature, one encoding.
    s = int.from_bytes(signature[32:], "little") + ed25519._L
    assert not ed25519.verify(public, b"m", signature[:32] + s.to_bytes(32, "little"))
    # A flipped signature bit fails.
    bad = bytearray(signature)
    bad[3] ^= 1
    assert not ed25519.verify(public, b"m", bytes(bad))


def test_keyid_is_sha256_of_the_public_key():
    public = ed25519.public_key(ed25519.generate_seed())
    assert ed25519.keyid(public) == hashlib.sha256(public).hexdigest()


def test_wrong_seed_size_raises():
    with pytest.raises(ValueError):
        ed25519.sign(b"short", b"m")
    with pytest.raises(ValueError):
        ed25519.public_key(b"x" * 31)
