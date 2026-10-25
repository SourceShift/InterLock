"""Membership credentials: one certificate per member per epoch, unlinkable to a
verifier, accountable to the issuer, revocable, and bound to the reporter's key."""
import pytest

from interlock.mesh import ed25519
from interlock.mesh.credential import (
    EPOCH_SECONDS, CredentialError, Issuer, Revocations, epoch_of, issuer_map, verify_certificate,
)

NOW = 1_800_000_000.0


def test_issue_verify_and_sybil_bound(tmp_path):
    issuer = Issuer.load_or_create(str(tmp_path / "issuer.json"), str(tmp_path / "ledger.json"))
    again = Issuer.load_or_create(str(tmp_path / "issuer.json"), str(tmp_path / "ledger.json"))
    assert again.keyid == issuer.keyid
    pseudonym = ed25519.public_key(ed25519.generate_seed())
    epoch = epoch_of(NOW)
    cert = issuer.issue("acme", pseudonym, epoch=epoch)
    issuers = issuer_map([issuer.public.hex()])
    body = verify_certificate(cert, issuers, now=NOW, pseudonym_public=pseudonym, scope="early")
    assert body["epoch"] == epoch and "acme" not in str(cert)
    assert issuer.owner_of(cert["id"]) == "acme"
    # One per member per epoch; a second pseudonym in the same epoch is refused.
    with pytest.raises(CredentialError):
        issuer.issue("acme", ed25519.public_key(ed25519.generate_seed()), epoch=epoch)
    # Next epoch: a fresh, unlinkable certificate.
    cert2 = issuer.issue("acme", ed25519.public_key(ed25519.generate_seed()), epoch=epoch + 1)
    assert cert2["certificate"]["pseudonym"] != cert["certificate"]["pseudonym"]
    # The ledger persisted.
    reloaded = Issuer.load_or_create(str(tmp_path / "issuer.json"), str(tmp_path / "ledger.json"))
    assert reloaded.owner_of(cert2["id"]) == "acme"


def test_verification_refusals():
    issuer = Issuer(ed25519.generate_seed())
    pseudonym = ed25519.public_key(ed25519.generate_seed())
    epoch = epoch_of(NOW)
    cert = issuer.issue("acme", pseudonym, epoch=epoch)
    issuers = issuer_map([issuer.public.hex()])
    verify_certificate(cert, issuers, now=NOW)
    verify_certificate(cert, issuers, now=NOW + EPOCH_SECONDS)  # one epoch of slack
    with pytest.raises(CredentialError):
        verify_certificate(cert, issuers, now=NOW + 3 * EPOCH_SECONDS)
    with pytest.raises(CredentialError):
        verify_certificate(cert, issuer_map([ed25519.public_key(ed25519.generate_seed()).hex()]), now=NOW)
    with pytest.raises(CredentialError):
        verify_certificate(cert, issuers, now=NOW, pseudonym_public=ed25519.public_key(ed25519.generate_seed()))
    with pytest.raises(CredentialError):
        verify_certificate(cert, issuers, now=NOW, scope="stable")
    revoked = Revocations()
    revoked.revoke(cert["id"])
    with pytest.raises(CredentialError):
        verify_certificate(cert, issuers, now=NOW, revoked=revoked)
    assert Revocations.from_dict(revoked.to_dict()).ids == {cert["id"]}
    tampered = dict(cert, certificate=dict(cert["certificate"], scope="admin"))
    with pytest.raises(CredentialError):
        verify_certificate(tampered, issuers, now=NOW)
    with pytest.raises(CredentialError):
        verify_certificate("nope", issuers, now=NOW)
    with pytest.raises(CredentialError):
        issuer.issue("x", b"short", epoch=epoch)


def test_credential_verify_refuses_a_revoked_certificate(tmp_path, capsys):
    """`credential revoke` writes the list; `credential verify --revoked` is the
    reader that makes it enforceable. Without the flag only the signature and
    epoch are checked."""
    import json

    from interlock.cli import main

    issuer_dir = tmp_path / "issuer"
    assert main(["mesh", "credential", "init", "--out", str(issuer_dir)]) == 0
    public = json.loads((issuer_dir / "issuer.json").read_text())["public"]
    pseudonym = ed25519.public_key(ed25519.generate_seed()).hex()
    cert_path = tmp_path / "cert.json"
    assert main(["mesh", "credential", "issue", "--issuer", str(issuer_dir),
                 "--member", "acme", "--pseudonym", pseudonym,
                 "--out", str(cert_path)]) == 0
    cert = json.loads(cert_path.read_text())
    assert main(["mesh", "credential", "verify", str(cert_path),
                 "--issuer-public", public]) == 0
    assert main(["mesh", "credential", "revoke", "--issuer", str(issuer_dir), cert["id"]]) == 0
    assert main(["mesh", "credential", "verify", str(cert_path), "--issuer-public", public,
                 "--revoked", str(issuer_dir / "revoked.json")]) == 2
    assert "REFUSED" in capsys.readouterr().err
