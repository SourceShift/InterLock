"""Membership credentials: accountable reporters that verifiers cannot link.

The early ring is a trusted community, and a reporter's weight in consensus
is worth attacking: one organisation pretending to be ten is the Sybil
problem every crowdsourced system meets. The strongest known answer binds all
of a member's pseudonyms to one admission token with a zero-knowledge
membership proof, so that even the issuer cannot link them. That needs
zkSNARK machinery the standard library does not have, and this module makes
the honest, smaller promise instead:

- An **issuer** admits an organisation once, out of band, and signs one
  **certificate per epoch** (a week) for a pseudonymous reporting key the
  member generated. The certificate carries the pseudonym, the epoch and a
  scope, and *not* the member's name.
- **Verifiers** (the consensus engine, mirrors) learn only that the issuer
  admitted whoever holds this key for this epoch. Two epochs' certificates
  from one member are unlinkable to them.
- The **issuer** keeps a private ledger of which member received which
  certificate, so misbehaviour has an owner: it can refuse the next epoch and
  publish the certificate id on a revocation list.
- One certificate per member per epoch is the Sybil bound: a member cannot be
  ten reporters at once.

Upgrade path: replace the issuer's signature with an anonymous credential or a
zk set-membership proof and nothing downstream changes, because verifiers
already see only ``(pseudonym, epoch, scope, signature)``.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional

from . import ed25519
from ._util import atomic_write, canonical, read_bounded

__all__ = ["EPOCH_SECONDS", "epoch_of", "Issuer", "verify_certificate", "CredentialError", "Revocations"]

EPOCH_SECONDS = 7 * 86400
CERT_VERSION = 1
LEDGER_MAX = 64 * 1024 * 1024


class CredentialError(ValueError):
    """A certificate that must not be trusted."""


def epoch_of(ts: Optional[float] = None) -> int:
    return int((time.time() if ts is None else ts) // EPOCH_SECONDS)


def certificate_id(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(body)).hexdigest()[:32]


class Issuer:
    """The admitting organisation's signing key and private ledger."""

    def __init__(self, seed: bytes, ledger_path: Optional[str] = None) -> None:
        if len(seed) != ed25519.KEY_SIZE:
            raise CredentialError("an issuer key is 32 bytes")
        self.seed = seed
        self.public = ed25519.public_key(seed)
        self.keyid = ed25519.keyid(self.public)
        self.ledger_path = ledger_path
        self.ledger: Dict[str, Dict[str, Any]] = {}
        if ledger_path and os.path.exists(ledger_path):
            self.ledger = json.loads(read_bounded(ledger_path, LEDGER_MAX).decode("utf-8")).get("certificates", {})

    @classmethod
    def load_or_create(cls, key_path: str, ledger_path: Optional[str] = None) -> "Issuer":
        if os.path.exists(key_path):
            record = json.loads(read_bounded(key_path, 4096).decode("utf-8"))
            return cls(bytes.fromhex(record["seed"]), ledger_path)
        seed = ed25519.generate_seed()
        issuer = cls(seed, ledger_path)
        atomic_write(key_path, json.dumps({"version": 1, "role": "issuer", "keytype": "ed25519",
                                           "seed": seed.hex(), "public": issuer.public.hex(),
                                           "keyid": issuer.keyid}, indent=1).encode("utf-8"), mode=0o600)
        return issuer

    def issue(self, member: str, pseudonym_public: bytes, *, epoch: Optional[int] = None,
              scope: str = "early") -> Dict[str, Any]:
        """Sign a certificate for ``pseudonym_public`` in ``epoch``. One per member per epoch."""
        if len(pseudonym_public) != ed25519.KEY_SIZE:
            raise CredentialError("a pseudonym is a 32-byte Ed25519 public key")
        epoch = epoch_of() if epoch is None else int(epoch)
        for record in self.ledger.values():
            if record["member"] == member and record["epoch"] == epoch and record["scope"] == scope:
                raise CredentialError("{} already holds a {} certificate for epoch {}".format(member, scope, epoch))
        body = {"version": CERT_VERSION, "pseudonym": pseudonym_public.hex(), "epoch": epoch, "scope": scope,
                "issuer": self.keyid}
        cert_id = certificate_id(body)
        cert = {"certificate": body, "id": cert_id, "signature": ed25519.sign(self.seed, canonical(body)).hex()}
        self.ledger[cert_id] = {"member": member, "epoch": epoch, "scope": scope, "issued": time.time(),
                                "pseudonym": ed25519.keyid(pseudonym_public)}
        self._save()
        return cert

    def owner_of(self, cert_id: str) -> Optional[str]:
        record = self.ledger.get(cert_id)
        return record["member"] if record else None

    def _save(self) -> None:
        if self.ledger_path:
            atomic_write(self.ledger_path, json.dumps({"version": 1, "certificates": self.ledger},
                                                      indent=1, sort_keys=True).encode("utf-8"), mode=0o600)


class Revocations:
    """Certificate ids the issuer withdrew, as a small signed-or-published list."""

    def __init__(self, ids: Iterable[str] = ()) -> None:
        self.ids = set(ids)

    def revoke(self, cert_id: str) -> None:
        self.ids.add(cert_id)

    def to_dict(self) -> Dict[str, Any]:
        return {"version": 1, "revoked": sorted(self.ids)}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Revocations":
        return cls(x for x in raw.get("revoked", []) if isinstance(x, str))


def verify_certificate(cert: Any, issuer_keyids: Mapping[str, bytes], *, now: Optional[float] = None,
                       revoked: Optional[Revocations] = None, scope: Optional[str] = None,
                       pseudonym_public: Optional[bytes] = None, epoch_slack: int = 1) -> Dict[str, Any]:
    """Return the certificate body if it is signed by a known issuer, current
    (within ``epoch_slack`` epochs), not revoked, for ``scope``, and, when
    given, for ``pseudonym_public``."""
    if not isinstance(cert, dict) or not isinstance(cert.get("certificate"), dict):
        raise CredentialError("not a certificate")
    body = cert["certificate"]
    if body.get("version") != CERT_VERSION:
        raise CredentialError("unsupported certificate version")
    issuer = body.get("issuer")
    public = issuer_keyids.get(issuer) if isinstance(issuer, str) else None
    if public is None:
        raise CredentialError("certificate from an unknown issuer")
    try:
        signature = bytes.fromhex(cert.get("signature", ""))
        pseudonym = bytes.fromhex(body.get("pseudonym", ""))
    except (ValueError, TypeError):
        raise CredentialError("certificate fields are not hex")
    if len(pseudonym) != ed25519.KEY_SIZE:
        raise CredentialError("certificate pseudonym is malformed")
    if not ed25519.verify(public, canonical(body), signature):
        raise CredentialError("certificate signature does not verify")
    if cert.get("id") != certificate_id(body):
        raise CredentialError("certificate id does not match its body")
    if revoked is not None and cert["id"] in revoked.ids:
        raise CredentialError("certificate is revoked")
    epoch = body.get("epoch")
    current = epoch_of(now)
    if not isinstance(epoch, int) or abs(epoch - current) > epoch_slack:
        raise CredentialError("certificate epoch {} is not current (now {})".format(epoch, current))
    if scope is not None and body.get("scope") != scope:
        raise CredentialError("certificate scope {!r} is not {!r}".format(body.get("scope"), scope))
    if pseudonym_public is not None and pseudonym != pseudonym_public:
        raise CredentialError("certificate is for a different key")
    return body


def issuer_map(publics: Iterable[str]) -> Dict[str, bytes]:
    """``{keyid: public bytes}`` from hex public keys, for :func:`verify_certificate`."""
    out: Dict[str, bytes] = {}
    for value in publics:
        try:
            public = bytes.fromhex(value)
        except (ValueError, TypeError):
            continue
        if len(public) == ed25519.KEY_SIZE:
            out[ed25519.keyid(public)] = public
    return out


def pseudonyms_for(cert_list: Iterable[Mapping[str, Any]]) -> List[str]:
    return [c["certificate"]["pseudonym"] for c in cert_list if isinstance(c, dict) and "certificate" in c]
