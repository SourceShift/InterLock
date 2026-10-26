"""The control plane's storage seam: one protocol, two implementations.

Every method that touches tenant data takes an ``org_id``. :class:`MemoryStore`
is the reference implementation used by the tests and the live smoke;
:class:`PostgresStore` is the durable one and issues
``SET LOCAL interlock.org_id`` as the first statement of every tenant
transaction, so C0's row-level-security policies apply. Every query still
carries ``org_id`` in its ``WHERE`` clause as well: RLS is the second fence,
not the only one (FR-055).

``psycopg`` is imported lazily by :func:`interlock.cloud.db.connect`; importing
this module needs no site-packages.
"""
from __future__ import annotations

import contextlib
import json
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from . import db as _db
from .db import CloudDependencyMissing, quote_literal  # noqa: F401  (re-exported)
from .enrollment import hash_token, mint_enrollment_token

ROLES = ("owner", "admin", "reviewer", "auditor")
STATUSES = ("active", "invited", "disabled")

#: Host lifecycle. ``revoked`` is terminal for the fleet view; ``disabled``
#: stops heartbeats without discarding the pin.
HOST_STATES = ("active", "disabled", "revoked")


class CrossOrgAccess(Exception):
    """A record was looked up under an org that does not own it."""


class NotFound(Exception):
    """A record does not exist or is not visible to the calling org."""


class ReviewConflict(Exception):
    """A review id was reused for a different binding (``409 review_conflict``)."""


class ReviewNotPending(Exception):
    """A decision arrived for a review that is no longer pending."""

    def __init__(self, status: str, message: Optional[str] = None) -> None:
        super().__init__(message or "review is {}".format(status))
        self.status = status


def _org_id(value: Union[str, "Org", None]) -> Optional[str]:
    """Accept either an Org (as the smoke passes) or its id."""
    if value is None:
        return None
    if isinstance(value, Org):
        return value.id
    return str(value)


def _now_iso(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    import datetime

    return datetime.datetime.fromtimestamp(
        value, tz=datetime.timezone.utc
    ).isoformat()


@dataclass(frozen=True)
class Org:
    id: str
    slug: str
    name: str
    sso_issuer: Optional[str] = None
    sso_client_id: Optional[str] = None
    step_up_policy: str = "webauthn"
    retention_days: int = 365

    def public(self) -> Dict[str, Any]:
        """The fields a route may return; no secrets live here anyway."""
        return {
            "id": self.id,
            "slug": self.slug,
            "name": self.name,
            "step_up_policy": self.step_up_policy,
            "retention_days": self.retention_days,
        }


@dataclass
class User:
    org_id: str
    id: str
    issuer: str
    subject: str
    email: str
    role: str
    status: str = "active"
    created: Optional[float] = None

    def public(self) -> Dict[str, Any]:
        """A member view with no session or credential material."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "status": self.status,
        }


@dataclass
class Session:
    org_id: str
    id: str
    user_id: str
    token_hash: str
    csrf_hash: str
    expires: float
    created: float = 0.0
    last_seen: float = 0.0
    step_up_at: Optional[float] = None
    step_up_method: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class AuditEntry:
    org_id: str
    id: str
    event: str
    actor: Optional[str]
    detail: Dict[str, Any] = field(default_factory=dict)
    created: float = 0.0

    def public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "event": self.event,
            "actor": self.actor,
            "detail": dict(self.detail),
            "created": _now_iso(self.created),
        }


@dataclass
class EnrollmentToken:
    """A single-use enrollment token; the raw value is never stored."""

    org_id: str
    id: str
    token_hash: str
    host_name: Optional[str] = None
    expires: float = 0.0
    used_at: Optional[float] = None

    def public(self) -> Dict[str, Any]:
        """The safe view: no hash and no raw token."""
        return {
            "id": self.id,
            "host_name": self.host_name,
            "expires_at": _now_iso(self.expires),
            "used": self.used_at is not None,
        }


@dataclass
class Host:
    """A registered host and the public keys it pinned at enrollment.

    ``owner_subject`` is required by the schema but C2 has no column that
    carries the token's creator across the enroll request (the plan forbids a
    schema change), so the enrolling admin is recorded in ``audit_log`` and
    the host carries the documented sentinel ``enrollment-token:<token id>``.
    """

    org_id: str
    id: str
    name: str
    owner_subject: str
    public_keys: List[Dict[str, Any]] = field(default_factory=list)
    state: str = "active"
    last_seen: Optional[float] = None

    def public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state,
            "owner_subject": self.owner_subject,
            "public_keys": [dict(pin) for pin in self.public_keys],
            "last_seen": _now_iso(self.last_seen),
        }


@dataclass
class AgentKey:
    """One agent key; ``secret_hash`` is the only secret-derived value."""

    org_id: str
    id: str
    prefix: str
    secret_hash: str
    host_id: str
    scopes: List[str] = field(default_factory=list)
    expires: Optional[float] = None
    revoked_at: Optional[float] = None

    def public(self) -> Dict[str, Any]:
        """The fleet view: prefix and timestamps, never the hash."""
        return {
            "id": self.id,
            "prefix": self.prefix,
            "host_id": self.host_id,
            "scopes": list(self.scopes),
            "expires_at": _now_iso(self.expires),
            "revoked_at": _now_iso(self.revoked_at),
            "revoked": self.revoked_at is not None,
        }


PLANE_REVIEW_STATUSES = (
    "pending", "approved", "rejected", "revoked", "expired",
)


@dataclass
class ReviewRecord:
    """One uploaded review as the plane stores it (preview is ciphertext)."""

    org_id: str
    host_id: str
    id: str
    binding: str
    status: str
    action: str
    phase: str
    principal: Optional[str]
    requester: Optional[str]
    policy_id: Optional[str]
    reason: Optional[str]
    args_digest: Optional[str]
    preview_enc: Optional[bytes]
    mask_counts: Dict[str, int]
    metadata: Dict[str, Any]
    created: float
    pending_until: Optional[float]
    decided: Optional[float] = None
    decided_by: Optional[str] = None
    approval_until: Optional[float] = None
    approvers: List[str] = field(default_factory=list)
    min_approvals: int = 1
    allow_self_approval: bool = True
    approval_ttl: float = 900.0

    def public(self) -> Dict[str, Any]:
        """The list view: no preview and no ciphertext ever leaves here."""
        return {
            "id": self.id,
            "host_id": self.host_id,
            "status": self.status,
            "action": self.action,
            "phase": self.phase,
            "principal": self.principal,
            "requester": self.requester,
            "policy_id": self.policy_id,
            "reason": self.reason,
            "args_digest": self.args_digest,
            "mask_counts": dict(self.mask_counts),
            "created": _now_iso(self.created),
            "pending_until": _now_iso(self.pending_until),
            "decided": _now_iso(self.decided),
            "decided_by": self.decided_by,
            "approval_until": _now_iso(self.approval_until),
            "approvers": list(self.approvers),
            "min_approvals": self.min_approvals,
            "allow_self_approval": self.allow_self_approval,
            "approval_ttl": self.approval_ttl,
        }


@dataclass
class DecisionRecord:
    """One reviewer's decision on a review."""

    org_id: str
    id: str
    review_id: str
    reviewer: str
    step_up_method: str
    step_up_at: float
    decision: str
    grant_id: Optional[str] = None
    grant_seq: Optional[int] = None
    approve_anyway: bool = False
    reason: Optional[str] = None


@dataclass
class GrantRecord:
    """A signed grant stored for delivery to one host."""

    org_id: str
    host_id: str
    id: str
    review_id: str
    seq: int
    envelope: Dict[str, Any]
    delivered_at: Optional[float] = None
    acked_at: Optional[float] = None


def keys_version(keys: List[AgentKey]) -> int:
    """A monotonic per-host key generation, derived without a new column.

    Every issued key adds one and every newly revoked key adds one, so a
    rotation or revocation always moves the counter forward while the schema
    stays exactly ``001_init.sql``.
    """
    return len(keys) + sum(1 for key in keys if key.revoked_at is not None)


class MemoryStore:
    """Thread-safe in-memory reference store.

    Records are keyed by ``(org_id, id)``. Looking a record up under the wrong
    org raises :class:`CrossOrgAccess` rather than returning ``None``: the
    cross-org matrix wants to prove the boundary is enforced, and a silent
    miss would make a broken lookup look like an empty result.
    """

    def __init__(self, orgs: Optional[Dict[str, Org]] = None,
                 users: Optional[Dict[Tuple[str, str], User]] = None,
                 sessions: Optional[Dict[Tuple[str, str], Session]] = None,
                 audit: Optional[List[AuditEntry]] = None) -> None:
        self._lock = threading.RLock()
        self.orgs: Dict[str, Org] = dict(orgs or {})
        self.users: Dict[Tuple[str, str], User] = dict(users or {})
        self.sessions: Dict[Tuple[str, str], Session] = dict(sessions or {})
        self.audit: List[AuditEntry] = list(audit or [])
        self.enrollment_tokens: Dict[Tuple[str, str], EnrollmentToken] = {}
        self.hosts: Dict[Tuple[str, str], Host] = {}
        self.agent_keys: Dict[Tuple[str, str], AgentKey] = {}
        self._domains: Dict[Tuple[str, str], bool] = {}
        #: (org_id, host_id, review_id) -> ReviewRecord.
        self.reviews: Dict[Tuple[str, str, str], ReviewRecord] = {}
        self.decisions: List[DecisionRecord] = []
        #: (org_id, grant_id) -> GrantRecord (plane-side delivery state).
        self.grants: Dict[Tuple[str, str], GrantRecord] = {}
        #: (org_id, host_id) -> (last_seq, last_sig).
        self.grant_heads: Dict[Tuple[str, str], Tuple[int, str]] = {}

    # -- orgs -----------------------------------------------------------
    def create_org(self, slug: str, name: str, *, id: Optional[str] = None,
                   sso_issuer: Optional[str] = None,
                   sso_client_id: Optional[str] = None) -> Org:
        with self._lock:
            if any(org.slug == slug for org in self.orgs.values()):
                raise ValueError("org slug already exists: {!r}".format(slug))
            org = Org(id=id or uuid.uuid4().hex, slug=slug, name=name,
                      sso_issuer=sso_issuer, sso_client_id=sso_client_id)
            self.orgs[org.id] = org
            return org

    def org_by_slug(self, slug: str) -> Optional[Org]:
        with self._lock:
            for org in self.orgs.values():
                if org.slug == slug:
                    return org
            return None

    def org_by_id(self, org_id: str) -> Optional[Org]:
        with self._lock:
            return self.orgs.get(_org_id(org_id) or "")

    def org_by_sso_issuer(self, issuer: str) -> Optional[Org]:
        with self._lock:
            for org in self.orgs.values():
                if org.sso_issuer == issuer:
                    return org
            return None

    def update_org(self, org_id: str, *, name: Optional[str] = None,
                   step_up_policy: Optional[str] = None) -> Org:
        with self._lock:
            org = self.orgs.get(_org_id(org_id) or "")
            if org is None:
                raise NotFound("org not found")
            updated = Org(
                id=org.id, slug=org.slug,
                name=org.name if name is None else name,
                sso_issuer=org.sso_issuer, sso_client_id=org.sso_client_id,
                step_up_policy=(org.step_up_policy if step_up_policy is None
                                else step_up_policy),
                retention_days=org.retention_days,
            )
            self.orgs[org.id] = updated
            return updated

    def add_org_domain(self, org_id: str, domain: str, *,
                       verified: bool = True) -> None:
        with self._lock:
            key = (_org_id(org_id) or "", domain.lower())
            self._domains[key] = bool(verified)

    def verified_domain(self, org_id: str, email: str) -> bool:
        oid = _org_id(org_id) or ""
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if not domain:
            return False
        with self._lock:
            return bool(self._domains.get((oid, domain), False))

    # -- users ----------------------------------------------------------
    def _other_org_user(self, org_id: str, user_id: str) -> Optional[User]:
        for (other_org, other_id), user in self.users.items():
            if other_id == user_id and other_org != org_id:
                return user
        return None

    def create_user(self, org_id: Union[str, Org], issuer: str, subject: str, *,
                    email: str = "", role: str = "auditor",
                    status: str = "active",
                    id: Optional[str] = None) -> User:
        oid = _org_id(org_id)
        if oid is None or oid not in self.orgs:
            raise NotFound("org not found")
        if role not in ROLES:
            raise ValueError("unknown role: {!r}".format(role))
        if status not in STATUSES:
            raise ValueError("unknown status: {!r}".format(status))
        with self._lock:
            user = User(org_id=oid, id=id or secrets.token_hex(8),
                        issuer=issuer, subject=subject, email=email,
                        role=role, status=status, created=_epoch())
            for existing in self.users.values():
                if existing.org_id == oid and existing.issuer == issuer \
                        and existing.subject == subject:
                    raise ValueError("user already exists for issuer/subject")
            self.users[(oid, user.id)] = user
            return user

    def user_by_issuer_subject(self, org_id: str, issuer: str,
                               subject: str) -> Optional[User]:
        oid = _org_id(org_id) or ""
        with self._lock:
            for user in self.users.values():
                if user.org_id == oid and user.issuer == issuer \
                        and user.subject == subject:
                    return user
        return None

    def user_by_email(self, org_id: str, email: str) -> Optional[User]:
        oid = _org_id(org_id) or ""
        with self._lock:
            for user in self.users.values():
                if user.org_id == oid and user.email.lower() == email.lower():
                    return user
        return None

    def user_by_id(self, org_id: str, user_id: str) -> Optional[User]:
        oid = _org_id(org_id) or ""
        with self._lock:
            user = self.users.get((oid, user_id))
            if user is not None:
                return user
            if self._other_org_user(oid, user_id) is not None:
                raise CrossOrgAccess(
                    "user {!r} belongs to another org".format(user_id)
                )
            return None

    def list_users(self, org_id: str) -> List[User]:
        oid = _org_id(org_id) or ""
        with self._lock:
            return sorted(
                (u for u in self.users.values() if u.org_id == oid),
                key=lambda u: u.id,
            )

    def set_user_status(self, org_id: str, user_id: str, status: str) -> User:
        if status not in STATUSES:
            raise ValueError("unknown status: {!r}".format(status))
        oid = _org_id(org_id) or ""
        with self._lock:
            user = self.users.get((oid, user_id))
            if user is None:
                if self._other_org_user(oid, user_id) is not None:
                    raise CrossOrgAccess("user belongs to another org")
                raise NotFound("user not found")
            updated = User(org_id=user.org_id, id=user.id, issuer=user.issuer,
                           subject=user.subject, email=user.email,
                           role=user.role, status=status, created=user.created)
            self.users[(oid, user_id)] = updated
            return updated

    def set_user_role(self, org_id: str, user_id: str, role: str) -> User:
        if role not in ROLES:
            raise ValueError("unknown role: {!r}".format(role))
        oid = _org_id(org_id) or ""
        with self._lock:
            user = self.users.get((oid, user_id))
            if user is None:
                if self._other_org_user(oid, user_id) is not None:
                    raise CrossOrgAccess("user belongs to another org")
                raise NotFound("user not found")
            updated = User(org_id=user.org_id, id=user.id, issuer=user.issuer,
                           subject=user.subject, email=user.email, role=role,
                           status=user.status, created=user.created)
            self.users[(oid, user_id)] = updated
            return updated

    def delete_user(self, org_id: str, user_id: str) -> bool:
        oid = _org_id(org_id) or ""
        with self._lock:
            if (oid, user_id) not in self.users:
                if self._other_org_user(oid, user_id) is not None:
                    raise CrossOrgAccess("user belongs to another org")
                return False
            del self.users[(oid, user_id)]
            for key in [k for k in self.sessions if k[0] == oid
                        and self.sessions[k].user_id == user_id]:
                self.sessions.pop(key, None)
            return True

    # -- sessions -------------------------------------------------------
    def create_session(self, org_id: str, user_id: str, token_hash: str,
                       csrf_hash: str, expires: float, *,
                       id: Optional[str] = None,
                       created: Optional[float] = None,
                       last_seen: Optional[float] = None,
                       step_up_at: Optional[float] = None,
                       step_up_method: Optional[str] = None,
                       ip: Optional[str] = None,
                       user_agent: Optional[str] = None) -> Session:
        oid = _org_id(org_id) or ""
        created_at = _epoch() if created is None else created
        seen_at = created_at if last_seen is None else last_seen
        with self._lock:
            session = Session(
                org_id=oid, id=id or secrets.token_hex(16), user_id=user_id,
                token_hash=token_hash, csrf_hash=csrf_hash, expires=expires,
                created=created_at, last_seen=seen_at,
                step_up_at=step_up_at, step_up_method=step_up_method,
                ip=ip, user_agent=user_agent,
            )
            self.sessions[(oid, session.id)] = session
            return session

    def session_by_token_hash(self, token_hash: str,
                              org_id: Optional[str] = None) -> Optional[Session]:
        with self._lock:
            found = None
            for session in self.sessions.values():
                if session.token_hash == token_hash:
                    found = session
                    break
            if found is None:
                return None
            if org_id is not None and found.org_id != _org_id(org_id):
                raise CrossOrgAccess("session belongs to another org")
            return found

    def touch_session(self, org_id: str, session_id: str,
                      last_seen: Optional[float] = None,
                      step_up_at: Optional[float] = None,
                      step_up_method: Optional[str] = None) -> Optional[Session]:
        oid = _org_id(org_id) or ""
        with self._lock:
            session = self.sessions.get((oid, session_id))
            if session is None:
                return None
            session.last_seen = _epoch() if last_seen is None else last_seen
            if step_up_at is not None:
                session.step_up_at = step_up_at
            if step_up_method is not None:
                session.step_up_method = step_up_method
            return session

    def delete_session(self, org_id: str, session_id: str) -> bool:
        oid = _org_id(org_id) or ""
        with self._lock:
            return self.sessions.pop((oid, session_id), None) is not None

    def delete_user_sessions(self, org_id: str, user_id: str) -> int:
        oid = _org_id(org_id) or ""
        with self._lock:
            keys = [k for k, s in self.sessions.items()
                    if k[0] == oid and s.user_id == user_id]
            for key in keys:
                self.sessions.pop(key, None)
            return len(keys)

    # -- audit ----------------------------------------------------------
    def audit_append(self, org_id: str, event: str, actor: Optional[str] = None,
                     detail: Optional[Dict[str, Any]] = None) -> AuditEntry:
        oid = _org_id(org_id) or ""
        with self._lock:
            entry = AuditEntry(org_id=oid, id=secrets.token_hex(8),
                               event=event, actor=actor,
                               detail=dict(detail or {}), created=_epoch())
            self.audit.append(entry)
            return entry

    def audit_list(self, org_id: str) -> List[AuditEntry]:
        oid = _org_id(org_id) or ""
        with self._lock:
            return [entry for entry in self.audit if entry.org_id == oid]

    # -- enrollment tokens ---------------------------------------------
    def create_enrollment_token(self, org_id: Union[str, Org],
                                host_name: Optional[str] = None, *,
                                ttl: float = 3600,
                                created_by: Optional[str] = None,
                                now: Optional[float] = None,
                                id: Optional[str] = None) -> Tuple[str, str]:
        """Mint a token and store only its hash; returns ``(id, raw)``.

        ``created_by`` is intentionally not stored: the schema has no column
        for it and the calling route records the creator in ``audit_log``
        beside the token id, never the token value.
        """
        oid = _org_id(org_id) or ""
        if oid not in self.orgs:
            raise NotFound("org not found")
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        at = _epoch() if now is None else float(now)
        token_id = id or "et_" + secrets.token_hex(8)
        raw = mint_enrollment_token(oid)
        token = EnrollmentToken(org_id=oid, id=token_id,
                                token_hash=hash_token(raw),
                                host_name=host_name, expires=at + float(ttl))
        with self._lock:
            self.enrollment_tokens[(oid, token_id)] = token
        return token_id, raw

    def consume_enrollment_token(self, raw: str, *,
                                 now: Optional[float] = None
                                 ) -> Optional[EnrollmentToken]:
        """Mark a valid token used exactly once; a second call returns None."""
        from .enrollment import enrollment_org

        org_id = enrollment_org(raw)
        if org_id is None:
            return None
        at = _epoch() if now is None else float(now)
        digest = hash_token(raw)
        with self._lock:
            for token in self.enrollment_tokens.values():
                if token.org_id == org_id and token.token_hash == digest:
                    if token.used_at is not None or at >= token.expires:
                        return None
                    token.used_at = at
                    return token
        return None

    def enrollment_token_by_id(self, org_id: str,
                               token_id: str) -> Optional[EnrollmentToken]:
        oid = _org_id(org_id) or ""
        with self._lock:
            return self.enrollment_tokens.get((oid, token_id))

    # -- hosts ----------------------------------------------------------
    def create_host(self, org_id: Union[str, Org], name: str, *,
                    owner_subject: str, public_keys: Optional[List[Dict[str, Any]]] = None,
                    state: str = "active", last_seen: Optional[float] = None,
                    id: Optional[str] = None) -> Host:
        oid = _org_id(org_id) or ""
        if oid not in self.orgs:
            raise NotFound("org not found")
        if state not in HOST_STATES:
            raise ValueError("unknown host state: {!r}".format(state))
        with self._lock:
            host = Host(org_id=oid, id=id or "host_" + secrets.token_hex(12),
                        name=name, owner_subject=owner_subject,
                        public_keys=list(public_keys or []), state=state,
                        last_seen=last_seen)
            self.hosts[(oid, host.id)] = host
            return host

    def _other_org_host(self, org_id: str, host_id: str) -> Optional[Host]:
        for (other_org, other_id), host in self.hosts.items():
            if other_id == host_id and other_org != org_id:
                return host
        return None

    def host_by_id(self, org_id: str, host_id: str) -> Optional[Host]:
        oid = _org_id(org_id) or ""
        with self._lock:
            host = self.hosts.get((oid, host_id))
            if host is not None:
                return host
            if self._other_org_host(oid, host_id) is not None:
                raise CrossOrgAccess(
                    "host {!r} belongs to another org".format(host_id)
                )
            return None

    def list_hosts(self, org_id: str) -> List[Host]:
        oid = _org_id(org_id) or ""
        with self._lock:
            return sorted(
                (host for host in self.hosts.values() if host.org_id == oid),
                key=lambda host: host.id,
            )

    def set_host_state(self, org_id: str, host_id: str, state: str) -> Host:
        if state not in HOST_STATES:
            raise ValueError("unknown host state: {!r}".format(state))
        oid = _org_id(org_id) or ""
        with self._lock:
            host = self.hosts.get((oid, host_id))
            if host is None:
                if self._other_org_host(oid, host_id) is not None:
                    raise CrossOrgAccess("host belongs to another org")
                raise NotFound("host not found")
            host.state = state
            return host

    def touch_host(self, org_id: str, host_id: str,
                   last_seen: Optional[float] = None) -> Optional[Host]:
        oid = _org_id(org_id) or ""
        with self._lock:
            host = self.hosts.get((oid, host_id))
            if host is None:
                if self._other_org_host(oid, host_id) is not None:
                    raise CrossOrgAccess("host belongs to another org")
                return None
            host.last_seen = _epoch() if last_seen is None else float(last_seen)
            return host

    # -- agent keys -----------------------------------------------------
    def create_agent_key(self, org_id: str, host_id: str, *,
                         prefix: str, secret_hash: str,
                         scopes: Optional[List[str]] = None,
                         expires: Optional[float] = None,
                         id: Optional[str] = None) -> AgentKey:
        oid = _org_id(org_id) or ""
        with self._lock:
            if (oid, host_id) not in self.hosts:
                if self._other_org_host(oid, host_id) is not None:
                    raise CrossOrgAccess("host belongs to another org")
                raise NotFound("host not found")
            key = AgentKey(org_id=oid, id=id or "key_" + secrets.token_hex(8),
                           prefix=prefix, secret_hash=secret_hash,
                           host_id=host_id, scopes=list(scopes or []),
                           expires=expires, revoked_at=None)
            self.agent_keys[(oid, key.id)] = key
            return key

    def agent_key_by_prefix(self, prefix: str, *,
                            org_id: Optional[str] = None
                            ) -> Optional[AgentKey]:
        """Look up a key by its public prefix.

        ``org_id`` is optional only for :class:`MemoryStore`; the Postgres
        implementation requires it because row-level security hides rows
        until the org context is set.
        """
        with self._lock:
            found = None
            for key in self.agent_keys.values():
                if key.prefix != prefix:
                    continue
                if org_id is not None and key.org_id != _org_id(org_id):
                    continue
                found = key
                break
            return found

    def agent_key_by_id(self, org_id: str, key_id: str) -> Optional[AgentKey]:
        oid = _org_id(org_id) or ""
        with self._lock:
            key = self.agent_keys.get((oid, key_id))
            if key is not None:
                return key
            for (other_org, other_id), other in self.agent_keys.items():
                if other_id == key_id and other_org != oid:
                    raise CrossOrgAccess("agent key belongs to another org")
            return None

    def list_agent_keys(self, org_id: str,
                        host_id: Optional[str] = None) -> List[AgentKey]:
        oid = _org_id(org_id) or ""
        with self._lock:
            return sorted(
                (key for key in self.agent_keys.values()
                 if key.org_id == oid
                 and (host_id is None or key.host_id == host_id)),
                key=lambda key: key.id,
            )

    def retire_agent_key(self, org_id: str, key_id: str, *,
                         expires: float) -> AgentKey:
        """Set the key's expiry; rotation retires the old key this way."""
        oid = _org_id(org_id) or ""
        with self._lock:
            key = self.agent_keys.get((oid, key_id))
            if key is None:
                raise NotFound("agent key not found")
            key.expires = float(expires)
            return key

    def revoke_agent_key(self, org_id: str, key_id: str, *,
                         now: Optional[float] = None) -> AgentKey:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._lock:
            key = self.agent_keys.get((oid, key_id))
            if key is None:
                raise NotFound("agent key not found")
            if key.revoked_at is None:
                key.revoked_at = at
            return key

    def revoke_host_keys(self, org_id: str, host_id: str, *,
                         now: Optional[float] = None) -> int:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._lock:
            count = 0
            for key in self.agent_keys.values():
                if key.org_id == oid and key.host_id == host_id \
                        and key.revoked_at is None:
                    key.revoked_at = at
                    count += 1
            return count

    # -- reviews and grants (C3) ----------------------------------------
    def upsert_review(self, org_id: Union[str, Org], host_id: str,
                      review_id: str, *, binding: str, action: str,
                      phase: str, principal: Optional[str] = None,
                      requester: Optional[str] = None,
                      policy_id: Optional[str] = None,
                      reason: Optional[str] = None,
                      args_digest: Optional[str] = None,
                      preview_enc: Optional[bytes] = None,
                      mask_counts: Optional[Dict[str, int]] = None,
                      metadata: Optional[Dict[str, Any]] = None,
                      created: Optional[float] = None,
                      pending_until: Optional[float] = None,
                      min_approvals: int = 1,
                      allow_self_approval: bool = True,
                      approval_ttl: float = 900.0) -> ReviewRecord:
        oid = _org_id(org_id) or ""
        with self._lock:
            if (oid, host_id) not in self.hosts:
                if self._other_org_host(oid, host_id) is not None:
                    raise CrossOrgAccess("host belongs to another org")
                raise NotFound("host not found")
            key = (oid, host_id, review_id)
            existing = self.reviews.get(key)
            if existing is not None:
                if existing.binding != binding:
                    raise ReviewConflict(
                        "review {} already exists with another binding".format(
                            review_id))
                return existing
            record = ReviewRecord(
                org_id=oid, host_id=host_id, id=review_id,
                binding=binding, status="pending", action=action, phase=phase,
                principal=principal, requester=requester,
                policy_id=policy_id, reason=reason, args_digest=args_digest,
                preview_enc=preview_enc, mask_counts=dict(mask_counts or {}),
                metadata=dict(metadata or {}),
                created=_epoch() if created is None else float(created),
                pending_until=None if pending_until is None else float(pending_until),
                min_approvals=int(min_approvals),
                allow_self_approval=bool(allow_self_approval),
                approval_ttl=float(approval_ttl),
            )
            self.reviews[key] = record
            return record

    def _other_org_review(self, org_id: str, review_id: str) -> Optional[ReviewRecord]:
        for (other_org, _host, other_id), record in self.reviews.items():
            if other_id == review_id and other_org != org_id:
                return record
        return None

    def review_by_id(self, org_id: str, review_id: str,
                     host_id: Optional[str] = None) -> Optional[ReviewRecord]:
        oid = _org_id(org_id) or ""
        with self._lock:
            if host_id is not None:
                record = self.reviews.get((oid, host_id, review_id))
                if record is not None:
                    return record
            else:
                for (record_org, _host, record_id), record in self.reviews.items():
                    if record_org == oid and record_id == review_id:
                        return record
            if self._other_org_review(oid, review_id) is not None:
                raise CrossOrgAccess(
                    "review {!r} belongs to another org".format(review_id))
            return None

    def list_reviews(self, org_id: str, *, status: Optional[str] = None,
                     host_id: Optional[str] = None, cursor: int = 0,
                     limit: int = 50) -> Tuple[List[ReviewRecord], Optional[int]]:
        oid = _org_id(org_id) or ""
        if (status is not None and status not in PLANE_REVIEW_STATUSES) or limit < 1:
            raise ValueError("invalid review filter")
        with self._lock:
            rows = [record for record in self.reviews.values()
                    if record.org_id == oid
                    and (status is None or record.status == status)
                    and (host_id is None or record.host_id == host_id)]
        rows.sort(key=lambda record: (-record.created, record.id))
        start = max(0, int(cursor))
        page = rows[start:start + int(limit)]
        next_cursor = start + len(page) if start + len(page) < len(rows) else None
        return page, next_cursor

    def record_decision(self, org_id: str, review_id: str, *, reviewer: str,
                        step_up_method: str, step_up_at: float,
                        decision: str, grant_id: Optional[str] = None,
                        grant_seq: Optional[int] = None,
                        approve_anyway: bool = False,
                        reason: Optional[str] = None,
                        status: Optional[str] = None,
                        decided_by: Optional[str] = None,
                        approval_until: Optional[float] = None,
                        now: Optional[float] = None) -> DecisionRecord:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._lock:
            record = None
            for (record_org, _host, record_id), candidate in self.reviews.items():
                if record_org == oid and record_id == review_id:
                    record = candidate
                    break
            if record is None:
                raise NotFound("review not found")
            if reviewer not in record.approvers:
                record.approvers.append(reviewer)
            if status is not None:
                record.status = status
                record.decided = at
                record.decided_by = decided_by or reviewer
                if approval_until is not None:
                    record.approval_until = float(approval_until)
            entry = DecisionRecord(
                org_id=oid, id="dec_" + secrets.token_hex(8),
                review_id=review_id, reviewer=reviewer,
                step_up_method=step_up_method, step_up_at=float(step_up_at),
                decision=decision, grant_id=grant_id, grant_seq=grant_seq,
                approve_anyway=bool(approve_anyway), reason=reason,
            )
            self.decisions.append(entry)
            return entry

    def pending_decisions(self, org_id: str, review_id: str) -> List[str]:
        oid = _org_id(org_id) or ""
        with self._lock:
            return sorted({entry.reviewer for entry in self.decisions
                           if entry.org_id == oid and entry.review_id == review_id
                           and entry.decision == "approve"})

    def grant_head(self, org_id: str, host_id: str) -> Dict[str, Any]:
        oid = _org_id(org_id) or ""
        with self._lock:
            seq, sig = self.grant_heads.get((oid, host_id), (0, "GENESIS"))
            return {"seq": int(seq), "sig": sig}

    def next_grant_seq(self, org_id: str, host_id: str) -> Tuple[int, str]:
        oid = _org_id(org_id) or ""
        with self._lock:
            seq, sig = self.grant_heads.get((oid, host_id), (0, "GENESIS"))
            return int(seq) + 1, sig

    def add_grant(self, org_id: str, host_id: str, *, grant_id: str,
                  review_id: str, seq: int, envelope: Dict[str, Any],
                  now: Optional[float] = None) -> GrantRecord:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._lock:
            existing = self.grants.get((oid, grant_id))
            if existing is not None:
                return existing
            record = GrantRecord(
                org_id=oid, host_id=host_id, id=grant_id, review_id=review_id,
                seq=int(seq), envelope=dict(envelope), delivered_at=at,
            )
            self.grants[(oid, grant_id)] = record
            current, _sig = self.grant_heads.get((oid, host_id), (0, "GENESIS"))
            if int(seq) >= current:
                self.grant_heads[(oid, host_id)] = (
                    int(seq), str(envelope.get("sig") or ""))
            return record

    def grants_after(self, org_id: str, host_id: str, seq: int) -> List[Dict[str, Any]]:
        oid = _org_id(org_id) or ""
        with self._lock:
            records = [record for record in self.grants.values()
                       if record.org_id == oid and record.host_id == host_id
                       and record.seq > int(seq)]
        records.sort(key=lambda record: record.seq)
        return [dict(record.envelope) for record in records]

    def ack_grants(self, org_id: str, host_id: str,
                   ids: List[str], *, now: Optional[float] = None) -> int:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._lock:
            acked = 0
            for grant_id in ids:
                record = self.grants.get((oid, grant_id))
                if record is None or record.host_id != host_id:
                    continue
                if record.acked_at is None:
                    record.acked_at = at
                    acked += 1
            return acked

    def last_ack_seq(self, org_id: str, host_id: str) -> int:
        oid = _org_id(org_id) or ""
        with self._lock:
            return max((record.seq for record in self.grants.values()
                        if record.org_id == oid and record.host_id == host_id
                        and record.acked_at is not None), default=0)

    def host_keys(self, org_id: str, host_id: str) -> List[Dict[str, Any]]:
        host = self.host_by_id(org_id, host_id)
        return [] if host is None else [dict(pin) for pin in host.public_keys]

    # -- RLS context ----------------------------------------------------
    @contextlib.contextmanager
    def set_org_context(self, org_id: str) -> Iterator["MemoryStore"]:
        """No-op context manager; here so both stores share one call shape."""
        yield self


class PostgresStore:
    """Durable store. Every tenant transaction starts with the RLS setting."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    # -- connection helpers --------------------------------------------
    @contextlib.contextmanager
    def _transaction(self, org_id: str) -> Iterator[Any]:
        conn = _db.connect(self.dsn)
        try:
            with conn.cursor() as cur:
                # First statement: the value is a safely quoted literal because
                # SET LOCAL does not accept a placeholder.
                cur.execute(
                    "SET LOCAL interlock.org_id = " + quote_literal(org_id)
                )
                yield cur
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @contextlib.contextmanager
    def _connection(self) -> Iterator[Any]:
        """A connection for statements on the global ``orgs`` table."""
        conn = _db.connect(self.dsn)
        try:
            yield conn
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @contextlib.contextmanager
    def set_org_context(self, org_id: str) -> Iterator[Any]:
        with self._transaction(org_id) as cur:
            yield cur

    # -- orgs -----------------------------------------------------------
    # The `orgs` table is the tenant registry itself, not tenant data: its
    # primary key *is* the org id, so it carries no `org_id` column and gets
    # no row-level-security policy (see 001_init.sql). Every other table in
    # this class is org-scoped and carries `org_id` in its WHERE clause as
    # well as in the RLS setting.
    def create_org(self, slug: str, name: str, *, id: Optional[str] = None,
                   sso_issuer: Optional[str] = None,
                   sso_client_id: Optional[str] = None) -> Org:
        org = Org(id=id or uuid.uuid4().hex, slug=slug, name=name,
                  sso_issuer=sso_issuer, sso_client_id=sso_client_id)
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO orgs (id, slug, name, sso_issuer, sso_client_id) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (org.id, org.slug, org.name, org.sso_issuer,
                     org.sso_client_id),
                )
        return org

    def _org_row(self, row: Tuple[Any, ...]) -> Org:
        return Org(id=row[0], slug=row[1], name=row[2], sso_issuer=row[3],
                   sso_client_id=row[4], step_up_policy=row[5],
                   retention_days=row[6])

    _ORG_COLUMNS = ("id, slug, name, sso_issuer, sso_client_id, "
                    "step_up_policy, retention_days")

    def org_by_slug(self, slug: str) -> Optional[Org]:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT " + self._ORG_COLUMNS + " FROM orgs WHERE slug = %s",
                    (slug,),
                )
                row = cur.fetchone()
        return self._org_row(row) if row else None

    def org_by_sso_issuer(self, issuer: str) -> Optional[Org]:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT " + self._ORG_COLUMNS +
                    " FROM orgs WHERE sso_issuer = %s", (issuer,),
                )
                row = cur.fetchone()
        return self._org_row(row) if row else None

    def org_by_id(self, org_id: str) -> Optional[Org]:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT " + self._ORG_COLUMNS + " FROM orgs WHERE id = %s",
                    (org_id,),
                )
                row = cur.fetchone()
        return self._org_row(row) if row else None

    def update_org(self, org_id: str, *, name: Optional[str] = None,
                   step_up_policy: Optional[str] = None) -> Org:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE orgs SET name = COALESCE(%s, name), "
                    "step_up_policy = COALESCE(%s, step_up_policy) "
                    "WHERE id = %s",
                    (name, step_up_policy, org_id),
                )
                cur.execute(
                    "SELECT " + self._ORG_COLUMNS + " FROM orgs WHERE id = %s",
                    (org_id,),
                )
                row = cur.fetchone()
        if row is None:
            raise NotFound("org not found")
        return self._org_row(row)

    def add_org_domain(self, org_id: str, domain: str, *,
                       verified: bool = True) -> None:
        with self._transaction(org_id) as cur:
            cur.execute(
                "INSERT INTO org_domains (org_id, domain, verified_at) "
                "VALUES (%s, %s, CASE WHEN %s THEN now() ELSE NULL END) "
                "ON CONFLICT (org_id, domain) DO UPDATE "
                "SET verified_at = EXCLUDED.verified_at",
                (org_id, domain.lower(), verified),
            )

    def verified_domain(self, org_id: str, email: str) -> bool:
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if not domain:
            return False
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT 1 FROM org_domains WHERE org_id = %s AND domain = %s "
                "AND verified_at IS NOT NULL",
                (org_id, domain),
            )
            return cur.fetchone() is not None

    # -- users ----------------------------------------------------------
    _USER_COLUMNS = "org_id, id, issuer, subject, email, role, status"

    def _user_row(self, row: Tuple[Any, ...]) -> User:
        return User(org_id=row[0], id=row[1], issuer=row[2], subject=row[3],
                    email=row[4], role=row[5], status=row[6])

    def create_user(self, org_id: Union[str, Org], issuer: str, subject: str, *,
                    email: str = "", role: str = "auditor",
                    status: str = "active",
                    id: Optional[str] = None) -> User:
        oid = _org_id(org_id) or ""
        if role not in ROLES:
            raise ValueError("unknown role: {!r}".format(role))
        user = User(org_id=oid, id=id or secrets.token_hex(8), issuer=issuer,
                    subject=subject, email=email, role=role, status=status,
                    created=_epoch())
        with self._transaction(oid) as cur:
            cur.execute(
                "INSERT INTO users (org_id, id, issuer, subject, email, role, "
                "status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (oid, user.id, issuer, subject, email, role, status),
            )
        return user

    def user_by_issuer_subject(self, org_id: str, issuer: str,
                               subject: str) -> Optional[User]:
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT " + self._USER_COLUMNS + " FROM users "
                "WHERE org_id = %s AND issuer = %s AND subject = %s",
                (org_id, issuer, subject),
            )
            row = cur.fetchone()
        return self._user_row(row) if row else None

    def user_by_email(self, org_id: str, email: str) -> Optional[User]:
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT " + self._USER_COLUMNS + " FROM users "
                "WHERE org_id = %s AND lower(email) = lower(%s)",
                (org_id, email),
            )
            row = cur.fetchone()
        return self._user_row(row) if row else None

    def user_by_id(self, org_id: str, user_id: str) -> Optional[User]:
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT " + self._USER_COLUMNS + " FROM users "
                "WHERE org_id = %s AND id = %s",
                (org_id, user_id),
            )
            row = cur.fetchone()
        return self._user_row(row) if row else None

    def list_users(self, org_id: str) -> List[User]:
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT " + self._USER_COLUMNS + " FROM users "
                "WHERE org_id = %s ORDER BY id",
                (org_id,),
            )
            return [self._user_row(row) for row in cur.fetchall()]

    def set_user_status(self, org_id: str, user_id: str, status: str) -> User:
        if status not in STATUSES:
            raise ValueError("unknown status: {!r}".format(status))
        with self._transaction(org_id) as cur:
            cur.execute(
                "UPDATE users SET status = %s WHERE org_id = %s AND id = %s",
                (status, org_id, user_id),
            )
            cur.execute(
                "SELECT " + self._USER_COLUMNS + " FROM users "
                "WHERE org_id = %s AND id = %s",
                (org_id, user_id),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFound("user not found")
        return self._user_row(row)

    def set_user_role(self, org_id: str, user_id: str, role: str) -> User:
        if role not in ROLES:
            raise ValueError("unknown role: {!r}".format(role))
        with self._transaction(org_id) as cur:
            cur.execute(
                "UPDATE users SET role = %s WHERE org_id = %s AND id = %s",
                (role, org_id, user_id),
            )
            cur.execute(
                "SELECT " + self._USER_COLUMNS + " FROM users "
                "WHERE org_id = %s AND id = %s",
                (org_id, user_id),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFound("user not found")
        return self._user_row(row)

    def delete_user(self, org_id: str, user_id: str) -> bool:
        with self._transaction(org_id) as cur:
            cur.execute(
                "DELETE FROM sessions WHERE org_id = %s AND user_id = %s",
                (org_id, user_id),
            )
            cur.execute(
                "DELETE FROM users WHERE org_id = %s AND id = %s",
                (org_id, user_id),
            )
            return cur.rowcount > 0

    # -- sessions -------------------------------------------------------
    _SESSION_COLUMNS = ("org_id, id, user_id, token_hash, csrf_hash, expires, "
                        "created, last_seen, step_up_at, step_up_method, ip, "
                        "user_agent")

    def _session_row(self, row: Tuple[Any, ...]) -> Session:
        return Session(
            org_id=row[0], id=row[1], user_id=row[2], token_hash=row[3],
            csrf_hash=row[4],
            expires=float(row[5].timestamp()) if hasattr(row[5], "timestamp")
            else float(row[5]),
            created=float(row[6].timestamp()) if hasattr(row[6], "timestamp")
            else float(row[6] or 0),
            last_seen=float(row[7].timestamp()) if hasattr(row[7], "timestamp")
            else float(row[7] or 0),
            step_up_at=(float(row[8].timestamp())
                        if hasattr(row[8], "timestamp") else row[8]),
            step_up_method=row[9], ip=row[10], user_agent=row[11],
        )

    def create_session(self, org_id: str, user_id: str, token_hash: str,
                       csrf_hash: str, expires: float, *,
                       id: Optional[str] = None,
                       created: Optional[float] = None,
                       last_seen: Optional[float] = None,
                       step_up_at: Optional[float] = None,
                       step_up_method: Optional[str] = None,
                       ip: Optional[str] = None,
                       user_agent: Optional[str] = None) -> Session:
        created_at = _epoch() if created is None else created
        session = Session(
            org_id=org_id, id=id or secrets.token_hex(16), user_id=user_id,
            token_hash=token_hash, csrf_hash=csrf_hash, expires=expires,
            created=created_at,
            last_seen=created_at if last_seen is None else last_seen,
            step_up_at=step_up_at, step_up_method=step_up_method, ip=ip,
            user_agent=user_agent,
        )
        with self._transaction(org_id) as cur:
            cur.execute(
                "INSERT INTO sessions (org_id, id, user_id, token_hash, "
                "csrf_hash, expires, created, last_seen, step_up_at, "
                "step_up_method, ip, user_agent) "
                "VALUES (%s, %s, %s, %s, %s, "
                "to_timestamp(%s), to_timestamp(%s), to_timestamp(%s), "
                "CASE WHEN %s::double precision IS NULL THEN NULL "
                "ELSE to_timestamp(%s) END, "
                "%s, %s, %s)",
                (org_id, session.id, user_id, token_hash, csrf_hash,
                 session.expires, session.created, session.last_seen,
                 session.step_up_at, session.step_up_at,
                 session.step_up_method, ip, user_agent),
            )
        return session

    def session_by_token_hash(self, token_hash: str,
                              org_id: Optional[str] = None) -> Optional[Session]:
        if org_id is None:
            # The org is part of the cookie precisely because RLS hides the
            # row until the setting is in place. Refusing here is louder than
            # returning a misleading "no such session".
            raise ValueError(
                "org_id is required to resolve a session under row-level security"
            )
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT " + self._SESSION_COLUMNS + " FROM sessions "
                "WHERE org_id = %s AND token_hash = %s",
                (org_id, token_hash),
            )
            row = cur.fetchone()
        return self._session_row(row) if row else None

    def touch_session(self, org_id: str, session_id: str,
                      last_seen: Optional[float] = None,
                      step_up_at: Optional[float] = None,
                      step_up_method: Optional[str] = None) -> Optional[Session]:
        seen = _epoch() if last_seen is None else last_seen
        with self._transaction(org_id) as cur:
            cur.execute(
                "UPDATE sessions SET last_seen = to_timestamp(%s), "
                "step_up_at = CASE WHEN %s::double precision IS NULL "
                "THEN step_up_at ELSE to_timestamp(%s) END, "
                "step_up_method = COALESCE(%s, step_up_method) "
                "WHERE org_id = %s AND id = %s",
                (seen, step_up_at, step_up_at, step_up_method, org_id,
                 session_id),
            )
            cur.execute(
                "SELECT " + self._SESSION_COLUMNS + " FROM sessions "
                "WHERE org_id = %s AND id = %s",
                (org_id, session_id),
            )
            row = cur.fetchone()
        return self._session_row(row) if row else None

    def delete_session(self, org_id: str, session_id: str) -> bool:
        with self._transaction(org_id) as cur:
            cur.execute(
                "DELETE FROM sessions WHERE org_id = %s AND id = %s",
                (org_id, session_id),
            )
            return cur.rowcount > 0

    def delete_user_sessions(self, org_id: str, user_id: str) -> int:
        with self._transaction(org_id) as cur:
            cur.execute(
                "DELETE FROM sessions WHERE org_id = %s AND user_id = %s",
                (org_id, user_id),
            )
            return cur.rowcount

    # -- audit ----------------------------------------------------------
    def audit_append(self, org_id: str, event: str, actor: Optional[str] = None,
                     detail: Optional[Dict[str, Any]] = None) -> AuditEntry:
        entry = AuditEntry(org_id=org_id, id=secrets.token_hex(8), event=event,
                           actor=actor, detail=dict(detail or {}),
                           created=_epoch())
        with self._transaction(org_id) as cur:
            cur.execute(
                "INSERT INTO audit_log (org_id, id, event, actor, detail) "
                "VALUES (%s, %s, %s, %s, %s::jsonb)",
                (org_id, entry.id, event, actor, json.dumps(entry.detail)),
            )
        return entry

    def audit_list(self, org_id: str) -> List[AuditEntry]:
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT org_id, id, event, actor, detail, created "
                "FROM audit_log WHERE org_id = %s ORDER BY created, id",
                (org_id,),
            )
            rows = cur.fetchall()
        out: List[AuditEntry] = []
        for row in rows:
            created = row[5]
            out.append(AuditEntry(
                org_id=row[0], id=row[1], event=row[2], actor=row[3],
                detail=row[4] or {},
                created=(created.timestamp() if hasattr(created, "timestamp")
                         else float(created or 0)),
            ))
        return out

    # -- enrollment tokens ---------------------------------------------
    def create_enrollment_token(self, org_id: Union[str, Org],
                                host_name: Optional[str] = None, *,
                                ttl: float = 3600,
                                created_by: Optional[str] = None,
                                now: Optional[float] = None,
                                id: Optional[str] = None) -> Tuple[str, str]:
        oid = _org_id(org_id) or ""
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        at = _epoch() if now is None else float(now)
        token_id = id or "et_" + secrets.token_hex(8)
        raw = mint_enrollment_token(oid)
        with self._transaction(oid) as cur:
            cur.execute(
                "INSERT INTO enrollment_tokens "
                "(org_id, id, token_hash, host_name, expires) "
                "VALUES (%s, %s, %s, %s, to_timestamp(%s))",
                (oid, token_id, hash_token(raw), host_name, at + float(ttl)),
            )
        return token_id, raw

    _TOKEN_COLUMNS = ("org_id, id, token_hash, host_name, expires, used_at")

    def _token_row(self, row: Tuple[Any, ...]) -> EnrollmentToken:
        return EnrollmentToken(
            org_id=row[0], id=row[1], token_hash=row[2], host_name=row[3],
            expires=_timestamp(row[4]) or 0.0,
            used_at=_timestamp(row[5]),
        )

    def consume_enrollment_token(self, raw: str, *,
                                 now: Optional[float] = None
                                 ) -> Optional[EnrollmentToken]:
        from .enrollment import enrollment_org

        org_id = enrollment_org(raw)
        if org_id is None:
            return None
        at = _epoch() if now is None else float(now)
        digest = hash_token(raw)
        with self._transaction(org_id) as cur:
            cur.execute(
                "SELECT " + self._TOKEN_COLUMNS + " FROM enrollment_tokens "
                "WHERE org_id = %s AND token_hash = %s",
                (org_id, digest),
            )
            row = cur.fetchone()
            if row is None:
                return None
            token = self._token_row(row)
            if token.used_at is not None or at >= token.expires:
                return None
            # Conditional on used_at so two concurrent consumers cannot both
            # win: only one UPDATE reports a row.
            cur.execute(
                "UPDATE enrollment_tokens SET used_at = to_timestamp(%s) "
                "WHERE org_id = %s AND id = %s AND used_at IS NULL "
                "AND expires > to_timestamp(%s)",
                (at, org_id, token.id, at),
            )
            if cur.rowcount != 1:
                return None
            token.used_at = at
            return token

    def enrollment_token_by_id(self, org_id: str,
                               token_id: str) -> Optional[EnrollmentToken]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT " + self._TOKEN_COLUMNS + " FROM enrollment_tokens "
                "WHERE org_id = %s AND id = %s",
                (oid, token_id),
            )
            row = cur.fetchone()
        return self._token_row(row) if row else None

    # -- hosts ----------------------------------------------------------
    _HOST_COLUMNS = "org_id, id, name, owner_subject, public_keys, state, last_seen"

    def _host_row(self, row: Tuple[Any, ...]) -> Host:
        return Host(org_id=row[0], id=row[1], name=row[2],
                    owner_subject=row[3], public_keys=list(row[4] or []),
                    state=row[5], last_seen=_timestamp(row[6]))

    def create_host(self, org_id: Union[str, Org], name: str, *,
                    owner_subject: str, public_keys: Optional[List[Dict[str, Any]]] = None,
                    state: str = "active", last_seen: Optional[float] = None,
                    id: Optional[str] = None) -> Host:
        oid = _org_id(org_id) or ""
        if state not in HOST_STATES:
            raise ValueError("unknown host state: {!r}".format(state))
        host = Host(org_id=oid, id=id or "host_" + secrets.token_hex(12),
                    name=name, owner_subject=owner_subject,
                    public_keys=list(public_keys or []), state=state,
                    last_seen=last_seen)
        with self._transaction(oid) as cur:
            cur.execute(
                "INSERT INTO hosts (org_id, id, name, owner_subject, "
                "public_keys, state, last_seen) "
                "VALUES (%s, %s, %s, %s, %s::jsonb, %s, "
                "CASE WHEN %s::double precision IS NULL THEN NULL "
                "ELSE to_timestamp(%s) END)",
                (oid, host.id, name, owner_subject,
                 json.dumps(host.public_keys), state,
                 host.last_seen, host.last_seen),
            )
        return host

    def host_by_id(self, org_id: str, host_id: str) -> Optional[Host]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT " + self._HOST_COLUMNS + " FROM hosts "
                "WHERE org_id = %s AND id = %s",
                (oid, host_id),
            )
            row = cur.fetchone()
        return self._host_row(row) if row else None

    def list_hosts(self, org_id: str) -> List[Host]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT " + self._HOST_COLUMNS + " FROM hosts "
                "WHERE org_id = %s ORDER BY id",
                (oid,),
            )
            return [self._host_row(row) for row in cur.fetchall()]

    def set_host_state(self, org_id: str, host_id: str, state: str) -> Host:
        if state not in HOST_STATES:
            raise ValueError("unknown host state: {!r}".format(state))
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "UPDATE hosts SET state = %s WHERE org_id = %s AND id = %s",
                (state, oid, host_id),
            )
            cur.execute(
                "SELECT " + self._HOST_COLUMNS + " FROM hosts "
                "WHERE org_id = %s AND id = %s",
                (oid, host_id),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFound("host not found")
        return self._host_row(row)

    def touch_host(self, org_id: str, host_id: str,
                   last_seen: Optional[float] = None) -> Optional[Host]:
        oid = _org_id(org_id) or ""
        seen = _epoch() if last_seen is None else float(last_seen)
        with self._transaction(oid) as cur:
            cur.execute(
                "UPDATE hosts SET last_seen = to_timestamp(%s) "
                "WHERE org_id = %s AND id = %s",
                (seen, oid, host_id),
            )
            cur.execute(
                "SELECT " + self._HOST_COLUMNS + " FROM hosts "
                "WHERE org_id = %s AND id = %s",
                (oid, host_id),
            )
            row = cur.fetchone()
        return self._host_row(row) if row else None

    # -- agent keys -----------------------------------------------------
    _KEY_COLUMNS = ("org_id, id, prefix, secret_hash, host_id, scopes, "
                    "expires, revoked_at")

    def _key_row(self, row: Tuple[Any, ...]) -> AgentKey:
        return AgentKey(org_id=row[0], id=row[1], prefix=row[2],
                        secret_hash=row[3], host_id=row[4],
                        scopes=list(row[5] or []),
                        expires=_timestamp(row[6]),
                        revoked_at=_timestamp(row[7]))

    def create_agent_key(self, org_id: str, host_id: str, *,
                         prefix: str, secret_hash: str,
                         scopes: Optional[List[str]] = None,
                         expires: Optional[float] = None,
                         id: Optional[str] = None) -> AgentKey:
        oid = _org_id(org_id) or ""
        key = AgentKey(org_id=oid, id=id or "key_" + secrets.token_hex(8),
                       prefix=prefix, secret_hash=secret_hash,
                       host_id=host_id, scopes=list(scopes or []),
                       expires=expires, revoked_at=None)
        with self._transaction(oid) as cur:
            # The foreign key proves the host exists inside this org; a
            # missing host raises the driver's integrity error rather than
            # writing a dangling key.
            cur.execute(
                "INSERT INTO agent_keys (org_id, id, prefix, secret_hash, "
                "host_id, scopes, expires) "
                "VALUES (%s, %s, %s, %s, %s, %s::jsonb, "
                "CASE WHEN %s::double precision IS NULL THEN NULL "
                "ELSE to_timestamp(%s) END)",
                (oid, key.id, prefix, secret_hash, host_id,
                 json.dumps(key.scopes), expires, expires),
            )
        return key

    def agent_key_by_prefix(self, prefix: str, *,
                            org_id: Optional[str] = None
                            ) -> Optional[AgentKey]:
        if org_id is None:
            # RLS hides agent_keys until interlock.org_id is set, so an
            # org-less lookup would silently miss every real key. Refusing is
            # louder and matches session_by_token_hash.
            raise ValueError(
                "org_id is required to resolve an agent key under row-level security"
            )
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT " + self._KEY_COLUMNS + " FROM agent_keys "
                "WHERE org_id = %s AND prefix = %s",
                (oid, prefix),
            )
            row = cur.fetchone()
        return self._key_row(row) if row else None

    def agent_key_by_id(self, org_id: str, key_id: str) -> Optional[AgentKey]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT " + self._KEY_COLUMNS + " FROM agent_keys "
                "WHERE org_id = %s AND id = %s",
                (oid, key_id),
            )
            row = cur.fetchone()
        return self._key_row(row) if row else None

    def list_agent_keys(self, org_id: str,
                        host_id: Optional[str] = None) -> List[AgentKey]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            if host_id is None:
                cur.execute(
                    "SELECT " + self._KEY_COLUMNS + " FROM agent_keys "
                    "WHERE org_id = %s ORDER BY id",
                    (oid,),
                )
            else:
                cur.execute(
                    "SELECT " + self._KEY_COLUMNS + " FROM agent_keys "
                    "WHERE org_id = %s AND host_id = %s ORDER BY id",
                    (oid, host_id),
                )
            return [self._key_row(row) for row in cur.fetchall()]

    def retire_agent_key(self, org_id: str, key_id: str, *,
                         expires: float) -> AgentKey:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "UPDATE agent_keys SET expires = to_timestamp(%s) "
                "WHERE org_id = %s AND id = %s",
                (float(expires), oid, key_id),
            )
            cur.execute(
                "SELECT " + self._KEY_COLUMNS + " FROM agent_keys "
                "WHERE org_id = %s AND id = %s",
                (oid, key_id),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFound("agent key not found")
        return self._key_row(row)

    def revoke_agent_key(self, org_id: str, key_id: str, *,
                         now: Optional[float] = None) -> AgentKey:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._transaction(oid) as cur:
            cur.execute(
                "UPDATE agent_keys SET revoked_at = COALESCE(revoked_at, "
                "to_timestamp(%s)) WHERE org_id = %s AND id = %s",
                (at, oid, key_id),
            )
            cur.execute(
                "SELECT " + self._KEY_COLUMNS + " FROM agent_keys "
                "WHERE org_id = %s AND id = %s",
                (oid, key_id),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFound("agent key not found")
        return self._key_row(row)

    def revoke_host_keys(self, org_id: str, host_id: str, *,
                         now: Optional[float] = None) -> int:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._transaction(oid) as cur:
            cur.execute(
                "UPDATE agent_keys SET revoked_at = to_timestamp(%s) "
                "WHERE org_id = %s AND host_id = %s AND revoked_at IS NULL",
                (at, oid, host_id),
            )
            return cur.rowcount


    # -- reviews and grants (C3) ----------------------------------------
    _REVIEW_COLUMNS = (
        "org_id, host_id, id, status, binding, action, phase, principal, "
        "requester, policy_id, reason, args_digest, preview_enc, mask_counts, "
        "metadata, created, pending_until, decided, decided_by, approval_until, "
        "approvers, min_approvals, allow_self_approval, approval_ttl"
    )

    def _review_row(self, row: Tuple[Any, ...]) -> ReviewRecord:
        return ReviewRecord(
            org_id=row[0], host_id=row[1], id=row[2], status=row[3],
            binding=row[4] or "", action=row[5] or "", phase=row[6] or "call",
            principal=row[7], requester=row[8], policy_id=row[9],
            reason=row[10], args_digest=row[11],
            preview_enc=bytes(row[12]) if row[12] is not None else None,
            mask_counts=dict(row[13] or {}), metadata=dict(row[14] or {}),
            created=_timestamp(row[15]) or 0.0,
            pending_until=_timestamp(row[16]),
            decided=_timestamp(row[17]), decided_by=row[18],
            approval_until=_timestamp(row[19]),
            approvers=list(row[20] or []),
            min_approvals=int(row[21] if row[21] is not None else 1),
            allow_self_approval=bool(row[22]),
            approval_ttl=float(row[23] if row[23] is not None else 900.0),
        )

    def upsert_review(self, org_id: Union[str, Org], host_id: str,
                      review_id: str, *, binding: str, action: str,
                      phase: str, principal: Optional[str] = None,
                      requester: Optional[str] = None,
                      policy_id: Optional[str] = None,
                      reason: Optional[str] = None,
                      args_digest: Optional[str] = None,
                      preview_enc: Optional[bytes] = None,
                      mask_counts: Optional[Dict[str, int]] = None,
                      metadata: Optional[Dict[str, Any]] = None,
                      created: Optional[float] = None,
                      pending_until: Optional[float] = None,
                      min_approvals: int = 1,
                      allow_self_approval: bool = True,
                      approval_ttl: float = 900.0) -> ReviewRecord:
        oid = _org_id(org_id) or ""
        at = _epoch() if created is None else float(created)
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT binding FROM reviews WHERE org_id = %s AND host_id = %s "
                "AND id = %s", (oid, host_id, review_id))
            row = cur.fetchone()
            if row is not None:
                if (row[0] or "") != binding:
                    raise ReviewConflict(
                        "review {} already exists with another binding".format(
                            review_id))
            else:
                cur.execute(
                    "INSERT INTO reviews (org_id, host_id, id, status, binding, "
                    "action, phase, principal, requester, policy_id, reason, "
                    "args_digest, preview_enc, mask_counts, metadata, created, "
                    "pending_until, approvers, min_approvals, allow_self_approval, "
                    "approval_ttl) VALUES (%s, %s, %s, 'pending', %s, %s, %s, %s, "
                    "%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, to_timestamp(%s), "
                    "to_timestamp(%s), '[]'::jsonb, %s, %s, %s)",
                    (oid, host_id, review_id, binding, action, phase, principal,
                     requester, policy_id, reason, args_digest, preview_enc,
                     json.dumps(mask_counts or {}), json.dumps(metadata or {}),
                     at, pending_until, int(min_approvals),
                     bool(allow_self_approval), float(approval_ttl)))
            cur.execute(
                "SELECT " + self._REVIEW_COLUMNS + " FROM reviews "
                "WHERE org_id = %s AND host_id = %s AND id = %s",
                (oid, host_id, review_id))
            row = cur.fetchone()
        return self._review_row(row)

    def review_by_id(self, org_id: str, review_id: str,
                     host_id: Optional[str] = None) -> Optional[ReviewRecord]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            if host_id is None:
                cur.execute(
                    "SELECT " + self._REVIEW_COLUMNS + " FROM reviews "
                    "WHERE org_id = %s AND id = %s", (oid, review_id))
            else:
                cur.execute(
                    "SELECT " + self._REVIEW_COLUMNS + " FROM reviews "
                    "WHERE org_id = %s AND host_id = %s AND id = %s",
                    (oid, host_id, review_id))
            row = cur.fetchone()
        return self._review_row(row) if row is not None else None

    def list_reviews(self, org_id: str, *, status: Optional[str] = None,
                     host_id: Optional[str] = None, cursor: int = 0,
                     limit: int = 50) -> Tuple[List[ReviewRecord], Optional[int]]:
        oid = _org_id(org_id) or ""
        if (status is not None and status not in PLANE_REVIEW_STATUSES) or limit < 1:
            raise ValueError("invalid review filter")
        clauses = ["org_id = %s"]
        params: List[Any] = [oid]
        if status is not None:
            clauses.append("status = %s")
            params.append(status)
        if host_id is not None:
            clauses.append("host_id = %s")
            params.append(host_id)
        offset = max(0, int(cursor))
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT " + self._REVIEW_COLUMNS + " FROM reviews WHERE "
                + " AND ".join(clauses)
                + " ORDER BY created DESC, id LIMIT %s OFFSET %s",
                tuple(params + [int(limit) + 1, offset]))
            rows = cur.fetchall()
        page = [self._review_row(row) for row in rows[:int(limit)]]
        next_cursor = offset + len(page) if len(rows) > int(limit) else None
        return page, next_cursor

    def record_decision(self, org_id: str, review_id: str, *, reviewer: str,
                        step_up_method: str, step_up_at: float,
                        decision: str, grant_id: Optional[str] = None,
                        grant_seq: Optional[int] = None,
                        approve_anyway: bool = False,
                        reason: Optional[str] = None,
                        status: Optional[str] = None,
                        decided_by: Optional[str] = None,
                        approval_until: Optional[float] = None,
                        now: Optional[float] = None) -> DecisionRecord:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        decision_id = "dec_" + secrets.token_hex(8)
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT approvers FROM reviews WHERE org_id = %s AND id = %s "
                "FOR UPDATE", (oid, review_id))
            row = cur.fetchone()
            if row is None:
                raise NotFound("review not found")
            approvers = list(row[0] or [])
            if reviewer not in approvers:
                approvers.append(reviewer)
            if status is not None:
                cur.execute(
                    "UPDATE reviews SET approvers = %s::jsonb, status = %s, "
                    "decided = to_timestamp(%s), decided_by = %s, "
                    "approval_until = CASE WHEN %s::double precision IS NULL "
                    "THEN approval_until ELSE to_timestamp(%s) END "
                    "WHERE org_id = %s AND id = %s",
                    (json.dumps(approvers), status, at, decided_by or reviewer,
                     approval_until, approval_until, oid, review_id))
            else:
                cur.execute(
                    "UPDATE reviews SET approvers = %s::jsonb "
                    "WHERE org_id = %s AND id = %s",
                    (json.dumps(approvers), oid, review_id))
            cur.execute(
                "INSERT INTO decisions (org_id, id, review_id, reviewer, "
                "step_up_method, step_up_at, decision, grant_id, grant_seq, "
                "approve_anyway, reason) VALUES (%s, %s, %s, %s, %s, "
                "to_timestamp(%s), %s, %s, %s, %s, %s)",
                (oid, decision_id, review_id, reviewer, step_up_method, at,
                 decision, grant_id, grant_seq, bool(approve_anyway), reason))
        return DecisionRecord(
            org_id=oid, id=decision_id, review_id=review_id, reviewer=reviewer,
            step_up_method=step_up_method, step_up_at=float(step_up_at),
            decision=decision, grant_id=grant_id, grant_seq=grant_seq,
            approve_anyway=bool(approve_anyway), reason=reason,
        )

    def pending_decisions(self, org_id: str, review_id: str) -> List[str]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT DISTINCT reviewer FROM decisions WHERE org_id = %s "
                "AND review_id = %s AND decision = 'approve' ORDER BY reviewer",
                (oid, review_id))
            return [row[0] for row in cur.fetchall()]

    def grant_head(self, org_id: str, host_id: str) -> Dict[str, Any]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT last_seq, last_sig FROM grant_heads "
                "WHERE org_id = %s AND host_id = %s", (oid, host_id))
            row = cur.fetchone()
        if row is None:
            return {"seq": 0, "sig": "GENESIS"}
        return {"seq": int(row[0]), "sig": row[1] or "GENESIS"}

    def next_grant_seq(self, org_id: str, host_id: str) -> Tuple[int, str]:
        head = self.grant_head(org_id, host_id)
        return int(head["seq"]) + 1, str(head["sig"])

    def add_grant(self, org_id: str, host_id: str, *, grant_id: str,
                  review_id: str, seq: int, envelope: Dict[str, Any],
                  now: Optional[float] = None) -> GrantRecord:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        with self._transaction(oid) as cur:
            cur.execute(
                "INSERT INTO cloud_grants (org_id, id, host_id, review_id, seq, "
                "envelope, delivered_at) VALUES (%s, %s, %s, %s, %s, %s::jsonb, "
                "to_timestamp(%s)) ON CONFLICT (org_id, id) DO NOTHING",
                (oid, grant_id, host_id, review_id, int(seq),
                 json.dumps(envelope), at))
            cur.execute(
                "SELECT seq, envelope FROM cloud_grants "
                "WHERE org_id = %s AND host_id = %s ORDER BY seq DESC LIMIT 1",
                (oid, host_id))
            row = cur.fetchone()
            if row is not None:
                current_seq = int(row[0])
                signature = str((row[1] or {}).get("sig") or "")
                cur.execute(
                    "INSERT INTO grant_heads (org_id, host_id, last_seq, last_sig) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT (org_id, host_id) "
                    "DO UPDATE SET last_seq = EXCLUDED.last_seq, "
                    "last_sig = EXCLUDED.last_sig, updated_at = now() "
                    "WHERE grant_heads.last_seq <= EXCLUDED.last_seq",
                    (oid, host_id, current_seq, signature))
        return GrantRecord(org_id=oid, host_id=host_id, id=grant_id,
                           review_id=review_id, seq=int(seq),
                           envelope=dict(envelope), delivered_at=at)

    def grants_after(self, org_id: str, host_id: str, seq: int) -> List[Dict[str, Any]]:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT envelope FROM cloud_grants WHERE org_id = %s "
                "AND host_id = %s AND seq > %s ORDER BY seq",
                (oid, host_id, int(seq)))
            return [dict(row[0] or {}) for row in cur.fetchall()]

    def ack_grants(self, org_id: str, host_id: str,
                   ids: List[str], *, now: Optional[float] = None) -> int:
        oid = _org_id(org_id) or ""
        at = _epoch() if now is None else float(now)
        acked = 0
        with self._transaction(oid) as cur:
            for grant_id in ids:
                cur.execute(
                    "UPDATE cloud_grants SET acked_at = to_timestamp(%s) "
                    "WHERE org_id = %s AND id = %s AND host_id = %s "
                    "AND acked_at IS NULL", (at, oid, grant_id, host_id))
                acked += cur.rowcount or 0
        return acked

    def last_ack_seq(self, org_id: str, host_id: str) -> int:
        oid = _org_id(org_id) or ""
        with self._transaction(oid) as cur:
            cur.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM cloud_grants "
                "WHERE org_id = %s AND host_id = %s AND acked_at IS NOT NULL",
                (oid, host_id))
            row = cur.fetchone()
        return int(row[0]) if row is not None else 0

    def host_keys(self, org_id: str, host_id: str) -> List[Dict[str, Any]]:
        host = self.host_by_id(org_id, host_id)
        return [] if host is None else [dict(pin) for pin in host.public_keys]


def _timestamp(value: Any) -> Optional[float]:
    """Postgres timestamps arrive as ``datetime``; tests may pass floats."""
    if value is None:
        return None
    if hasattr(value, "timestamp"):
        return float(value.timestamp())
    return float(value)


def _epoch() -> float:
    """Wall-clock seconds, kept here so stores do not import time twice."""
    import time

    return time.time()


Store = Union[MemoryStore, PostgresStore]

__all__ = [
    "AgentKey",
    "AuditEntry",
    "CloudDependencyMissing",
    "CrossOrgAccess",
    "EnrollmentToken",
    "HOST_STATES",
    "Host",
    "MemoryStore",
    "NotFound",
    "Org",
    "PostgresStore",
    "ROLES",
    "Session",
    "Store",
    "User",
    "keys_version",
]
