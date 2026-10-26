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

ROLES = ("owner", "admin", "reviewer", "auditor")
STATUSES = ("active", "invited", "disabled")


class CrossOrgAccess(Exception):
    """A record was looked up under an org that does not own it."""


class NotFound(Exception):
    """A record does not exist or is not visible to the calling org."""


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
        self._domains: Dict[Tuple[str, str], bool] = {}

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


def _epoch() -> float:
    """Wall-clock seconds, kept here so stores do not import time twice."""
    import time

    return time.time()


Store = Union[MemoryStore, PostgresStore]

__all__ = [
    "AuditEntry",
    "CloudDependencyMissing",
    "CrossOrgAccess",
    "MemoryStore",
    "NotFound",
    "Org",
    "PostgresStore",
    "ROLES",
    "Session",
    "Store",
    "User",
]
