"""One store contract over both implementations, plus the RLS statement order."""
from __future__ import annotations

import hashlib
import os
import sys
import types
import uuid
from typing import Any, List, Tuple

import pytest

from interlock.cloud.store import (
    CrossOrgAccess,
    MemoryStore,
    NotFound,
    PostgresStore,
)

DSN = os.environ.get("IL_CLOUD_TEST_DSN")


class RecordingCursor:
    def __init__(self, recorder: List[Tuple[str, Any]], rows=None):
        self.recorder = recorder
        self.rows = list(rows or [])
        self.rowcount = 1

    def execute(self, sql, params=None):
        self.recorder.append((sql, params))

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows, self.rows = self.rows, []
        return rows

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class RecordingConnection:
    def __init__(self, recorder):
        self.recorder = recorder
        self.commits = 0

    def cursor(self):
        return RecordingCursor(self.recorder)

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        pass


def _install_fake_psycopg(monkeypatch):
    recorder: List[Tuple[str, Any]] = []

    def fake_connect(dsn, **kwargs):
        return RecordingConnection(recorder)

    monkeypatch.setitem(sys.modules, "psycopg",
                        types.SimpleNamespace(connect=fake_connect))
    return recorder


# -- RLS recorder -------------------------------------------------------

def test_postgres_sets_org_context_before_every_tenant_statement(monkeypatch):
    recorder = _install_fake_psycopg(monkeypatch)
    store = PostgresStore("postgresql://unused")

    store.user_by_id("org-1", "u1")

    assert recorder[0][0] == "SET LOCAL interlock.org_id = 'org-1'"
    for sql, _params in recorder[1:]:
        assert "org_id" in sql, sql


def test_every_tenant_query_carries_org_id(monkeypatch):
    recorder = _install_fake_psycopg(monkeypatch)
    store = PostgresStore("postgresql://unused")
    org = "org-1"

    store.create_user(org, issuer="i", subject="s", role="admin")
    store.user_by_issuer_subject(org, "i", "s")
    store.user_by_email(org, "a@b.test")
    store.user_by_id(org, "u1")
    store.list_users(org)
    # The fake cursor returns no row, so the follow-up SELECT reads back as a
    # miss; the statements are still recorded, which is what this test checks.
    with pytest.raises(NotFound):
        store.set_user_status(org, "u1", "active")
    with pytest.raises(NotFound):
        store.set_user_role(org, "u1", "admin")
    store.create_session(org, "u1", "hash", "csrf", 2000.0)
    store.session_by_token_hash("hash", org_id=org)
    store.touch_session(org, "s1", 1000.0)
    store.delete_session(org, "s1")
    store.delete_user_sessions(org, "u1")
    store.audit_append(org, "member.updated", actor="u1")
    store.audit_list(org)
    store.verified_domain(org, "a@b.test")

    for sql, _params in recorder:
        if sql.startswith("SET LOCAL"):
            continue
        assert "org_id" in sql, sql


def test_org_id_is_quoted_as_a_literal_not_a_placeholder(monkeypatch):
    recorder = _install_fake_psycopg(monkeypatch)
    store = PostgresStore("postgresql://unused")

    store.list_users("x' OR '1'='1")

    first = recorder[0][0]
    assert first.startswith("SET LOCAL interlock.org_id = '")
    assert "'x'' OR ''1''=''1'" in first
    assert "%s" not in first


# -- behaviour contract -------------------------------------------------

def _contract(store):
    suffix = uuid.uuid4().hex[:12]
    org = store.create_org(slug="contract-" + suffix, name="Contract")
    user = store.create_user(org, issuer="https://idp.example",
                             subject="subject-" + suffix, email="u@test",
                             role="admin")
    assert store.user_by_id(org.id, user.id).email == "u@test"
    assert store.user_by_issuer_subject(
        org.id, "https://idp.example", "subject-" + suffix).id == user.id
    assert [u.id for u in store.list_users(org.id)] == [user.id]

    updated = store.set_user_role(org.id, user.id, "reviewer")
    assert updated.role == "reviewer"
    updated = store.set_user_status(org.id, user.id, "disabled")
    assert updated.status == "disabled"

    token_hash = hashlib.sha256(("raw-" + suffix).encode()).hexdigest()
    session = store.create_session(org.id, user.id, token_hash, "csrf-hash",
                                   expires=4102444800.0)  # 2100-01-01, inside datetime's range
    assert store.session_by_token_hash(token_hash, org_id=org.id).id == session.id
    store.touch_session(org.id, session.id, 1234.0)
    assert store.delete_session(org.id, session.id) is True

    second = store.create_session(org.id, user.id, "other-" + suffix, "csrf",
                                  expires=4102444800.0)  # 2100-01-01, inside datetime's range
    assert store.delete_user_sessions(org.id, user.id) >= 1
    assert store.session_by_token_hash(second.token_hash,
                                       org_id=org.id) is None

    store.audit_append(org.id, "member.updated", actor=user.id,
                       detail={"target": user.id})
    entries = store.audit_list(org.id)
    assert entries[-1].event == "member.updated"
    assert entries[-1].detail["target"] == user.id


def test_contract_on_memory_store():
    _contract(MemoryStore())


@pytest.mark.skipif(not DSN, reason="IL_CLOUD_TEST_DSN is not set")
def test_contract_on_postgres_store():
    _contract(PostgresStore(DSN))


def test_memory_store_isolates_orgs():
    store = MemoryStore()
    org_a = store.create_org(slug="a", name="A")
    org_b = store.create_org(slug="b", name="B")
    user = store.create_user(org_a, issuer="i", subject="s", role="owner")
    with pytest.raises(CrossOrgAccess):
        store.user_by_id(org_b.id, user.id)


# -- row-level security -------------------------------------------------

@pytest.mark.skipif(not DSN, reason="IL_CLOUD_TEST_DSN is not set")
def test_row_level_security_hides_another_orgs_rows():
    """The policies must filter, not just the ``WHERE`` clauses.

    The store also carries ``org_id`` in every query, so this check talks to
    the database directly: with one org's context set, the other org's row
    must be invisible even to a query that does not mention it.
    """
    psycopg = pytest.importorskip("psycopg")
    from interlock.cloud.db import quote_literal

    store = PostgresStore(DSN)
    suffix = uuid.uuid4().hex[:12]
    org_a = store.create_org(slug="rls-a-" + suffix, name="A")
    org_b = store.create_org(slug="rls-b-" + suffix, name="B")
    store.create_user(org_a, issuer="i", subject="s", email="a@b.test",
                      role="admin")
    store.create_user(org_b, issuer="i", subject="s", email="b@b.test",
                      role="admin")

    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT rolsuper, rolbypassrls FROM pg_roles "
                        "WHERE rolname = current_user")
            superuser, bypassrls = cur.fetchone()
            if superuser or bypassrls:
                pytest.skip("the connected role bypasses row-level security")
            cur.execute("SET LOCAL interlock.org_id = "
                        + quote_literal(org_a.id))
            cur.execute("SELECT count(*) FROM users")
            assert cur.fetchone()[0] == 1
            cur.execute("SELECT count(*) FROM users WHERE org_id = "
                        + quote_literal(org_b.id))
            assert cur.fetchone()[0] == 0
