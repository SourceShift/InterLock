"""Small builders shared by the C4 tests.

The cloud tests drive the ASGI app through one ``_call`` helper and build
receipt chains directly with ``compute_mac`` so a test can choose the signer
(HMAC or Ed25519) and the exact fields under test.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from interlock.cloud.app import CloudApp
from interlock.cloud.config import CloudConfig
from interlock.cloud.enrollment import generate_agent_key
from interlock.receipt import GENESIS, Receipt, compute_mac, hmac_sha256
from interlock.receipt_ed25519 import (
    generate_seed,
    public_key,
    ed25519_signer,
)

NOW = 2_000_000_000.0
KEK = "ab" * 32


def call(app, path, *, method="GET", headers=None, body=None, query=b""):
    sent = []
    payload = b"" if body is None else body

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path,
        "raw_path": path.encode(), "query_string": query,
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8787),
    }
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    response_headers = {}
    for name, value in start["headers"]:
        response_headers.setdefault(name.decode(), value.decode())
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    try:
        decoded = json.loads(raw) if raw else None
    except (UnicodeDecodeError, ValueError):
        decoded = None
    return start["status"], response_headers, decoded, raw


def login(app, org, user):
    raw = app.sessions.login(user)
    session = app.store.session_by_token_hash(app.sessions.hash(raw))
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
    }
    return headers, session


def make_app(role="owner", *, now=NOW, receipt_seed=None, host_keys=None):
    """One org, user, host and app; the caller adds agent keys as needed."""
    from interlock.cloud.store import MemoryStore

    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example",
                             subject="u1", email="u1@acme.test", role=role)
    keys = list(host_keys or [])
    host = store.create_host(org, "box", owner_subject="owner-x",
                             public_keys=keys, last_seen=now - 10)
    app = CloudApp(
        CloudConfig(session_secret="s" * 32, preview_kek=KEK),
        store=store, ping=lambda dsn: True, clock=lambda: now,
        approval_seed=generate_seed(),
    )
    headers, session = login(app, org, user)
    return SimpleNamespace(app=app, store=store, org=org, user=user,
                           host=host, headers=headers, session=session)


def add_agent_key(env, *, scopes=("ingest:receipts",)):
    raw, prefix, digest = generate_agent_key()
    env.store.create_agent_key(env.org.id, env.host.id, prefix=prefix,
                               secret_hash=digest, scopes=list(scopes))
    return {
        "authorization": "Bearer " + raw,
        "x-interlock-org": env.org.id,
        "x-interlock-host": env.host.id,
        "content-type": "application/json",
    }


def ed25519_host(env):
    """Replace the host's pin with an Ed25519 receipt key; return its seed."""
    seed = generate_seed()
    public = public_key(seed)
    env.host.public_keys[:] = [{
        "public_key": public.hex(), "kind": "receipt", "use": "receipt",
    }]
    return seed, public


def chain(key, *, start=GENESIS, count=3, signer=hmac_sha256,
          base_ts=NOW - 60, **fields):
    """Build a linked chain of ``count`` receipts signed with ``key``."""
    receipts = []
    prev = start
    for index in range(count):
        body = {"ts": float(base_ts + index), "action": "shell",
                "verdict": "ALLOW", "reason": "policy", "policy_id": "p-1",
                "principal": "alice", "prev": prev}
        body.update(fields)
        receipt = Receipt(**body)
        receipt.mac = compute_mac(receipt, signer, key)
        receipts.append(receipt)
        prev = receipt.mac
    return receipts


def ed25519_chain(seed, **kwargs):
    return chain(seed, signer=ed25519_signer, **kwargs)


def ingest(env, headers, receipts, **extra):
    body = {"receipts": [receipt.fields() for receipt in receipts]}
    body.update(extra)
    return call(env.app, "/v1/receipts", method="POST", headers=headers,
                body=json.dumps(body).encode())


def checkpoint_doc(seed, *, org_id, host_id, head_mac, count,
                   issued_at=NOW):
    from interlock.cloud.receipts import sign_checkpoint

    return sign_checkpoint(seed, {
        "v": 1, "org_id": org_id, "host_id": host_id,
        "head_mac": head_mac, "count": count, "issued_at": issued_at,
    })


def post_json(env, path, headers, payload):
    merged = dict(headers or {})
    merged.setdefault("content-type", "application/json")
    return call(env.app, path, method="POST", headers=merged,
                body=json.dumps(payload).encode())


__all__ = [
    "KEK",
    "NOW",
    "add_agent_key",
    "call",
    "chain",
    "checkpoint_doc",
    "ed25519_chain",
    "ed25519_host",
    "ingest",
    "login",
    "make_app",
    "post_json",
]
