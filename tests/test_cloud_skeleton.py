"""The cloud skeleton: dependency-free imports, config, ASGI envelope, schema
coverage, migration ordering, the CLI stub and packaging metadata.

Each test is named for the claim it proves. The important one is the zero-dep
gate: the plane must import under ``python3 -I -S`` with no site-packages, so
the Postgres driver and the ASGI server cannot be imported at module scope.
The kickoff's bare `-I -S -c 'import interlock.cloud'` cannot import a cwd
package (``-I`` removes the cwd from ``sys.path``), so the subprocess inserts
the repository root explicitly while still proving site-packages are absent.
"""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: The spec's data model, in order, and the subset that carries org_id.
TABLES = [
    "orgs",
    "org_domains",
    "users",
    "sessions",
    "webauthn_credentials",
    "totp_secrets",
    "enrollment_tokens",
    "hosts",
    "agent_keys",
    "reviews",
    "decisions",
    "receipts",
    "receipt_heads",
    "policy_artifacts",
    "policy_manifests",
    "policy_rollouts",
    "policy_kills",
    "audit_log",
    "webhook_endpoints",
    "webhook_deliveries",
]

ORG_SCOPED = [table for table in TABLES if table != "orgs"]

ACTIONS = ["enroll", "run", "status", "leave", "policy", "keys"]

MIN_SECRET = 32


# -- helpers ------------------------------------------------------------

def _call(path, method="GET", headers=None, app_instance=None):
    """Drive the ASGI app in-process and return status, headers, body, events."""
    from interlock.cloud.app import app as default_app

    target = app_instance if app_instance is not None else default_app
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8787),
    }
    asyncio.run(target(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent
                    if m["type"] == "http.response.body")
    decoded = dict((k.decode(), v.decode()) for k, v in start["headers"])
    return start["status"], decoded, json.loads(body), sent


def _sql() -> str:
    from interlock.cloud.migrate import MIGRATIONS_DIR

    return (MIGRATIONS_DIR / "001_init.sql").read_text(encoding="utf-8")


def _valid_config(**overrides):
    from interlock.cloud.config import CloudConfig

    values = {"dsn": "postgresql://interlock@localhost/interlock",
              "session_secret": "x" * MIN_SECRET}
    values.update(overrides)
    return CloudConfig(**values)


# -- zero-dependency gate ----------------------------------------------

def test_cloud_package_imports_without_site_packages():
    code = (
        "import sys; sys.path.insert(0, {!r}); "
        "import interlock.cloud, interlock.cloud.app, interlock.cloud.migrate; "
        "print('zero-dep ok')"
    ).format(str(ROOT))
    proc = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "zero-dep ok" in proc.stdout


# -- config -------------------------------------------------------------

def test_config_defaults_are_loopback_and_calm():
    from interlock.cloud.config import CloudConfig

    config = CloudConfig()
    assert config.dsn == ""
    assert config.bind_host == "127.0.0.1"
    assert config.bind_port == 8787
    assert config.log_level == "info"
    assert config.public_url == ""
    assert config.state_dir.name == "cloud-plane"
    assert config.state_dir.parent.name == ".interlock"


def test_from_env_reads_every_override():
    from interlock.cloud.config import CloudConfig

    config = CloudConfig.from_env({
        "IL_CLOUD_DSN": "postgresql://db/interlock",
        "IL_CLOUD_BIND": "::1",
        "IL_CLOUD_PORT": "9000",
        "IL_CLOUD_PUBLIC_URL": "https://cloud.example",
        "IL_CLOUD_SESSION_SECRET": "s" * 40,
        "IL_CLOUD_LOG_LEVEL": "debug",
        "IL_CLOUD_STATE_DIR": "/tmp/il-cloud",
    })
    assert config.dsn == "postgresql://db/interlock"
    assert config.bind_host == "::1"
    assert config.bind_port == 9000
    assert config.public_url == "https://cloud.example"
    assert config.session_secret == "s" * 40
    assert config.log_level == "debug"
    assert str(config.state_dir) == "/tmp/il-cloud"


def test_validate_accepts_a_complete_loopback_config():
    _valid_config().validate()


def test_validate_requires_a_dsn():
    from interlock.cloud.config import ConfigError

    with pytest.raises(ConfigError) as exc:
        _valid_config(dsn="").validate()
    assert "IL_CLOUD_DSN" in str(exc.value)


def test_from_env_rejects_a_non_numeric_port():
    from interlock.cloud.config import CloudConfig, ConfigError

    with pytest.raises(ConfigError) as exc:
        CloudConfig.from_env({"IL_CLOUD_PORT": "eighty"})
    assert "IL_CLOUD_PORT" in str(exc.value)


def test_malformed_env_port_is_a_usage_error_not_a_traceback(monkeypatch, capsys):
    from interlock.cloud.__main__ import main

    monkeypatch.setenv("IL_CLOUD_PORT", "eighty")
    assert main([]) == 2
    assert "IL_CLOUD_PORT" in capsys.readouterr().err


def test_connect_passes_a_connect_timeout(monkeypatch):
    from interlock.cloud import db

    seen = {}

    class _FakeConnection:
        pass

    def _connect(dsn, **kwargs):
        seen["dsn"] = dsn
        seen.update(kwargs)
        return _FakeConnection()

    monkeypatch.setitem(sys.modules, "psycopg",
                        types.SimpleNamespace(connect=_connect))
    conn = db.connect("postgresql://db/interlock")
    assert isinstance(conn, _FakeConnection)
    assert seen == {"dsn": "postgresql://db/interlock",
                    "connect_timeout": db.CONNECT_TIMEOUT_SECONDS}


def test_validate_rejects_an_out_of_range_port():
    from interlock.cloud.config import ConfigError

    with pytest.raises(ConfigError) as exc:
        _valid_config(bind_port=70000).validate()
    assert "IL_CLOUD_PORT" in str(exc.value)


def test_validate_rejects_a_short_session_secret():
    from interlock.cloud.config import ConfigError

    with pytest.raises(ConfigError) as exc:
        _valid_config(session_secret="short").validate()
    assert "IL_CLOUD_SESSION_SECRET" in str(exc.value)


def test_validate_rejects_an_arbitrary_bind_interface():
    from interlock.cloud.config import ConfigError

    with pytest.raises(ConfigError) as exc:
        _valid_config(bind_host="eth0").validate()
    assert "IL_CLOUD_BIND" in str(exc.value)


def test_public_bind_requires_https_public_url():
    from interlock.cloud.config import ConfigError

    with pytest.raises(ConfigError) as exc:
        _valid_config(bind_host="0.0.0.0", public_url="http://cloud.example").validate()
    assert "https://" in str(exc.value)

    _valid_config(bind_host="0.0.0.0",
                  public_url="https://cloud.example").validate()


# -- ASGI envelope ------------------------------------------------------

def test_healthz_answers_ok_with_json_and_a_generated_request_id():
    status, headers, body, sent = _call("/healthz")

    assert status == 200
    assert body == {"status": "ok", "service": "interlock-cloud"}
    assert headers["content-type"].startswith("application/json")
    assert re.match(r"^[0-9a-f]{16}$", headers["x-request-id"])
    starts = [m for m in sent if m["type"] == "http.response.start"]
    bodies = [m for m in sent if m["type"] == "http.response.body"]
    assert len(starts) == 1 and len(bodies) == 1
    assert bodies[0].get("more_body") is False


def test_inbound_request_id_is_echoed_when_well_formed():
    _status, headers, _body, _sent = _call(
        "/healthz", headers={"x-request-id": "smoke-1"}
    )
    assert headers["x-request-id"] == "smoke-1"


@pytest.mark.parametrize("inbound", ["bad id!", "a" * 65, "abc\n", "abc\r"])
def test_invalid_request_id_is_replaced(inbound):
    _status, headers, _body, _sent = _call(
        "/healthz", headers={"x-request-id": inbound}
    )
    assert headers["x-request-id"] != inbound
    assert re.match(r"^[0-9a-f]{16}$", headers["x-request-id"])


def test_unknown_path_is_404_not_found():
    status, headers, body, _sent = _call("/nope")
    assert status == 404
    assert body["error"] == {"code": "not_found", "message": "no such route"}
    assert headers["x-request-id"]


def test_non_get_on_a_known_path_is_405_with_allow():
    status, headers, body, _sent = _call("/healthz", method="POST")
    assert status == 405
    assert headers["allow"] == "GET"
    assert body["error"]["code"] == "method_not_allowed"


def test_readyz_without_a_dsn_is_503_unavailable():
    status, _headers, body, _sent = _call("/readyz")
    assert status == 503
    assert body == {"status": "unavailable"}


def test_readyz_pings_and_is_ready_when_the_database_answers():
    from interlock.cloud.app import CloudApp

    seen = []

    def _ping(dsn):
        seen.append(dsn)
        return True

    instance = CloudApp(_valid_config(), ping=_ping)
    status, _headers, body, _sent = _call("/readyz", app_instance=instance)
    assert status == 200
    assert body == {"status": "ready"}
    assert seen == ["postgresql://interlock@localhost/interlock"]


def test_readyz_reports_unavailable_when_the_ping_fails():
    from interlock.cloud.app import CloudApp

    instance = CloudApp(_valid_config(), ping=lambda dsn: False)
    status, _headers, body, _sent = _call("/readyz", app_instance=instance)
    assert status == 503
    assert body == {"status": "unavailable"}


def test_readyz_ping_runs_off_the_event_loop_thread():
    from interlock.cloud.app import CloudApp

    threads = []

    def _ping(dsn):
        threads.append(threading.current_thread())
        return True

    instance = CloudApp(_valid_config(), ping=_ping)
    status, _headers, body, _sent = _call("/readyz", app_instance=instance)
    assert status == 200
    assert body == {"status": "ready"}
    assert threads and threads[0] is not threading.main_thread()


def test_oversized_declared_body_is_413_payload_too_large():
    status, _headers, body, _sent = _call(
        "/healthz", headers={"content-length": "70000"}
    )
    assert status == 413
    assert body["error"]["code"] == "payload_too_large"


# -- migrations ---------------------------------------------------------

def test_available_lists_the_migrations_in_order():
    from interlock.cloud.migrate import available

    assert available() == [
        (1, "001_init.sql"),
        (2, "002_c3_reviews_grants.sql"),
        (3, "003_c4_receipts_audit.sql"),
        (4, "004_c5_policy_distribution.sql"),
    ]


def test_parse_versions_sorts_by_number():
    from interlock.cloud.migrate import parse_versions

    assert parse_versions(["002_b.sql", "001_a.sql"]) == [
        (1, "001_a.sql"),
        (2, "002_b.sql"),
    ]


def test_parse_versions_rejects_a_duplicate_prefix():
    from interlock.cloud.migrate import parse_versions

    with pytest.raises(ValueError):
        parse_versions(["001_a.sql", "001_b.sql"])


def test_parse_versions_rejects_a_gap():
    from interlock.cloud.migrate import parse_versions

    with pytest.raises(ValueError):
        parse_versions(["001_a.sql", "003_c.sql"])


def test_available_reads_a_temporary_migration_directory(tmp_path, monkeypatch):
    import interlock.cloud.migrate as migrate

    (tmp_path / "001_a.sql").write_text("select 1;", encoding="utf-8")
    (tmp_path / "002_b.sql").write_text("select 2;", encoding="utf-8")
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", tmp_path)
    assert migrate.available() == [(1, "001_a.sql"), (2, "002_b.sql")]


# -- schema -------------------------------------------------------------

def test_every_tenant_table_is_created_exactly_once():
    created = re.findall(r"CREATE TABLE\s+([a-z_][a-z0-9_]*)", _sql())
    assert len(created) == len(TABLES)
    assert set(created) == set(TABLES)
    for table in TABLES:
        assert created.count(table) == 1, table


def test_every_org_scoped_table_enables_rls_and_has_an_isolation_policy():
    sql = _sql()
    for table in ORG_SCOPED:
        assert "ALTER TABLE {} ENABLE ROW LEVEL SECURITY;".format(table) in sql
        assert (
            "CREATE POLICY org_isolation ON {} USING "
            "(org_id = current_setting('interlock.org_id', true));".format(table)
        ) in sql
    # orgs has no org_id: policy on it would compare a column that does not exist.
    assert "ALTER TABLE orgs " not in sql


def test_schema_stores_policy_epochs_as_the_hex_rule_set_identity():
    sql = _sql()
    assert not re.search(r"\bepoch\s+integer\b", sql, re.I)
    assert sql.count(
        "epoch text not null check (epoch ~ '^[0-9a-f]{16}$')"
    ) == 2  # policy_artifacts and policy_manifests


def test_org_retention_defaults_to_365_days_within_the_spec_bounds():
    block = re.search(r"CREATE TABLE orgs \((.*?)\);", _sql(), re.S).group(1)
    assert re.search(
        r"retention_days integer not null default 365\s+"
        r"check \(retention_days between 30 and 2555\)",
        block,
    )


def test_user_roles_are_explicit_and_limited_to_the_fixed_model():
    block = re.search(r"CREATE TABLE users \((.*?)\);", _sql(), re.S).group(1)
    assert "default 'member'" not in block
    assert re.search(
        r"role text not null\s+"
        r"check \(role in \('owner', 'admin', 'reviewer', 'auditor'\)\)",
        block,
    )


def test_receipts_primary_key_contains_mac():
    block = re.search(r"CREATE TABLE receipts \((.*?)\);", _sql(), re.S)
    assert block is not None
    assert re.search(r"primary key \([^)]*\bmac\b[^)]*\)", block.group(1), re.I)


def test_secrets_are_hashed_or_encrypted_never_plaintext():
    sql = _sql()
    assert "secret_hash text not null" in sql       # agent_keys
    assert "secret_enc text not null" in sql        # totp_secrets
    assert "csrf_hash text not null" in sql         # sessions
    assert re.search(r"^\s*(password|secret)\s+", sql, re.M) is None


def test_schema_documents_the_rls_role_property():
    sql = _sql()
    assert "BYPASSRLS" in sql
    assert "table owner" in sql


# -- packaging ----------------------------------------------------------

def test_pyproject_declares_the_cloud_extra_and_sql_package_data():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (
        'cloud = ["uvicorn>=0.30", "psycopg[binary]>=3.1", "cryptography>=42", "webauthn>=2.0"]'
        in text
    )
    assert '"interlock.cloud"' in text
    assert "*.sql" in text
    assert re.search(r"^dependencies\s*=\s*\[\s*\]\s*$", text, re.M)
    scripts = text.split("[project.scripts]", 1)[1].split("\n[", 1)[0]
    assert "cloud" not in scripts


# -- CLI ----------------------------------------------------------------

def test_cloud_is_registered_in_commands():
    from interlock.cli import COMMANDS

    assert ("cloud", "Enroll hosts and run the cloud connector", "cloud") in COMMANDS


@pytest.mark.parametrize("action", ACTIONS)
def test_every_cloud_subcommand_parses(action):
    from interlock.cli import build_parser

    args = build_parser().parse_args(["cloud", action])
    assert args.cloud_command == action


def test_unknown_cloud_action_is_a_usage_error():
    from interlock.cli import main

    assert main(["cloud", "bogus"]) == 64


def test_cloud_policy_is_the_one_remaining_stub(capsys):
    from interlock.cli import main

    assert main(["cloud", "policy"]) == 3
    assert "interlock cloud policy: not implemented yet" in capsys.readouterr().err


def test_cloud_enroll_help_exits_zero():
    from interlock.cli import main

    assert main(["cloud", "enroll", "--help"]) == 0
