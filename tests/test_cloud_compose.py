"""The production compose stack, its secret files and its operator scripts.

These are static checks, not a deploy: the stack must bind loopback by
default, take every secret from a mounted file (never an environment value),
carry healthchecks, run the plane read-only, and ship backup/restore scripts
that refuse to lower the manifest version floor silently.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy" / "cloud"
COMPOSE = DEPLOY / "docker-compose.yml"
ENV_EXAMPLE = DEPLOY / ".env.example"
SECRETS = DEPLOY / "secrets"

#: A value that looks like real key material rather than a placeholder.
_ENTROPY = re.compile(r"[0-9a-fA-F]{32,}|[A-Za-z0-9_-]{40,}")


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _services() -> dict:
    return _compose()["services"]


def _env(name: str) -> dict:
    return _services()[name]["environment"]


# -- shape --------------------------------------------------------------

def test_the_stack_parses_with_the_expected_services_and_volumes():
    document = _compose()
    assert document["name"] == "interlock-cloud"
    assert set(document["services"]) == {"postgres", "plane", "retention",
                                         "caddy"}
    assert set(document["volumes"]) == {
        "interlock-cloud-pgdata", "interlock-cloud-caddy-data",
        "interlock-cloud-caddy-config"}
    assert set(document["secrets"]) == {
        "postgres_password", "session_secret", "approval_key", "policy_key",
        "preview_kek", "oidc_client_secret"}


def test_every_secret_is_a_file_mounted_by_compose():
    for name, block in _compose()["secrets"].items():
        assert "file" in block, name
        assert "secrets/" in block["file"], name
        # An inline value in the compose file is exactly what this forbids.
        assert "environment" not in block, name


def test_the_plane_and_postgres_publish_only_on_loopback():
    services = _services()
    plane_ports = services["plane"]["ports"]
    assert "127.0.0.1:8787:8787" in plane_ports
    assert "127.0.0.1:9101:9101" in plane_ports
    assert all(str(port).startswith("127.0.0.1:")
               for port in plane_ports)
    assert all(str(port).startswith("127.0.0.1:")
               for port in services["postgres"]["ports"])


def test_caddy_shares_the_plane_network_namespace_and_the_tls_ports():
    caddy = _services()["caddy"]
    assert caddy["network_mode"] == "service:plane"
    assert "80:80" in caddy["ports"]
    assert "443:443" in caddy["ports"]
    assert "443:443/udp" in caddy["ports"]
    mounted = {volume.split(":")[0] for volume in caddy["volumes"]}
    assert "./Caddyfile" in mounted


# -- secrets ------------------------------------------------------------

def test_the_plane_reads_every_secret_from_a_file_path():
    environment = _env("plane")
    secret_keys = [key for key in environment
                   if key.endswith(("_FILE", "_SECRET", "_KEY", "_KEK"))]
    assert "IL_CLOUD_SESSION_SECRET_FILE" in secret_keys
    assert "IL_CLOUD_APPROVAL_KEY_FILE" in secret_keys
    assert "IL_CLOUD_POLICY_KEY_FILE" in secret_keys
    assert "IL_CLOUD_PREVIEW_KEK_FILE" in secret_keys
    assert "IL_CLOUD_OIDC_CLIENT_SECRET_FILE" in secret_keys
    for key in secret_keys:
        value = str(environment[key])
        if value:
            assert value.startswith("/run/secrets/"), key
    assert "IL_CLOUD_SESSION_SECRET" not in environment
    assert "IL_CLOUD_PREVIEW_KEK" not in environment


def test_postgres_reads_its_password_from_a_file_not_the_environment():
    environment = _env("postgres")
    assert environment["POSTGRES_PASSWORD_FILE"] == "/run/secrets/postgres_password"
    assert "POSTGRES_PASSWORD" not in environment
    assert _services()["postgres"]["secrets"] == ["postgres_password"]


def test_no_compose_or_env_value_carries_a_real_looking_secret():
    for path in (COMPOSE, ENV_EXAMPLE):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            content = line.strip()
            if not content or content.startswith("#"):
                continue
            # Skip the paths and variable references that are the point.
            if "secrets/" in content or "${" in content or "/run/" in content:
                continue
            assert not _ENTROPY.search(content), "{}: {}".format(path, content)


def test_the_env_example_has_placeholders_and_secret_file_paths():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    values = {}
    for line in text.splitlines():
        if line.strip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    for key in ("IL_CLOUD_DB_PASSWORD_FILE", "IL_CLOUD_SESSION_SECRET_FILE_PATH",
                "IL_CLOUD_APPROVAL_KEY_FILE_PATH",
                "IL_CLOUD_POLICY_KEY_FILE_PATH",
                "IL_CLOUD_PREVIEW_KEK_FILE_PATH",
                "IL_CLOUD_OIDC_CLIENT_SECRET_FILE_PATH"):
        assert values[key].startswith("./secrets/"), key
    assert "IL_CLOUD_SESSION_SECRET" not in values
    assert "IL_CLOUD_PREVIEW_KEK" not in values
    assert values["IL_CLOUD_PUBLIC_URL"].startswith("https://")
    assert values["IL_CLOUD_HOSTNAME"] == "cloud.example.com"


def test_the_secret_directory_contains_no_material():
    names = {path.name for path in SECRETS.iterdir()}
    assert names <= {".gitignore", "README.md"}
    ignore = (SECRETS / ".gitignore").read_text(encoding="utf-8")
    assert "*" in ignore.splitlines()
    assert "!README.md" in ignore


# -- health and hardening ----------------------------------------------

def test_postgres_and_the_plane_have_healthchecks_and_start_in_order():
    services = _services()
    assert "pg_isready" in " ".join(services["postgres"]["healthcheck"]["test"])
    plane_check = " ".join(str(part) for part in
                           services["plane"]["healthcheck"]["test"])
    assert "/readyz" in plane_check
    assert services["plane"]["depends_on"]["postgres"]["condition"] == (
        "service_healthy")
    assert services["caddy"]["depends_on"]["plane"]["condition"] == (
        "service_healthy")


def test_the_plane_and_retention_run_read_only_without_capabilities():
    for name in ("plane", "retention"):
        service = _services()[name]
        assert service["read_only"] is True, name
        assert "ALL" in service["cap_drop"], name
        assert "no-new-privileges:true" in service["security_opt"], name
        assert "/tmp" in service["tmpfs"], name


def test_the_plane_and_retention_override_the_entrypoint_not_the_command():
    # Compose appends `command:` to the image ENTRYPOINT. The image's
    # entrypoint is already `python3 -m interlock.cloud`, so a `command:` here
    # would run `python3 -m interlock.cloud sh -c ...` and exit with an
    # argparse error. Only an explicit `entrypoint:` replaces it.
    services = _services()
    for name in ("plane", "retention"):
        assert "command" not in services[name], name
        entrypoint = services[name]["entrypoint"]
        assert isinstance(entrypoint, list) and entrypoint, name
        script = " ".join(str(part) for part in entrypoint)
        assert "sh" in script and "-c" in script, name
    plane_script = " ".join(str(part) for part in services["plane"]["entrypoint"])
    assert "interlock.cloud.migrate" in plane_script
    assert "interlock.cloud" in plane_script
    retention_script = " ".join(
        str(part) for part in services["retention"]["entrypoint"])
    assert "interlock.cloud.retention" in retention_script


def test_the_plane_and_retention_can_authenticate_to_postgres():
    # The postgres container requires a password over TCP and the DSN has no
    # password, so both services mount the secret and read it into PGPASSWORD.
    services = _services()
    for name in ("plane", "retention"):
        assert "postgres_password" in services[name]["secrets"], name
        script = " ".join(str(part) for part in services[name]["entrypoint"])
        assert "/run/secrets/postgres_password" in script, name
        assert "PGPASSWORD" in script, name
    # Still a file, never an environment value.
    assert "PGPASSWORD" not in services["plane"]["environment"]
    assert "PGPASSWORD" not in services["retention"]["environment"]


def test_the_profiles_separate_production_tls_and_ops():
    services = _services()
    assert set(services["plane"]["profiles"]) == {"prod", "tls"}
    assert services["retention"]["profiles"] == ["ops"]
    assert services["caddy"]["profiles"] == ["tls"]


# -- image and edge -----------------------------------------------------

def test_the_dockerfile_installs_only_the_cloud_extra_and_runs_unprivileged():
    text = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "'.[cloud]'" in text
    assert "USER interlock" in text
    assert "uid 10001" in text or "--uid 10001" in text
    assert "EXPOSE 8787 9101" in text
    assert "interlock.cloud" in text


def test_the_caddyfile_terminates_tls_and_forwards_to_loopback():
    text = (DEPLOY / "Caddyfile").read_text(encoding="utf-8")
    assert "reverse_proxy 127.0.0.1:8787" in text
    assert "Strict-Transport-Security" in text
    assert "max_size 10MB" in text
    assert "X-Content-Type-Options" in text


# -- operator scripts ---------------------------------------------------

@pytest.mark.parametrize("name", ["backup.sh", "restore.sh"])
def test_operator_scripts_are_executable_and_syntax_clean(name):
    path = DEPLOY / name
    assert os.access(path, os.X_OK)
    completed = subprocess.run(
        ["bash", "-n", str(path)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


def test_backup_writes_a_custom_dump_and_a_sha256_sidecar():
    text = (DEPLOY / "backup.sh").read_text(encoding="utf-8")
    assert "pg_dump --format=custom" in text
    assert "--no-owner --no-privileges" in text
    assert ".sha256" in text
    assert "set -euo pipefail" in text


def test_backup_refuses_to_run_without_a_dsn():
    completed = subprocess.run(
        ["bash", str(DEPLOY / "backup.sh")],
        capture_output=True, text=True,
        env={key: value for key, value in os.environ.items()
             if key != "IL_CLOUD_DSN"})
    assert completed.returncode == 2
    assert "IL_CLOUD_DSN" in completed.stderr


def test_restore_requires_yes_and_warns_about_the_version_floor():
    text = (DEPLOY / "restore.sh").read_text(encoding="utf-8")
    assert "refusing to restore without --yes" in text
    assert "--reset-floor" in text
    assert "version-floor" in text
    completed = subprocess.run(
        ["bash", str(DEPLOY / "restore.sh"), "--file", "missing.dump"],
        capture_output=True, text=True)
    assert completed.returncode == 2
    assert "--yes" in completed.stderr
