"""The connector home: 0600 config and seed, strict document, redaction.

``CloudHome.load`` refuses any mode with a ``0o077`` bit, before parsing. A
save goes through a mode-0600 temporary file and ``os.replace`` so there is
never a readable window. The document is validated against an exact field
list: a typo is a refusal, not a silently ignored setting.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from interlock.cloud.connector.config import (
    CONFIG_MODE,
    REDACTED,
    SEED_MODE,
    CloudHome,
    HomeError,
    default_home,
    redact,
)
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.identity import generate_host_seed


def _document(**overrides):
    raw, _prefix, _digest = generate_agent_key()
    document = {
        "url": "https://cloud.example",
        "org_id": "org-1",
        "host_id": "host-1",
        "agent_key_id": "key-1",
        "agent_key": raw,
        "host_key_id": "a" * 64,
        "host_public_key": "b" * 64,
        "plane_public_keys": {"approval": "", "policy": "", "receipt": ""},
        "spool_dir": "spool",
        "state_dir": "state",
        "share_usernames": False,
    }
    document.update(overrides)
    return document


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


# -- writing and reading ------------------------------------------------

def test_save_writes_0600_json_and_load_round_trips(tmp_path):
    home = CloudHome(tmp_path)
    document = _document()

    saved = home.save(document)

    assert saved == document
    assert _mode(home.config_path) == CONFIG_MODE == 0o600
    assert json.loads(home.config_path.read_text()) == document
    assert home.load() == document
    assert [path.name for path in tmp_path.iterdir()] == ["cloud.json"]


def test_a_c2_document_without_share_usernames_loads_with_the_default(tmp_path):
    # A cloud.json enrolled before C3 has no `share_usernames`; loading it must
    # not fail, and the normalised copy carries the opt-out default so the
    # connector can read the field without a `.get` fallback.
    home = CloudHome(tmp_path)
    document = _document()
    del document["share_usernames"]
    home.save(document)

    assert home.load()["share_usernames"] is False
    assert json.loads(home.config_path.read_text())["share_usernames"] is False


def test_save_replaces_atomically_and_leaves_no_temporary_file(tmp_path):
    home = CloudHome(tmp_path)
    home.save(_document())
    home.save(_document(host_id="host-2"))

    assert home.load()["host_id"] == "host-2"
    assert not [path for path in tmp_path.iterdir()
                if path.name.endswith(".tmp")]


def test_document_serves_the_saved_copy_without_re_reading(tmp_path):
    home = CloudHome(tmp_path)
    home.save(_document())
    os.chmod(home.config_path, 0o644)

    # The live smoke proves the mode refusal before constructing a Connector;
    # the connector must then use the document it was already handed.
    with pytest.raises(PermissionError):
        home.load()
    assert home.document["url"] == "https://cloud.example"


def test_load_missing_file_is_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        CloudHome(tmp_path).load()


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o604, 0o606])
def test_load_refuses_a_config_with_any_group_or_world_bits(tmp_path, mode):
    home = CloudHome(tmp_path)
    home.save(_document())
    os.chmod(home.config_path, mode)

    with pytest.raises(PermissionError) as exc:
        CloudHome(tmp_path).load()
    assert "chmod 600" in str(exc.value)
    assert oct(mode)[2:] in str(exc.value)


def test_load_refuses_an_unsafe_seed_before_parsing_the_config(tmp_path):
    home = CloudHome(tmp_path)
    home.save(_document())
    home.save_seed(generate_host_seed())
    os.chmod(home.seed_path, 0o644)

    with pytest.raises(PermissionError) as exc:
        CloudHome(tmp_path).load()
    assert "cloud.seed" in str(exc.value)


def test_seed_is_32_bytes_at_0600_and_never_in_the_document(tmp_path):
    home = CloudHome(tmp_path)
    seed = generate_host_seed()

    home.save(_document())
    home.save_seed(seed)

    assert _mode(home.seed_path) == SEED_MODE == 0o600
    assert home.load_seed() == seed
    assert seed not in home.config_path.read_bytes()
    assert seed.hex() not in home.config_path.read_text()


@pytest.mark.parametrize("seed", [b"", b"x" * 31, b"x" * 33, "x" * 32])
def test_save_seed_rejects_anything_but_32_bytes(tmp_path, seed):
    with pytest.raises(ValueError):
        CloudHome(tmp_path).save_seed(seed)


def test_load_seed_rejects_a_missing_or_wrong_length_file(tmp_path):
    home = CloudHome(tmp_path)
    with pytest.raises(FileNotFoundError):
        home.load_seed()
    home.seed_path.write_bytes(b"short")
    os.chmod(home.seed_path, 0o600)
    with pytest.raises(HomeError):
        home.load_seed()


def test_remove_config_removes_both_files_and_forgets_the_cache(tmp_path):
    home = CloudHome(tmp_path)
    home.save(_document())
    home.save_seed(generate_host_seed())

    assert home.remove_config() is True
    assert not home.config_path.exists() and not home.seed_path.exists()
    assert home.remove_config() is False
    with pytest.raises(FileNotFoundError):
        home.document


def test_default_home_honours_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("IL_CLOUD_HOME", str(tmp_path / "custom"))
    assert default_home() == tmp_path / "custom"
    monkeypatch.delenv("IL_CLOUD_HOME")
    assert default_home().name == ".interlock"


# -- document validation ------------------------------------------------

def test_unknown_field_is_refused():
    document = _document()
    document["agent_secret"] = "oops"
    with pytest.raises(HomeError) as exc:
        CloudHome.validate_document(document)
    assert "agent_secret" in str(exc.value)


def test_missing_field_is_refused():
    document = _document()
    del document["host_id"]
    with pytest.raises(HomeError) as exc:
        CloudHome.validate_document(document)
    assert "host_id" in str(exc.value)


@pytest.mark.parametrize("field", [
    "url", "org_id", "host_id", "agent_key_id", "agent_key",
    "host_key_id", "host_public_key", "spool_dir", "state_dir",
])
def test_every_string_field_must_be_a_non_empty_string(field):
    for value in ("", 5, None):
        with pytest.raises(HomeError):
            CloudHome.validate_document(_document(**{field: value}))


def test_non_object_documents_are_refused():
    for document in (None, [], "x", 5):
        with pytest.raises(HomeError):
            CloudHome.validate_document(document)


def test_plane_public_keys_must_be_an_object():
    with pytest.raises(HomeError):
        CloudHome.validate_document(_document(plane_public_keys=[]))


def test_agent_key_must_be_a_well_formed_ilk_key():
    with pytest.raises(HomeError):
        CloudHome.validate_document(_document(agent_key="not-a-key"))


@pytest.mark.parametrize("url,accepted", [
    ("https://cloud.example", True),
    ("https://cloud.example:8443/base", True),
    ("http://127.0.0.1:8787", True),
    ("http://[::1]:8787", True),
    ("http://localhost:8787", True),
    ("http://cloud.example", False),
    ("http://192.168.1.5:8787", False),
    ("ftp://cloud.example", False),
    ("cloud.example", False),
    ("", False),
])
def test_url_must_be_https_or_loopback_http(url, accepted):
    document = _document(url=url)
    if accepted:
        CloudHome.validate_document(document)
    else:
        with pytest.raises(HomeError):
            CloudHome.validate_document(document)


# -- redaction ----------------------------------------------------------

def test_redact_hides_sensitive_names_recursively():
    raw, _prefix, _digest = generate_agent_key()
    payload = {
        "agent_key": raw,
        "nested": {"token": "ilkt_org_secret", "password": "x",
                   "authorization": "Bearer " + raw,
                   "keep": "visible"},
        "list": [{"cookie": "c"}, raw],
        "message": "request failed for " + raw + " while enrolling",
    }

    cleaned = redact(payload)

    assert cleaned["agent_key"] == REDACTED
    assert cleaned["nested"]["token"] == REDACTED
    assert cleaned["nested"]["password"] == REDACTED
    assert cleaned["nested"]["authorization"] == REDACTED
    assert cleaned["nested"]["keep"] == "visible"
    assert cleaned["list"][0]["cookie"] == REDACTED
    assert cleaned["list"][1] == "ilk_[redacted]"
    assert raw not in json.dumps(cleaned)
    assert cleaned["message"] == (
        "request failed for ilk_[redacted] while enrolling")


def test_redact_leaves_plain_values_alone():
    assert redact({"a": 1, "b": True, "c": None}) == {
        "a": 1, "b": True, "c": None}
