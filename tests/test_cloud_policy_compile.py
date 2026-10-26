"""The compiler: deterministic bytes, a round-trip proof, explicit refusals.

A compile is only publishable if the artifact it produced judges the corpus
exactly as the authored engine did. These tests pin byte determinism (across
processes and hash seeds), the round-trip corpus, the module-reference rules,
and the refusal codes the route surfaces as ``422``.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

from interlock.cloud.policy import compile as compiler
from interlock.cloud.policy.compile import (
    DEFAULT_CORPUS,
    RULES_MODULE_ENV,
    CompileError,
    compile_from_source,
)
from interlock.enforce import Decision
from interlock.event import SensorEvent
from interlock.policy.artifact import (
    FAILURE_POLICY_DEFAULTS,
    canonical_bytes,
    load_artifact,
)
from tests.fixtures.cloud.rules_module import scope_document

MODULE = "tests.fixtures.cloud.rules_module:templates"


def _scope(**overrides):
    document = scope_document()
    document.update(overrides)
    return document


# -- determinism --------------------------------------------------------

def test_the_same_source_compiles_to_byte_identical_artifacts():
    first = compile_from_source([], _scope(), rules_module=MODULE)
    second = compile_from_source([], _scope(), rules_module=MODULE)
    assert first.artifact_bytes == second.artifact_bytes
    assert first.sha256 == second.sha256
    assert first.epoch == second.epoch
    assert first.artifact_bytes == canonical_bytes(json.loads(
        first.artifact_bytes.decode("utf-8")))
    assert hashlib.sha256(first.artifact_bytes).hexdigest() == first.sha256


def test_two_processes_with_different_hash_seeds_agree():
    code = (
        "import json\n"
        "from interlock.cloud.policy.compile import compile_from_source\n"
        "from tests.fixtures.cloud.rules_module import scope_document\n"
        "r = compile_from_source([], scope_document(), "
        "rules_module='tests.fixtures.cloud.rules_module:templates')\n"
        "print(r.sha256)\n"
    )
    outputs = []
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for seed in ("0", "1", "random"):
        environment = dict(os.environ, PYTHONHASHSEED=seed)
        completed = subprocess.run(
            [sys.executable, "-c", code], cwd=root, env=environment,
            capture_output=True, text=True, timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.append(completed.stdout.strip())
    assert len(set(outputs)) == 1


def test_template_ids_and_diffs_are_sorted_not_binding_order():
    scope = {
        "version": 1,
        "default_scope": [],
        "allow_unscoped": False,
        "bindings": {
            "zeta": [
                {"template": "shell_allowlist", "params": {"allow": ["ls"]}},
                {"template": "file_guard", "params": {"escalate_prefixes": ["/srv"]}},
            ],
            "alpha": [
                {"template": "egress_denylist", "params": {"deny_hosts": ["x.test"]}},
            ],
        },
    }
    result = compile_from_source([], scope, rules_module=MODULE)
    assert result.template_ids == ["egress_denylist", "file_guard",
                                   "shell_allowlist"]
    assert result.diffs["policy_ids_added"] == []
    assert result.diffs["policy_ids_removed"] == []
    assert list(result.diffs["counts"]) == sorted(result.diffs["counts"])


# -- the round trip -----------------------------------------------------

def test_the_compiled_artifact_judges_the_bundled_corpus_identically():
    result = compile_from_source([], _scope(), rules_module=MODULE)
    assert DEFAULT_CORPUS.is_file()
    events = []
    for line in DEFAULT_CORPUS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            raw = json.loads(line)
            events.append(SensorEvent(**{key: raw[key] for key in (
                "action", "args", "principal", "parent_principal", "span_id",
                "phase", "cwd", "call_id") if key in raw}))
    assert len(events) >= 40
    compiled = load_artifact(result.artifact_bytes)
    verdicts = {compiled.evaluate(event).verdict.name for event in events}
    assert verdicts == {"ALLOW", "BLOCK", "MODIFY", "ESCALATE"}
    assert result.diffs["counts"] == {
        "ALLOW": 18, "BLOCK": 18, "ESCALATE": 8, "MODIFY": 4,
    }


def test_the_first_divergence_refuses_the_compile(monkeypatch):
    class Divergent:
        def evaluate(self, event):
            return Decision.block("diverged", policy_id="other")

    monkeypatch.setattr(compiler, "load_artifact", lambda raw: Divergent())
    with pytest.raises(CompileError) as exc:
        compile_from_source([], _scope(), rules_module=MODULE)
    assert exc.value.code == "bad_artifact"
    assert "divergence at corpus event 0" in exc.value.message


def test_an_empty_policy_is_refused():
    with pytest.raises(CompileError) as exc:
        compile_from_source([], {"version": 1, "bindings": {}})
    assert exc.value.code == "bad_artifact"
    assert "empty" in exc.value.message


def test_a_document_only_policy_compiles_without_a_module():
    result = compile_from_source(
        [{"version": 1, "rules": []}],
        {"version": 1, "bindings": {}},
        corpus=DEFAULT_CORPUS,
    )
    assert result.rules_module is None
    artifact = load_artifact(result.artifact_bytes)
    assert artifact.documents[0]["source"] == "<policy>"


# -- module references --------------------------------------------------

def test_scoped_bindings_without_any_module_are_refused_with_the_exact_message():
    with pytest.raises(CompileError) as exc:
        compile_from_source([], _scope(), rules_module=None)
    assert exc.value.code == "bad_artifact"
    assert exc.value.message == (
        "scope bindings require a rules module (set rules_module or "
        "IL_CLOUD_POLICY_MODULE)")


def test_the_environment_names_the_module_for_a_deployment(monkeypatch):
    monkeypatch.setenv(RULES_MODULE_ENV, MODULE)
    result = compile_from_source([], _scope())
    assert result.rules_module == MODULE
    assert load_artifact(result.artifact_bytes).rules_module == MODULE


def test_an_explicit_module_that_disagrees_with_the_environment_is_refused(
        monkeypatch):
    monkeypatch.setenv(RULES_MODULE_ENV, "tests.fixtures.cloud.other:templates")
    with pytest.raises(CompileError) as exc:
        compile_from_source([], _scope(), rules_module=MODULE)
    assert exc.value.code == "module_mismatch"


def test_an_unresolvable_module_or_binding_is_a_bad_artifact():
    with pytest.raises(CompileError) as exc:
        compile_from_source([], _scope(),
                            rules_module="tests.fixtures.cloud.nope:templates")
    assert exc.value.code == "bad_artifact"

    scope = _scope()
    scope["bindings"]["acme"].append({"template": "ghost", "params": {}})
    with pytest.raises(CompileError) as exc:
        compile_from_source([], scope, rules_module=MODULE)
    assert exc.value.code == "bad_artifact"
    assert "ghost" in exc.value.message


def test_the_artifact_names_the_module_but_embeds_no_code():
    result = compile_from_source([], _scope(), rules_module=MODULE)
    artifact = json.loads(result.artifact_bytes.decode("utf-8"))
    assert artifact["rules_module"] == MODULE
    assert artifact["template_ids"] == result.template_ids
    assert "def " not in result.artifact_bytes.decode("utf-8")
    assert "lambda" not in result.artifact_bytes.decode("utf-8")


# -- failure policy and catalog -----------------------------------------

def test_failure_policy_is_validated_and_carried():
    policy = dict(FAILURE_POLICY_DEFAULTS, shell="open", email="open")
    result = compile_from_source([], _scope(), rules_module=MODULE,
                                 failure_policy=policy)
    assert result.failure_policy == policy
    assert load_artifact(result.artifact_bytes).failure_policy == policy

    with pytest.raises(CompileError) as exc:
        compile_from_source([], _scope(), rules_module=MODULE,
                            failure_policy={"shell": "closed"})
    assert exc.value.code == "bad_artifact"


def test_the_catalog_is_part_of_the_identity():
    first = compile_from_source([], _scope(), rules_module=MODULE,
                                catalog="catalog-a")
    second = compile_from_source([], _scope(), rules_module=MODULE,
                                 catalog="catalog-b")
    assert first.catalog == "catalog-a"
    assert first.epoch != second.epoch
    assert first.sha256 != second.sha256


def test_a_broken_corpus_refuses_rather_than_skipping_the_proof(tmp_path):
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(CompileError) as exc:
        compile_from_source([], _scope(), rules_module=MODULE, corpus=corpus)
    assert exc.value.code == "bad_artifact"

    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(CompileError):
        compile_from_source([], _scope(), rules_module=MODULE, corpus=empty)


def test_the_report_has_stable_keys():
    result = compile_from_source([], _scope(), rules_module=MODULE)
    report = result.to_dict()
    assert set(report) == {
        "sha256", "epoch", "size", "rules_module", "template_ids",
        "scope_epochs", "diffs", "catalog", "failure_policy",
    }
    assert report["size"] == len(result.artifact_bytes)
    assert list(report["scope_epochs"]) == ["acme", "acme/agent1", "beta"]
