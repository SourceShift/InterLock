"""Every catalog detector against the actions that must end in each of its
verdicts, and the look-alikes that must not.

The cases live in ``tests/conformance/detectors/*.json`` (format in
``tests/conformance/runner.py``). One pytest item per entry: an entry's cases
run in order on one rule instance, so a stateful detector is one sequence.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "conformance"))
import runner  # noqa: E402

ENTRIES = runner.load()

#: Factories whose arguments JSON cannot express, so their behaviour is pinned
#: by the module's own unit tests instead.
NOT_JSON = {
    ("mcp_capability_lease", "mcp_capability_lease"): "takes a live LeaseRegistry holding issued grants",
    ("secret_path_command_guard", "secret_path_command_guard"):
        "paths are resolved against the process HOME, so its behaviour is pinned by "
        "tests/test_secret_path_command_guard.py",
}


def _id(entry):
    return "{}:{}.{}".format(entry["_file"], entry["detector"], entry["factory"])


@pytest.mark.parametrize("entry", ENTRIES, ids=[_id(e) for e in ENTRIES])
def test_detector_conformance(entry):
    failed = [o for o in runner.run_entry(entry) if not o.ok]
    assert not failed, "\n".join(
        "{} | expect {} got {}{}".format(o.name, o.expect, o.got, " | " + o.detail if o.detail else "")
        for o in failed)


def test_every_catalog_factory_has_cases():
    from interlock.console.catalog import build_catalog

    covered = {(e["detector"], e["factory"]) for e in ENTRIES} | set(NOT_JSON)
    missing = sorted("{}.{}".format(d["module"], f["name"])
                     for d in build_catalog()["detectors"] for f in d["factories"]
                     if (d["module"], f["name"]) not in covered)
    assert not missing, "no conformance cases for: " + ", ".join(missing)
    here = os.path.dirname(__file__)
    for module, _ in NOT_JSON:
        assert os.path.exists(os.path.join(here, "test_{}.py".format(module))), module


def test_every_declared_verdict_is_reached():
    """A factory that can BLOCK and ESCALATE has a case ending in each."""
    from interlock.console.catalog import build_catalog

    reached = {}
    for e in ENTRIES:
        reached.setdefault(e["detector"], set()).update(c["expect"] for c in e["cases"])
    gaps = []
    exempt = {module for module, _ in NOT_JSON}
    for d in build_catalog()["detectors"]:
        if d["module"] in exempt:
            continue
        declared = {v.upper() for v in d.get("verdicts", [])} - {"ALLOW"}
        missing = declared - reached.get(d["module"], set())
        if missing:
            gaps.append("{}: {}".format(d["module"], ", ".join(sorted(missing))))
    assert not gaps, "verdicts never reached: " + "; ".join(gaps)
