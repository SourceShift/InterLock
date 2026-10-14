"""The detector catalog API: ``GET /api/detectors`` and
``GET /api/detectors/<module>``.

Each test is named for the claim it proves:

- ``/api/detectors`` reports a count and a detector list matching
  ``interlock/detectors/`` exactly (AC1),
- every detector has a non-empty summary, at least one factory whose
  signature starts with ``(``, verdicts drawn only from ALLOW/BLOCK/MODIFY,
  and a category that is one of the listed categories; ``shell_injection_guard``
  lists a factory named ``shell_injection_guard`` (AC2),
- the category names match the docs page's headings, in order, and every
  detector module appears in exactly one category (AC3),
- ``/api/detectors/shell_injection_guard`` answers 200 with ``doc`` equal to
  that module's ``inspect.getdoc`` text; an unknown module and a path-traversal
  attempt both answer 404 with code ``unknown_detector`` (AC4),
- every detector reports the ``policy_id`` it stamps on a receipt, which is not
  its module name, so the console can link a rule to its detector's detail page
  (AC5).

The server is hosted in-process, in a daemon thread, the same way
:mod:`tests.test_console_server` hosts it for the health-endpoint tests.
"""
from __future__ import annotations

import contextlib
import http.client
import importlib
import inspect
import json
import pkgutil
import re
import threading
from pathlib import Path
from typing import Iterator

import interlock.detectors as detectors_pkg
from interlock.console.server import ConsoleServer


@contextlib.contextmanager
def _serve(static_root: Path) -> Iterator[ConsoleServer]:
    server = ConsoleServer(("127.0.0.1", 0), static_root)
    thread = threading.Thread(
        target=server.serve_forever, daemon=True, name="interlock-console-catalog-test"
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _request(server: ConsoleServer, path: str, *, method: str = "GET"):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5.0)
    try:
        conn.request(method, path)
        response = conn.getresponse()
        body = response.read()
        return response, body
    finally:
        conn.close()


def test_detectors_count_and_modules_match_the_package(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/detectors")

    assert response.status == 200
    payload = json.loads(body)
    expected = sorted(
        m.name for m in pkgutil.iter_modules(detectors_pkg.__path__) if not m.name.startswith("_")
    )
    assert payload["count"] == len(expected) == len(payload["detectors"])
    assert sorted(d["module"] for d in payload["detectors"]) == expected


def test_every_detector_has_the_required_shape(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/detectors")

    assert response.status == 200
    payload = json.loads(body)
    category_names = {c["name"] for c in payload["categories"]}
    for detector in payload["detectors"]:
        assert detector["summary"].strip()
        assert detector["factories"]
        for factory in detector["factories"]:
            assert factory["name"]
            assert factory["signature"].startswith("(")
        assert set(detector["verdicts"]) <= {"ALLOW", "BLOCK", "MODIFY", "ESCALATE"}
        assert detector["category"] in category_names
        assert "policy_id" in detector

    shell_guard = next(d for d in payload["detectors"] if d["module"] == "shell_injection_guard")
    assert "shell_injection_guard" in [f["name"] for f in shell_guard["factories"]]


def test_detector_reports_the_id_it_stamps_on_a_receipt(tmp_path):
    """A receipt's ``policy_id`` is the id the deciding detector stamped, which is
    not its module name (``tool_result_injection_guard`` stamps
    ``tool_result_injection``). The catalog carries it so the console can link a
    receipt's rule to that detector's detail page instead of the policy list."""
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/detectors")

    assert response.status == 200
    by_module = {d["module"]: d for d in json.loads(body)["detectors"]}
    assert by_module["tool_result_injection_guard"]["policy_id"] == "tool_result_injection"
    assert by_module["shell_injection_guard"]["policy_id"] == "shell_injection"
    # A module that stamps no id of its own reports null, not a missing key.
    assert by_module["data_egress"]["policy_id"] is None


def test_categories_match_the_docs_page_headings_and_partition_modules(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/detectors")

    assert response.status == 200
    payload = json.loads(body)

    docs_text = Path("docs/reference/detectors.md").read_text(encoding="utf-8")
    after_categories = docs_text.split("\n## Categories\n", 1)[1]
    headings = re.findall(r"^## (.+)$", after_categories, re.M)
    assert [c["name"] for c in payload["categories"]] == headings

    seen = {}
    for category in payload["categories"]:
        for module in category["modules"]:
            seen[module] = seen.get(module, 0) + 1
    detector_modules = {d["module"] for d in payload["detectors"]}
    assert set(seen) == detector_modules
    assert all(count == 1 for count in seen.values())


def test_detector_detail_matches_inspect_getdoc(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/detectors/shell_injection_guard")

    assert response.status == 200
    payload = json.loads(body)
    module = importlib.import_module("interlock.detectors.shell_injection_guard")
    assert payload["module"] == "shell_injection_guard"
    assert payload["doc"] == inspect.getdoc(module)


def test_unknown_and_path_traversal_module_names_are_404_unknown_detector(tmp_path):
    with _serve(tmp_path) as server:
        unknown_response, unknown_body = _request(server, "/api/detectors/os")
        traversal_response, traversal_body = _request(server, "/api/detectors/..%2fsink")

    assert unknown_response.status == 404
    assert json.loads(unknown_body)["error"]["code"] == "unknown_detector"
    assert traversal_response.status == 404
    assert json.loads(traversal_body)["error"]["code"] == "unknown_detector"
