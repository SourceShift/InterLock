"""Run detector conformance cases: each catalog detector against actions that
must end in a given verdict, and look-alikes that must not.

A case file (``tests/conformance/detectors/<category>.json``) is a list of entries::

    {"detector": "data_egress", "factory": "network_egress_guard",
     "kwargs": {"allowed_hosts": ["api.acme.com"]},
     "cases": [
       {"name": "post to an unlisted host", "expect": "BLOCK",
        "event": {"action": "http_post", "args": {"url": "https://evil.example/x"}}},
       {"name": "post to the listed host", "expect": "ALLOW",
        "event": {"action": "http_post", "args": {"url": "https://api.acme.com/x"}}}
     ]}

- Cases of one entry run **in order on one rule instance**, so a stateful
  detector (rate limits, budgets, loops, baselines) is exercised as a sequence.
- ``expect`` is ALLOW, BLOCK, MODIFY or ESCALATE: the engine's verdict for the
  event. For MODIFY, ``rewrite_includes`` / ``rewrite_excludes`` list strings
  the rewritten arguments (or result) must / must not contain.
- ``event`` takes ``action``, ``args``, ``phase`` ("call" or "result"),
  ``principal``, ``span_id``, ``parent_principal``, ``call_id``.
- ``{{name}}`` in any string is replaced by a credential-shaped fixture built
  here at run time (see :data:`FIXTURES`), so no literal key is ever committed.

``python3 tests/conformance/runner.py [FILE ...]`` prints one line per case:
pass/fail, the detector, the case name and the verdicts - never the payload.
"""
from __future__ import annotations

import copy
import glob
import importlib
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from interlock.event import SensorEvent  # noqa: E402
from interlock.policy.engine import PolicyEngine  # noqa: E402

VERDICTS = ("ALLOW", "BLOCK", "MODIFY", "ESCALATE")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


#: Credential-shaped fixtures, assembled so no literal sits in the repository.
FIXTURES: Dict[str, str] = {
    "gh_token": "gh" + "p_" + "R7t3Vw9Qx2" * 3 + "Lm4Np8",
    "gh_fine_token": "github" + "_pat_" + "11ABCDEFG0" + "a1B2c3D4e5" * 6 + "Zz",
    "aws_key_id": "AK" + "IA" + "QWERTYUIOP234567",
    "aws_secret": "wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCY" + "zzEXAMPLEKEY",
    "stripe_key": "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "stripe_test_key": "sk" + "_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "openai_key": "sk" + "-proj-" + "Ab1Cd2Ef3Gh4" * 4,
    "anthropic_key": "sk" + "-ant-api03-" + "Zx9_Yw8-Vu7Ts6Rq5Po4Nm3",
    "slack_token": "xo" + "xb-" + "1234567890-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx",
    "slack_webhook": "https://hooks." + "slack.com/services/" + "T00000000/B00000000/" + "XXXXXXXXXXXXXXXXXXXXXXXX",
    "google_api_key": "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "npm_token": "np" + "m_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
           + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "pem_private_key": "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n-----END RSA "
                       + "PRIVATE KEY-----",
    "db_uri": "postgres://admin:" + "S3cr3tPassw0rd" + "@db.internal:5432/prod",
    "basic_auth_url": "https://deploy:" + "hunter2hunter2" + "@git.example.com/repo.git",
    "bearer_header": "Authorization: Bearer " + "abcDEF123ghiJKL456mnoPQR789",
    "s3_presigned_url": "https://bucket.s3.amazonaws.com/report.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                        "&X-Amz-Credential=" + "AK" + "IAQWERTYUIOP234567" + "%2F20261014%2Fus-east-1%2Fs3%2Faws4_request"
                        "&X-Amz-Signature=" + "a" * 64,
    "credit_card": "4111 1111 1111 1111",
    "iban": "DE89 3704 0044 0532 0130 00",
    "ssn": "123-45-6789",
    "us_phone": "(415) 555-0132",
    "email": "jordan.lee@" + "partner.example",
    "ipv4": "203.0.113.42",
    "private_ip": "10.0.0.12",
    "metadata_ip": "169.254.169.254",
}
assert _luhn_ok(FIXTURES["credit_card"].replace(" ", ""))


def expand(value: Any) -> Any:
    if isinstance(value, str):
        for name, fixture in FIXTURES.items():
            value = value.replace("{{" + name + "}}", fixture)
        return value
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


@dataclass
class Outcome:
    detector: str
    factory: str
    name: str
    expect: str
    got: str
    ok: bool
    detail: str = ""


def _event(spec: Dict[str, Any]) -> SensorEvent:
    spec = expand(spec)
    return SensorEvent(action=spec["action"], args=spec.get("args", {}), phase=spec.get("phase", "call"),
                       principal=spec.get("principal"), span_id=spec.get("span_id"),
                       parent_principal=spec.get("parent_principal"), call_id=spec.get("call_id"))


def run_entry(entry: Dict[str, Any]) -> List[Outcome]:
    module = importlib.import_module("interlock.detectors." + entry["detector"])
    factory = getattr(module, entry["factory"])
    rule = factory(**copy.deepcopy(expand(entry.get("kwargs", {}))))
    engine = PolicyEngine([rule])
    out: List[Outcome] = []
    for case in entry["cases"]:
        try:
            decision = engine.evaluate(_event(case["event"]))
            got = decision.verdict.name
        except Exception as exc:  # a detector that raises is a finding, not a crash
            out.append(Outcome(entry["detector"], entry["factory"], case["name"], case["expect"],
                               "RAISED", False, type(exc).__name__))
            continue
        ok = got == case["expect"]
        detail = ""
        if ok and got == "MODIFY":
            text = json.dumps([decision.modified_args, decision.modified_result], default=str)
            for s in expand(case.get("rewrite_includes", [])):
                if s not in text:
                    ok, detail = False, "rewrite lacks an expected string"
            for s in expand(case.get("rewrite_excludes", [])):
                if s in text:
                    ok, detail = False, "rewrite still contains a string it should not"
        out.append(Outcome(entry["detector"], entry["factory"], case["name"], case["expect"], got, ok, detail))
    return out


def load(paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for path in paths or sorted(glob.glob(os.path.join(HERE, "detectors", "*.json"))):
        with open(path) as fh:
            for entry in json.load(fh):
                entry["_file"] = os.path.basename(path)
                entries.append(entry)
    return entries


def main(argv: List[str]) -> int:
    failed = 0
    for entry in load(argv or None):
        for o in run_entry(entry):
            failed += not o.ok
            print("{} {}.{} | {} | expect {} got {}{}".format(
                "ok  " if o.ok else "FAIL", o.detector, o.factory, o.name, o.expect, o.got,
                " | " + o.detail if o.detail else ""))
    print("{} failing".format(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
