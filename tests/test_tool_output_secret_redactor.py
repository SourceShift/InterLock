"""tool_output_secret_redactor on real-world shapes: what it must mask, what it
must leave alone, and the counts it reports for the receipt.

The false positives here come from real Claude Code transcripts: a Read of a
TypeScript file whose interface declared ``link_token: string;`` came back
with the type masked as a secret. Credential-shaped fixtures are built at run
time so no literal key sits in the repository.
"""
import pytest

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.tool_output_secret_redactor import redact_text, tool_output_secret_redactor

GITHUB_TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 3 + "F6g7H8"
AWS_LINE = "export AWS_SECRET_ACCESS_KEY=" + "wJalrXUtn" + "FEMIK7MDENG"


def _result(text):
    return SensorEvent(action="Read", args={"result": text}, phase="result")


@pytest.mark.parametrize("line", [
    "  link_token: string;",
    "  api_token?: string | null;",
    "PASSWORD_RESET_TTL: number;",
    "API_KEY = os.environ['API_KEY']",
    "SECRET_KEY = settings.secret",
    "token: ${GITHUB_TOKEN}",
    "const AUTH_TOKEN = getToken();",
])
def test_types_and_references_are_not_secrets(line):
    redacted, kinds = redact_text(line)
    assert redacted == line and kinds == []


@pytest.mark.parametrize("line", [
    "API_TOKEN=abc123xyz789",
    AWS_LINE,
    "db_password: hunter2hunter2",
    "  api_token: 'abcdef123456'",
])
def test_secret_assignments_are_still_masked(line):
    redacted, kinds = redact_text(line)
    # A more specific pattern (AWS_SECRET, ...) may claim it first; masked either way.
    assert "[REDACTED " in redacted and len(kinds) == 1


def test_the_rewrite_reports_how_many_of_each_kind_it_masked():
    text = "API_SECRET=abcdefgh\nX_TOKEN=zzzzzzzz\n" + GITHUB_TOKEN
    decision = PolicyEngine([tool_output_secret_redactor()]).evaluate(_result(text))
    assert decision.verdict is Verdict.MODIFY
    assert decision.masked == {"SECRET": 2, "GITHUB_TOKEN": 1}
    assert GITHUB_TOKEN not in str(decision.modified_result)


def test_a_typescript_interface_passes_untouched():
    source = "interface BriefLinkRow {\n  link_token: string;\n  client_uuid: string;\n}\n"
    assert PolicyEngine([tool_output_secret_redactor()]).evaluate(_result(source)).verdict is Verdict.ALLOW
