"""Regenerate docs/reference/detectors.md from the detector modules themselves.

The catalog is generated rather than hand-written so it cannot drift from the
code: every row comes from a module's docstring summary, its rule factories'
signatures, the verdicts it can return, and the action names it is scoped to.

    python scripts/gen_detector_catalog.py          # rewrite the page
    python scripts/gen_detector_catalog.py --check  # exit 1 if the page is stale

A new detector module must be added to one CATEGORIES entry below; the script
refuses to run while any module is uncategorised.
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import pkgutil
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import interlock.detectors as detectors_pkg  # noqa: E402

OUT = ROOT / "docs" / "reference" / "detectors.md"

# Source links go to the repository, not to a relative path. The catalog is
# published as a docs site (interlock.sourceshift.ai) as well as read on GitHub,
# and a relative ../../interlock/... link 404s once the page is built. An
# absolute blob URL is correct in both places.
BLOB = "https://github.com/SourceShift/InterLock/blob/main"

# (title, one-line description, modules). Order is the order on the page.
CATEGORIES: List[Tuple[str, str, List[str]]] = [
    (
        "Prompt injection and jailbreaks",
        "Hostile instructions in user input, retrieved documents, tool output, or agent memory.",
        [
            "prompt_injection", "jailbreak", "dan_persona_guard", "crescendo_guard",
            "many_shot_jailbreak_guard", "leetspeak_jailbreak_guard",
            "hypothetical_framing_guard", "social_engineering_framing_guard",
            "refusal_suppression_guard", "goal_hijack_guard", "system_prompt_extraction",
            "indirect_injection_marker", "translation_evasion_guard", "delimiter_smuggling",
            "homoglyph_injection", "unicode_tag_injection", "html_comment_injection_guard",
            "markdown_link_injection_guard", "payload_splitting_guard",
            "base64_payload_scan", "canary_leak_guard", "pinned_context_guard",
            "memory_write_injection_guard", "tool_output_override_guard",
            "tool_result_injection_guard", "rag_source_allowlist",
            "mcp_prompt_arg_injection",
        ],
    ),
    (
        "Classic injection in arguments",
        "Web-era vulnerabilities that ride in a tool argument the model filled in.",
        [
            "sql_injection_guard", "nosql_injection_guard", "shell_injection_guard",
            "ldap_injection_guard", "xxe_guard", "ssti_guard", "path_traversal_guard",
            "prototype_pollution_guard", "open_redirect_guard",
            "crlf_header_injection_guard", "script_tag_output_guard",
            "ansi_escape_output_guard", "url_scheme_guard", "mass_assignment_guard",
            "pickle_deser_guard", "download_extension_guard",
        ],
    ),
    (
        "Secrets and personal data",
        "Mask credentials and PII out of outbound payloads (most rewrite rather than block).",
        [
            "bearer_token_redactor", "basic_auth_url_redactor", "aws_arn_redactor",
            "github_pat_redactor", "google_api_key_redactor", "jwt_redactor",
            "pem_private_key_redactor", "db_uri_redactor", "stripe_key_redactor",
            "slack_webhook_redactor", "s3_presigned_redactor", "output_secret_redactor",
            "secret_entropy_egress_guard", "env_secret_read_guard",
            "git_credential_guard", "tool_output_secret_redactor", "data_masking_guard",
            "pii_argument_guard", "email_pii_redactor",
            "output_email_redactor",
            "iban_redactor", "ssn_redactor", "us_phone_redactor", "ipv4_redactor",
        ],
    ),
    (
        "Data leaving the system",
        "Where data may go and how much of it, before it leaves the process.",
        [
            "data_egress", "egress_rate_limiter", "private_ip_egress_guard",
            "raw_ip_egress_guard", "data_volume_egress_guard", "http_request_guard",
            "http_status_guard",
            "markdown_image_exfil_guard", "host_fanout_guard",
        ],
    ),
    (
        "Code execution and host access",
        "Commands and submitted code that would reach the shell, filesystem, or network.",
        [
            "execution_guard", "code_eval_exec_guard", "code_dunder_escape_guard",
            "code_filesystem_guard", "code_network_guard", "dynamic_import_guard",
            "subprocess_spawn_guard", "destructive_command_guard", "command_intent_guard",
            "sql_statement_guard", "runbook_guard",
            "sensitive_file_write_guard", "signal_kill_guard", "memory_bomb_guard",
        ],
    ),
    (
        "MCP servers and tools",
        "Which servers an agent may connect to, and whether their tools changed since review.",
        [
            "mcp_server_allowlist", "mcp_transport_guard", "mcp_tool_pinning",
            "mcp_tool_description_scan",
            "mcp_trust_registry", "mcp_resource_uri_guard", "mcp_sampling_model_guard",
            "mcp_consent_budget", "mcp_capability_lease", "mcp_server_attestation",
            "mcp_elicitation_guard",
            "mcp_surface_baseline",
        ],
    ),
    (
        "Agent-to-agent (A2A)",
        "Which peers an agent may reach, and whether their advertised agent cards changed.",
        [
            "a2a_policy",
        ],
    ),
    (
        "Budgets, rate limits, and loops",
        "Stop runaway agents: too many calls, too much spend, the same call on repeat.",
        [
            "call_rate_limiter", "cost_budget_guard", "tool_budget_limiter", "result_size_guard",
            "write_action_limiter", "duplicate_call_loop_guard", "output_length_guard",
            "memory_write_size_guard", "failed_auth_lockout", "token_budget_guard",
        ],
    ),
    (
        "Provenance stamps",
        "Rewrite events to carry integrity and ordering metadata for downstream storage.",
        [
            "event_hmac_stamp", "content_digest_stamp", "sequence_number_stamp",
            "provenance_origin_tag",
        ],
    ),
    (
        "Tool allow and deny lists",
        "Least privilege by tool name.",
        ["tool_policy"],
    ),
]

# Scoping the action-name scan cannot see: conventions on the arguments, and
# modules whose factories are scoped differently from one another.
SCOPE_NOTES: Dict[str, str] = {
    "data_egress": "egress verbs (`http_post`, `fetch`, `send_email`, +16 more); "
                   "`sensitive_path_guard`: read verbs (`read_file`, `cat`, `open`, +8 more). "
                   "Configurable",
    "mcp_tool_pinning": "calls to the tools you pinned; reads `args[\"__schema__\"]` "
                        "and blocks when it is missing",
    "mcp_trust_registry": "every call; origin from `args[\"__origin__\"]` or a dotted "
                          "name (`github.create_issue`). An unknown origin is blocked. "
                          "Unlabelled MCP protocol events are skipped",
    "mcp_server_attestation": "events from the servers you listed (`__origin__` or "
                              "dotted name); reads `__attestation__` and `__tools__`",
    "mcp_capability_lease": "calls whose server is known (`__origin__` or dotted name); "
                            "a lease covers one server and tool name; `tools/list` and "
                            "unlabelled MCP protocol events are ignored",
    "mcp_surface_baseline": "`tools/list` events labelled with `__origin__`; "
                            "reads `__tools__`",
    "mcp_consent_budget": "any call, counted per tool name. Wrap it so it only sees "
                          "your high-risk tools",
    "cost_budget_guard": "calls with a numeric `args[\"cost\"]`",
    "call_rate_limiter": "any call, counted per principal",
    "token_budget_guard": "any call, estimated tokens counted per principal over a "
                          "rolling `window_s`",
    "tool_budget_limiter": "any call, counted per tool name",
    "runbook_guard": "calls carrying `command`/`cmd` (or the `keys` you name); "
                     "everything else in those arguments must match a runbook",
    "http_request_guard": "calls with a `url`/`endpoint`/`uri` argument (or the `actions` "
                          "you name)",
    "mcp_elicitation_guard": "`mcp.elicitation` / `elicitation/create` events",
    "duplicate_call_loop_guard": "any call, identical repeats in a row",
    "command_intent_guard": "any call (or the `actions` you name); parses every str "
                            "argument (or the `keys` you name) as a shell command",
    "sql_statement_guard": "any call (or the `actions` you name); parses SQL-named "
                           "arguments (`sql`, `query`, `statement`, ...; or the `keys` you name)",
}

SHOWN_ACTIONS = 8


def _summary(module) -> str:
    doc = (module.__doc__ or "").strip().split("\n\n")[0]
    text = " ".join(doc.split())
    text = re.sub(r"^Argument guard:\s*", "", text)
    text = text.replace("``", "`")
    match = re.match(r"(.+?\.)(\s|$)", text)
    if match:
        text = match.group(1)
    if len(text) > 120 and " so " in text:
        text = text.split(" so ", 1)[0] + "."
    return text[0].upper() + text[1:]


def _factories(module) -> List[str]:
    out = []
    for name, fn in inspect.getmembers(module, inspect.isfunction):
        if fn.__module__ != module.__name__ or name.startswith("_"):
            continue
        if "Rule" not in str(inspect.signature(fn).return_annotation):
            continue
        params = []
        for p in inspect.signature(fn).parameters.values():
            if p.kind is p.VAR_KEYWORD:
                params.append("**" + p.name)
            elif p.default is p.empty:
                params.append(p.name)
            else:
                params.append(p.name + "=…")
        out.append("`{}({})`".format(name, ", ".join(params)))
    return out


def _verdicts(source: str) -> str:
    kinds = []
    if re.search(r"Decision\.block\b", source):
        kinds.append("block")
    if re.search(r"Decision\.modify(_result)?\b", source):
        kinds.append("rewrite")
    if re.search(r"Decision\.escalate\b", source):
        kinds.append("ask")
    return ", ".join(kinds) or "–"


def _scope(name: str, module, source: str) -> str:
    if re.search(r"\.phase\s*=\s*[\"']result[\"']", source):
        return "tool results"
    if name in SCOPE_NOTES:
        return SCOPE_NOTES[name]
    actions = set()
    prefixes = ()
    for key, value in vars(module).items():
        key = key.lstrip("_")
        if not key.isupper():
            continue
        # Whole-word ACTION(S): "REDACTION" must not match.
        if re.search(r"(^|_)ACTIONS?($|_)", key):
            if isinstance(value, str):
                actions.add(value)
            elif isinstance(value, (frozenset, set, tuple, list)):
                actions.update(v for v in value if isinstance(v, str))
        elif key == "MUTATING_PREFIXES":
            prefixes = tuple(value)
    if prefixes:
        return "actions starting with " + ", ".join("`{}`".format(p) for p in prefixes)
    if not actions:
        return "any call"
    names = sorted(actions)
    shown = ", ".join("`{}`".format(a) for a in names[:SHOWN_ACTIONS])
    if len(names) > SHOWN_ACTIONS:
        shown += ", +{} more".format(len(names) - SHOWN_ACTIONS)
    if _configurable(module):
        shown += ". Configurable"
    return shown


def _configurable(module) -> bool:
    """True when a factory takes a parameter that overrides its action names."""
    for name, fn in inspect.getmembers(module, inspect.isfunction):
        if fn.__module__ == module.__name__ and not name.startswith("_"):
            if any("action" in p for p in inspect.signature(fn).parameters):
                return True
    return False


def render() -> str:
    modules = sorted(m.name for m in pkgutil.iter_modules(detectors_pkg.__path__))
    listed = [m for _, _, mods in CATEGORIES for m in mods]
    missing = sorted(set(modules) - set(listed))
    unknown = sorted(set(listed) - set(modules))
    dupes = sorted({m for m in listed if listed.count(m) > 1})
    if missing or unknown or dupes:
        sys.exit(
            "catalog out of sync with interlock/detectors/:\n"
            "  uncategorised: {}\n  no such module: {}\n  listed twice: {}".format(
                missing or "-", unknown or "-", dupes or "-"
            )
        )

    lines = [
        "# Detector catalog",
        "",
        "<!-- Generated by scripts/gen_detector_catalog.py. Do not edit by hand. -->",
        "",
        "interlock ships {} detectors. Each one is a small, dependency-free rule for a"
        .format(len(modules)),
        "single kind of attack. Nothing is enabled until you install it. To learn how to",
        "choose and combine them, read the [detectors guide](../guides/detectors.md).",
        "",
        "How to read the table:",
        "",
        "- **Factory** is what you call to build the rule, e.g.",
        "  `from interlock.detectors.sql_injection_guard import sql_injection_guard`.",
        "  `=…` marks an optional parameter.",
        "- **Verdict** is what the rule returns on a match: *block* stops the call,",
        "  *rewrite* lets it continue with the matched text masked or the event stamped,",
        "  *ask* pauses it for a human approver (an ESCALATE; blocked when there is none).",
        "- **Scoped to** is which events the rule looks at. A detector scoped to named",
        "  actions **does nothing for a tool with a different name**, so check this",
        "  column before you rely on one. \"any call\" means every call-phase event.",
        "",
        "## Categories",
        "",
    ]
    for title, blurb, mods in CATEGORIES:
        anchor = re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")
        lines.append("- [{}](#{}) ({}): {}".format(title, anchor, len(mods), blurb))
    lines.append("")

    for title, blurb, mods in CATEGORIES:
        lines += ["## " + title, "", blurb, "",
                  "| Detector | What it catches | Verdict | Scoped to | Factory |",
                  "|---|---|---|---|---|"]
        for name in mods:
            module = importlib.import_module("interlock.detectors." + name)
            source = inspect.getsource(module)
            link = "[`{0}`]({1}/interlock/detectors/{0}.py)".format(name, BLOB)
            row = [link, _summary(module), _verdicts(source),
                   _scope(name, module, source), "<br>".join(_factories(module))]
            lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate docs/reference/detectors.md from the detector modules."
    )
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if the page differs from what would be generated")
    opts = parser.parse_args()
    text = render()
    if opts.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("{} is stale; run scripts/gen_detector_catalog.py".format(OUT.relative_to(ROOT)))
            return 1
        print("{} is up to date".format(OUT.relative_to(ROOT)))
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print("wrote {}".format(OUT.relative_to(ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
