"""The detector catalog: one implementation of the category table and the
per-module facts (summary, factories, verdicts, scope, configurability),
shared by the console's ``/api/detectors`` routes and by
``scripts/gen_detector_catalog.py``, so the docs page and the console cannot
drift from each other or from the modules under ``interlock/detectors/``.

The catalog never imports anything outside ``interlock.detectors``, and a
module name from a URL is only ever compared against the list of detector
modules already known to :func:`build_catalog` - never imported directly.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
from functools import lru_cache
from typing import Any, Dict, List, Tuple

from .. import detectors as detectors_pkg
from .server import PREFIX_ROUTES, ROUTES

#: (title, one-line description, modules). Order is the order the docs page
#: and the console both list categories in.
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

#: Scoping the action-name scan cannot see: conventions on the arguments, and
#: modules whose factories are scoped differently from one another.
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

MODULE_NAME_RE = re.compile(r"^[a-z0-9_]+$")


def summary(module: Any) -> str:
    """The first sentence of ``module``'s docstring, as the docs page shows it."""
    doc = (module.__doc__ or "").strip().split("\n\n")[0]
    text = " ".join(doc.split())
    text = re.sub(r"^Argument guard:\s*", "", text)
    text = text.replace("``", "`")
    match = re.match(r"(.+?\.)(\s|$)", text)
    if match:
        text = match.group(1)
    if len(text) > 120 and " so " in text:
        text = text.split(" so ", 1)[0] + "."
    if not text:
        return ""
    return text[0].upper() + text[1:]


def _json_default(value: Any) -> Tuple[Any, bool]:
    """The JSON value for a default, and whether it needed ``repr()`` instead."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value, False
    if isinstance(value, (list, tuple)) and all(
        item is None or isinstance(item, (bool, int, float, str)) for item in value
    ):
        return list(value), False
    return repr(value), True


def _param_info(param: "inspect.Parameter") -> Dict[str, Any]:
    annotation = None if param.annotation is inspect.Parameter.empty else param.annotation
    if param.default is inspect.Parameter.empty:
        return {
            "name": param.name,
            "kind": param.kind.name,
            "required": True,
            "default": None,
            "annotation": annotation,
        }
    default, is_repr = _json_default(param.default)
    info: Dict[str, Any] = {
        "name": param.name,
        "kind": param.kind.name,
        "required": False,
        "default": default,
        "annotation": annotation,
    }
    if is_repr:
        info["default_repr"] = True
    return info


def factories(module: Any) -> List[Dict[str, Any]]:
    """One entry per rule factory: a public function returning a ``Rule``."""
    out = []
    for name, fn in inspect.getmembers(module, inspect.isfunction):
        if fn.__module__ != module.__name__ or name.startswith("_"):
            continue
        signature = inspect.signature(fn)
        if "Rule" not in str(signature.return_annotation):
            continue
        out.append(
            {
                "name": name,
                "signature": str(signature),
                "params": [_param_info(p) for p in signature.parameters.values()],
            }
        )
    return out


def verdicts(source: str) -> List[str]:
    """The verdict names (``ALLOW``, ``BLOCK``, ``MODIFY``, ``ESCALATE``) ``source`` can produce."""
    kinds = []
    if re.search(r"Decision\.allow\b", source):
        kinds.append("ALLOW")
    if re.search(r"Decision\.block\b", source):
        kinds.append("BLOCK")
    if re.search(r"Decision\.modify(_result)?\b", source):
        kinds.append("MODIFY")
    if re.search(r"Decision\.escalate\b", source):
        kinds.append("ESCALATE")
    return kinds


def configurable(module: Any) -> bool:
    """True when a factory takes a parameter that overrides its action names."""
    for name, fn in inspect.getmembers(module, inspect.isfunction):
        if fn.__module__ == module.__name__ and not name.startswith("_"):
            if any("action" in p for p in inspect.signature(fn).parameters):
                return True
    return False


def scope(name: str, module: Any, source: str) -> str:
    """The "Scoped to" text the docs page shows for this module."""
    if re.search(r"\.phase\s*=\s*[\"']result[\"']", source):
        return "tool results"
    if name in SCOPE_NOTES:
        return SCOPE_NOTES[name]
    actions = set()
    prefixes: Tuple[str, ...] = ()
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
    if configurable(module):
        shown += ". Configurable"
    return shown


def detector_names() -> List[str]:
    """Every detector module name under ``interlock/detectors/``, sorted."""
    return sorted(
        m.name for m in pkgutil.iter_modules(detectors_pkg.__path__) if not m.name.startswith("_")
    )


def check_categories(modules: List[str]) -> None:
    """Raise when ``CATEGORIES`` and the modules on disk have drifted apart."""
    listed = [m for _, _, mods in CATEGORIES for m in mods]
    missing = sorted(set(modules) - set(listed))
    unknown = sorted(set(listed) - set(modules))
    dupes = sorted({m for m in listed if listed.count(m) > 1})
    if missing or unknown or dupes:
        raise RuntimeError(
            "catalog out of sync with interlock/detectors/:\n"
            "  uncategorised: {}\n  no such module: {}\n  listed twice: {}".format(
                missing or "-", unknown or "-", dupes or "-"
            )
        )


def _build_detector(name: str, category: str) -> Dict[str, Any]:
    module = importlib.import_module("interlock.detectors." + name)
    source = inspect.getsource(module)
    return {
        "module": name,
        "category": category,
        "summary": summary(module),
        "factories": factories(module),
        "verdicts": verdicts(source),
        "scope": scope(name, module, source),
        "configurable": configurable(module),
    }


@lru_cache(maxsize=1)
def build_catalog() -> Dict[str, Any]:
    """The ``/api/detectors`` body. Built once per process and reused."""
    check_categories(detector_names())
    categories = [
        {"name": title, "description": blurb, "modules": list(mods)}
        for title, blurb, mods in CATEGORIES
    ]
    detectors = [
        _build_detector(name, title) for title, _, mods in CATEGORIES for name in mods
    ]
    return {"count": len(detectors), "categories": categories, "detectors": detectors}


def detector_detail(module_name: str) -> Dict[str, Any]:
    """The detector object for ``module_name`` plus its full docstring.

    Raises ``KeyError`` for a name that is not a known detector module.
    """
    for detector in build_catalog()["detectors"]:
        if detector["module"] == module_name:
            module = importlib.import_module("interlock.detectors." + module_name)
            return dict(detector, doc=inspect.getdoc(module) or "")
    raise KeyError(module_name)


def _unknown_detector() -> Tuple[int, dict]:
    return 404, {"error": {"code": "unknown_detector", "message": "no such detector module"}}


def _list_detectors(_handler: Any) -> Tuple[int, dict]:
    return 200, build_catalog()


def _detector_detail_route(handler: Any) -> Tuple[int, dict]:
    name = handler.path_tail
    if not MODULE_NAME_RE.match(name):
        return _unknown_detector()
    try:
        return 200, detector_detail(name)
    except KeyError:
        return _unknown_detector()


ROUTES["/api/detectors"] = {"GET": _list_detectors}
PREFIX_ROUTES["/api/detectors/"] = {"GET": _detector_detail_route}
