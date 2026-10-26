"""Deny-by-default route authorization (FR-054).

One table is the whole model. A route missing from it is refused, so adding a
route means deliberately adding a permission row. The table is keyed by
``(method, route)`` where a route may contain ``{name}`` placeholders; a
concrete path is normalised before lookup.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Pattern, Set, Tuple

#: The fixed human role model. ``agent`` is deliberately absent: agent keys do
#: not use this table at all. They are authenticated by
#: :mod:`interlock.cloud.auth.agent` and authorized against
#: :data:`AGENT_ROUTES`, so ``authorize("agent", ...)`` stays forbidden for
#: every human route.
ROLES = ("owner", "admin", "reviewer", "auditor")

ALL_ROLES = frozenset(("owner", "admin", "reviewer", "auditor"))

#: Routes every authenticated human may use. They are not org-admin actions.
AUTHENTICATED_ROUTES = frozenset({
    ("GET", "/v1/me"),
    ("POST", "/v1/auth/logout"),
})

#: Routes that need no session at all. ``/v1/enroll`` is here because its
#: handler authenticates the single-use enrollment token in the request body;
#: it must not be reachable with a session cookie *or* a CSRF token, and no
#: other route may be added here.
PUBLIC_ROUTES = frozenset({
    ("GET", "/"),
    ("GET", "/login"),
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("GET", "/v1/auth/login"),
    ("GET", "/v1/auth/callback"),
    ("POST", "/v1/enroll"),
    # The mobile review UI's one asset. It contains no tenant data and is
    # safe to serve before login; the pages that load it are not public.
    ("GET", "/static/stepup.js"),
})

#: (method, route) -> roles allowed. A route absent here is denied.
#: These are human routes only; agent routes live in :data:`AGENT_ROUTES`.
PERMISSIONS: Dict[Tuple[str, str], Set[str]] = {
    ("GET", "/v1/org"): {"owner", "admin", "reviewer", "auditor"},
    ("PATCH", "/v1/org"): {"owner"},
    ("GET", "/v1/members"): {"owner", "admin", "auditor"},
    ("POST", "/v1/members/invite"): {"owner", "admin"},
    ("PATCH", "/v1/members/{id}"): {"owner", "admin"},
    ("DELETE", "/v1/members/{id}"): {"owner", "admin"},
    # C2: enrollment and the host fleet are administrative surfaces.
    ("POST", "/v1/admin/enrollment-tokens"): {"owner", "admin"},
    ("GET", "/v1/hosts"): {"owner", "admin"},
    ("GET", "/v1/hosts/{id}"): {"owner", "admin"},
    ("POST", "/v1/keys"): {"owner", "admin"},
    ("POST", "/v1/keys/{id}/revoke"): {"owner", "admin"},
    # C3: reviewers (and their admins) see and decide reviews. Auditors may
    # not list reviews; on detail they are routed to a deliberate 404 so a
    # probe cannot tell a real id from a missing one (they may search
    # receipts, never read a preview).
    ("GET", "/v1/reviews"): {"owner", "admin", "reviewer"},
    ("GET", "/v1/reviews/{id}"): {"owner", "admin", "reviewer", "auditor"},
    ("POST", "/v1/reviews/{id}/decision"): {"owner", "admin", "reviewer"},
    # The same capability as the two server-rendered, mobile-first pages.
    ("GET", "/reviews"): {"owner", "admin", "reviewer"},
    ("GET", "/reviews/{id}"): {"owner", "admin", "reviewer", "auditor"},
    ("POST", "/reviews/{id}/decision"): {"owner", "admin", "reviewer"},
    ("POST", "/reviews/{id}/step-up"): {"owner", "admin", "reviewer"},
    # C4: auditors (and admins) search receipts and export a verified chain.
    # Auditors may never read a preview or raw arguments; the route has no
    # field that could carry them.
    ("GET", "/v1/audit"): {"owner", "admin", "auditor"},
    ("GET", "/v1/audit/export"): {"owner", "admin", "auditor"},
    # Retention is an owner action: it deletes tenant data and runs audited.
    ("POST", "/v1/admin/retention/run"): {"owner"},
    # Unfreezing receipt ingest after a fork is a deliberate, audited
    # administrator action with a required reason.
    ("POST", "/v1/hosts/{id}/unfreeze"): {"owner", "admin"},
    # C5: compiling and publishing policy are administrative actions. A kill
    # switch is an owner action; promot/rollback is administrative. Auditors
    # may list rollouts but cannot change distribution.
    ("POST", "/v1/policy/compile"): {"owner", "admin"},
    ("POST", "/v1/policy/publish"): {"owner", "admin"},
    ("POST", "/v1/policy/kill"): {"owner"},
    ("POST", "/v1/policy/rollouts/{id}/promote"): {"owner", "admin"},
    ("GET", "/v1/policy/rollouts"): {"owner", "admin", "auditor"},
}

#: (method, literal route) -> required agent scope, or ``None`` when any
#: authenticated key may call it. These routes are matched exactly before
#: ``normalize_route``: ``/v1/hosts/self`` must not be mistaken for the human
#: ``/v1/hosts/{id}`` route.
AGENT_ROUTES: Dict[Tuple[str, str], Optional[str]] = {
    ("POST", "/v1/hosts/self"): None,
    # C3 connector surface. Reviews are uploaded, grants are polled and acked;
    # every one is scoped to the authenticated key's host.
    ("POST", "/v1/reviews"): None,
    ("GET", "/v1/grants"): None,
    ("POST", "/v1/grants/ack"): None,
    # C4 connector surface. The key must carry the ingest scope; both routes
    # are scoped to the authenticated key's host, never a body-supplied one.
    ("POST", "/v1/receipts"): "ingest:receipts",
    ("POST", "/v1/checkpoints"): "ingest:receipts",
    # C5 connector surface. The key must carry the policy-pull scope; every
    # route is scoped to the authenticated key's host and org, never a
    # body-supplied identity.
    ("GET", "/v1/hints"): "pull:policy",
    ("GET", "/v1/manifest"): "pull:policy",
    ("GET", "/v1/kills"): "pull:policy",
    # Variable route: the artifact is addressed by hash, and a host may only
    # fetch bytes the plane stored for its own org.
    ("GET", "/v1/artifacts/{sha256}"): "pull:policy",
}


class Forbidden(Exception):
    """The caller's role is not in the route's permission row."""

    def __init__(self, message: str = "forbidden") -> None:
        super().__init__(message)
        self.code = "forbidden"


def _compile(route: str) -> Pattern[str]:
    pattern = "^" + re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", r"[^/]+", route) + "$"
    return re.compile(pattern)


_VAR_ROUTES: List[Tuple[Pattern[str], str]] = sorted(
    ((_compile(route), route) for _method, route in PERMISSIONS
     if "{" in route),
    key=lambda item: -len(item[1]),
)


#: Literal routes in the table (no parameters). They must win over a variable
#: pattern: ``/v1/members/invite`` is not ``/v1/members/{id}``.
_EXACT_ROUTES = frozenset(
    route for _method, route in PERMISSIONS if "{" not in route
)


def normalize_route(path: str) -> str:
    """Map a concrete path onto its table entry when it has parameters."""
    clean = path.split("?", 1)[0]
    if clean in _EXACT_ROUTES:
        return clean
    for pattern, route in _VAR_ROUTES:
        if pattern.match(clean):
            return route
    return clean


def is_public(method: str, path: str) -> bool:
    return (method.upper(), normalize_route(path)) in PUBLIC_ROUTES


def is_authenticated_route(method: str, path: str) -> bool:
    return (method.upper(), normalize_route(path)) in AUTHENTICATED_ROUTES


_AGENT_VAR_ROUTES: List[Tuple[Pattern[str], Tuple[str, str]]] = sorted(
    ((_compile(route), (method, route))
     for method, route in AGENT_ROUTES if "{" in route),
    key=lambda item: -len(item[1][1]),
)


def agent_route(method: str, path: str) -> Optional[Tuple[str, str]]:
    """The ``AGENT_ROUTES`` key for an agent route, else ``None``.

    Literal entries are matched verbatim, before variable human routes are
    normalised, so ``/v1/hosts/self`` is never folded onto
    ``/v1/hosts/{id}``. A parameterised agent route (the artifact-by-hash
    fetch) is matched only against the agent table - it can never widen a
    human permission row.
    """
    clean = path.split("?", 1)[0]
    key = (method.upper(), clean)
    if key in AGENT_ROUTES:
        return key
    for pattern, route_key in _AGENT_VAR_ROUTES:
        if route_key[0] == method.upper() and pattern.match(clean):
            return route_key
    return None


def required_agent_scope(method: str, path: str) -> Optional[str]:
    key = agent_route(method, path)
    return AGENT_ROUTES[key] if key is not None else None


def allowed_roles(method: str, path: str) -> Optional[Set[str]]:
    """The roles permitted for a route, or ``None`` when it is unlisted."""
    key = (method.upper(), normalize_route(path))
    if key in AUTHENTICATED_ROUTES:
        return set(ALL_ROLES)
    return PERMISSIONS.get(key)


def authorize(role: str, method: str, path: str) -> None:
    """Return ``None`` when allowed, else raise :class:`Forbidden`.

    Deny by default is the point: a route that has not been added to the
    table cannot be reached by any role.
    """
    if (method.upper(), normalize_route(path)) in PUBLIC_ROUTES:
        return
    roles = allowed_roles(method, path)
    if roles is None or role not in roles:
        raise Forbidden("role {!r} may not {} {}".format(role, method, path))


def permissions_for(role: str) -> List[Tuple[str, str]]:
    """The table rows a role may use, useful for the RBAC matrix test."""
    return sorted(
        (method, route)
        for (method, route), roles in PERMISSIONS.items()
        if role in roles
    )


def all_routes() -> Iterable[Tuple[str, str]]:
    return sorted(PERMISSIONS)


__all__ = [
    "AGENT_ROUTES",
    "ALL_ROLES",
    "AUTHENTICATED_ROUTES",
    "Forbidden",
    "PERMISSIONS",
    "PUBLIC_ROUTES",
    "ROLES",
    "agent_route",
    "allowed_roles",
    "authorize",
    "is_authenticated_route",
    "is_public",
    "normalize_route",
    "permissions_for",
    "required_agent_scope",
]
