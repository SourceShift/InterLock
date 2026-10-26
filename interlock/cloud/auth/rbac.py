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
}

#: (method, literal route) -> required agent scope, or ``None`` when any
#: authenticated key may call it. These routes are matched exactly before
#: ``normalize_route``: ``/v1/hosts/self`` must not be mistaken for the human
#: ``/v1/hosts/{id}`` route.
AGENT_ROUTES: Dict[Tuple[str, str], Optional[str]] = {
    ("POST", "/v1/hosts/self"): None,
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


def agent_route(method: str, path: str) -> Optional[Tuple[str, str]]:
    """The ``AGENT_ROUTES`` key for an exact agent route, else ``None``.

    Agent routes are matched verbatim, before variable human routes are
    normalised, so ``/v1/hosts/self`` is never folded onto
    ``/v1/hosts/{id}``.
    """
    key = (method.upper(), path.split("?", 1)[0])
    return key if key in AGENT_ROUTES else None


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
