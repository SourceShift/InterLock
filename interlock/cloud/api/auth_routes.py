"""Login, session, org and member routes for the cloud plane.

Registration is additive: :func:`register` extends C0's route table, it does
not fork a second framework. Authentication happens before authorization, and
an org-scoped lookup happens after it, so a permitted role probing a foreign
id gets ``404`` while a role absent from the permission table gets ``403``
(FR-054, FR-056).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from functools import partial
from typing import Any, Dict, Iterable, Optional

from ..auth.oidc import AuthError, OIDCClient
from ..auth.rbac import ROLES
from ..db import CloudDependencyMissing
from ..http import (
    ApiError,
    Request,
    Response,
    build_cookie,
    clear_cookie,
    csrf_cookie,
    escape,
    html_response,
    json_response,
    parse_json_body,
    redirect_response,
    session_cookie,
)
from ..store import NotFound, Org, User

OIDC_COOKIE_MAX_AGE = 600
OIDC_CALLBACK_PATH = "/v1/auth/callback"


def _safe_next(value: Optional[str]) -> str:
    """Only a same-origin absolute path is a valid post-login destination."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    # A backslash is treated as a slash by some browsers; refuse it outright.
    # A semicolon would end the cookie value we store this path in.
    if "\\" in value or ";" in value or "\r" in value or "\n" in value:
        return "/"
    return value


def _require_safe_next(value: Optional[str]) -> str:
    """Reject an open-redirect attempt on the login request itself."""
    if value is None or value == "":
        return "/"
    if not value.startswith("/") or value.startswith("//") \
            or "\\" in value or ";" in value \
            or "\r" in value or "\n" in value:
        raise ApiError(422, "invalid_request",
                       "next must be a same-origin path")
    return value


def _hash(value: Dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _audience_contains(claims: Dict[str, Any], client_id: str) -> bool:
    """True when the token's audience names ``client_id`` (or its ``azp``)."""
    audience = claims.get("aud")
    if isinstance(audience, str):
        return audience == client_id
    if isinstance(audience, (list, tuple)):
        return client_id in audience
    return claims.get("azp") == client_id


def _oauth_cookie(name: str, value: str) -> str:
    return build_cookie(name, value, max_age=OIDC_COOKIE_MAX_AGE,
                        path=OIDC_CALLBACK_PATH, http_only=True)


def _clear_oauth_cookies() -> Iterable[str]:
    for name in ("il_oidc_state", "il_oidc_nonce", "il_oidc_verifier",
                 "il_oidc_next"):
        yield clear_cookie(name, path=OIDC_CALLBACK_PATH)


def _resolve_org(app: Any, issuer: str) -> Optional[Org]:
    """Pick the org for an issuer: configured slug first, then SSO mapping.

    A configured slug is not a blank cheque: when that org pins its own
    ``sso_issuer``, the discovered issuer still has to match it exactly.
    """
    slug = app.config.oidc_org_slug
    if slug:
        org = app.store.org_by_slug(slug)
        if org is None:
            return None
        if org.sso_issuer and org.sso_issuer != issuer:
            return None
        return org
    return app.store.org_by_sso_issuer(issuer)


def _audit(app: Any, request: Request, event: str, *,
           target: Optional[str] = None,
           before: Optional[Dict[str, Any]] = None,
           after: Optional[Dict[str, Any]] = None) -> None:
    """Append one admin/role-change row (FR-058); no secrets in the detail."""
    detail: Dict[str, Any] = {"target": target, "ip": request.client_ip}
    if before is not None:
        detail["before_hash"] = _hash(before)
    if after is not None:
        detail["after_hash"] = _hash(after)
    app.store.audit_append(request.org.id, event,
                           actor=request.user.id, detail=detail)


def _json_body(request: Request, allowed: Iterable[str]) -> Dict[str, Any]:
    return parse_json_body(request.body, request.headers, allowed)


def _member_or_404(app: Any, request: Request, member_id: str) -> User:
    user = app.store.user_by_id(request.org.id, member_id)
    if user is None:
        # Cross-org and missing are indistinguishable, by design (FR-056).
        raise ApiError(404, "not_found", "member not found")
    return user


# -- pages --------------------------------------------------------------

async def index_page(app: Any, request: Request) -> Response:
    # Every value that reaches the page goes through ``escape``: these two
    # pages are the only HTML the plane renders, and an unescaped value in
    # one of them would be a cross-site scripting hole.
    title = escape(app.config.public_url or "interlock cloud")
    body = (
        "<!doctype html><title>interlock cloud</title>"
        "<h1>interlock cloud</h1>"
        "<p>{}</p>"
        "<p><a href=\"/login\">Sign in</a></p>"
    ).format(title)
    return html_response(200, body)


async def login_page(app: Any, request: Request) -> Response:
    target = escape(_safe_next(request.query_one("next")))
    body = (
        "<!doctype html><title>Sign in</title>"
        "<h1>Sign in</h1>"
        "<p><a href=\"/v1/auth/login?next={}\">Continue with SSO</a></p>"
    ).format(target)
    return html_response(200, body)


# -- auth ---------------------------------------------------------------

async def login(app: Any, request: Request) -> Response:
    config = app.config
    if not config.oidc_issuer or not config.oidc_client_id:
        raise ApiError(503, "unavailable", "OIDC is not configured")
    target = _require_safe_next(request.query_one("next"))
    client = app.oidc_client()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = OIDCClient.pkce_pair()
    try:
        location = client.authorization_url(state, nonce, challenge)
    except AuthError as exc:
        # The provider is unreachable or misconfigured: say so, do not leak
        # the discovery URL and do not answer 500.
        raise ApiError(exc.status, exc.code, exc.message) from None
    except CloudDependencyMissing as exc:
        raise ApiError(503, "unavailable", str(exc)) from None
    headers = [
        ("set-cookie", _oauth_cookie("il_oidc_state", state)),
        ("set-cookie", _oauth_cookie("il_oidc_nonce", nonce)),
        ("set-cookie", _oauth_cookie("il_oidc_verifier", verifier)),
        ("set-cookie", _oauth_cookie("il_oidc_next", target)),
    ]
    return redirect_response(location, headers)


async def callback(app: Any, request: Request) -> Response:
    code = request.query_one("code")
    state = request.query_one("state")
    if not code or not state:
        raise ApiError(422, "invalid_request", "code and state are required")
    expected_state = request.cookie("il_oidc_state")
    if not expected_state or not hmac.compare_digest(expected_state, state):
        raise ApiError(403, "csrf", "state does not match")
    nonce = request.cookie("il_oidc_nonce") or ""
    verifier = request.cookie("il_oidc_verifier")
    if not verifier:
        raise ApiError(422, "invalid_request", "missing PKCE verifier")

    client = app.oidc_client()
    try:
        claims = client.exchange(code, verifier, nonce=nonce)
    except AuthError as exc:
        raise ApiError(exc.status, exc.code, exc.message) from None
    except CloudDependencyMissing as exc:
        raise ApiError(503, "unavailable", str(exc)) from None

    org = _resolve_org(app, str(claims.get("iss") or ""))
    if org is None:
        raise ApiError(403, "not_provisioned", "issuer is not provisioned")
    if org.sso_client_id and not _audience_contains(claims, org.sso_client_id):
        # The org pins its own client registration. A token minted for
        # another client of the same issuer is not accepted here: the check
        # can only narrow who gets in, never widen it.
        raise ApiError(403, "bad_audience", "audience does not match")

    issuer = str(claims.get("iss") or "")
    subject = str(claims.get("sub") or "")
    email = str(claims.get("email") or "")
    user = app.store.user_by_issuer_subject(org.id, issuer, subject)
    if user is None:
        # JIT is deliberately narrow: a verified org domain and the
        # least-privileged fixed role. It never merges by email alone (FR-048).
        if app.store.verified_domain(org.id, email):
            user = app.store.create_user(org.id, issuer=issuer, subject=subject,
                                         email=email, role="auditor")
        else:
            raise ApiError(403, "not_provisioned",
                           "no account for this identity")
    if user.status != "active":
        raise ApiError(403, "forbidden", "account is disabled")

    raw = app.sessions.login(user, ip=request.client_ip,
                             user_agent=request.header("user-agent") or "")
    session = app.store.session_by_token_hash(
        app.sessions.hash(raw), org_id=org.id
    )
    if session is None:  # pragma: no cover - the row was just written
        raise ApiError(500, "internal_error", "the session could not be stored")
    csrf = app.sessions.csrf_token(session.id)
    headers = [
        ("set-cookie", session_cookie(
            app.sessions.cookie_value(org.id, raw),
            app.config.session_absolute_seconds,
        )),
        ("set-cookie", csrf_cookie(
            csrf, app.config.session_absolute_seconds
        )),
    ]
    headers.extend(("set-cookie", value) for value in _clear_oauth_cookies())
    return redirect_response(_safe_next(request.cookie("il_oidc_next")),
                             headers)


async def logout(app: Any, request: Request) -> Response:
    app.sessions.logout(request.session.org_id, request.session.id)
    headers = [
        ("set-cookie", clear_cookie("__Host-il_session")),
        ("set-cookie", clear_cookie("il_csrf", http_only=False)),
    ]
    return json_response(200, {"status": "logged_out"}, headers)


async def me(app: Any, request: Request) -> Response:
    return json_response(200, {
        "id": request.user.id,
        "email": request.user.email,
        "role": request.user.role,
        "org": request.org.slug,
        "step_up_at": request.session.step_up_at,
    })


# -- org ----------------------------------------------------------------

async def get_org(app: Any, request: Request) -> Response:
    return json_response(200, request.org.public())


async def patch_org(app: Any, request: Request) -> Response:
    body = _json_body(request, ("name", "step_up_policy"))
    if not body:
        raise ApiError(422, "invalid_request", "no fields to update")
    if "step_up_policy" in body and body["step_up_policy"] not in (
            "webauthn", "totp", "either"):
        raise ApiError(422, "invalid_request", "unknown step-up policy")
    before = request.org.public()
    try:
        updated = app.store.update_org(
            request.org.id, name=body.get("name"),
            step_up_policy=body.get("step_up_policy"),
        )
    except NotFound:
        raise ApiError(404, "not_found", "org not found") from None
    _audit(app, request, "org.updated", target=updated.id,
           before=before, after=updated.public())
    return json_response(200, updated.public())


# -- members ------------------------------------------------------------

async def list_members(app: Any, request: Request) -> Response:
    users = app.store.list_users(request.org.id)
    return json_response(200, {"members": [user.public() for user in users]})


async def invite_member(app: Any, request: Request) -> Response:
    body = _json_body(request, ("email", "role"))
    email = str(body.get("email") or "").strip()
    role = str(body.get("role") or "auditor")
    if "@" not in email:
        raise ApiError(422, "invalid_request", "a valid email is required")
    if role not in ROLES:
        raise ApiError(422, "invalid_request", "unknown role")
    try:
        user = app.store.create_user(
            request.org.id, issuer="pending",
            subject="invite:{}".format(secrets.token_hex(8)),
            email=email, role=role, status="invited",
        )
    except ValueError as exc:
        raise ApiError(422, "invalid_request", str(exc)) from None
    _audit(app, request, "member.invited", target=user.id, after=user.public())
    return json_response(201, {"member": user.public()})


async def patch_member(app: Any, request: Request) -> Response:
    member_id = (request.params or {}).get("id", "")
    user = _member_or_404(app, request, member_id)
    body = _json_body(request, ("role", "status"))
    if not body:
        raise ApiError(422, "invalid_request", "no fields to update")
    if "role" in body and body["role"] not in ROLES:
        raise ApiError(422, "invalid_request", "unknown role")
    if "status" in body and body["status"] not in (
            "active", "invited", "disabled"):
        raise ApiError(422, "invalid_request", "unknown status")

    before = user.public()
    updated = user
    if "role" in body:
        updated = app.store.set_user_role(request.org.id, member_id,
                                          str(body["role"]))
    if "status" in body:
        updated = app.store.set_user_status(request.org.id, member_id,
                                            str(body["status"]))
        if updated.status == "disabled":
            app.sessions.disable_user(request.org.id, member_id)
    _audit(app, request, "member.updated", target=member_id,
           before=before, after=updated.public())
    return json_response(200, {"member": updated.public()})


async def delete_member(app: Any, request: Request) -> Response:
    member_id = (request.params or {}).get("id", "")
    user = _member_or_404(app, request, member_id)
    before = user.public()
    app.sessions.disable_user(request.org.id, member_id)
    app.store.delete_user(request.org.id, member_id)
    _audit(app, request, "member.deleted", target=member_id, before=before)
    return json_response(200, {"deleted": True})


def register(app: Any) -> None:
    """Add the C1 routes to a :class:`~interlock.cloud.app.CloudApp`."""
    app.add_route("/", "GET", partial(index_page, app))
    app.add_route("/login", "GET", partial(login_page, app))
    app.add_route("/v1/auth/login", "GET", partial(login, app))
    app.add_route(OIDC_CALLBACK_PATH, "GET", partial(callback, app))
    app.add_route("/v1/auth/logout", "POST", partial(logout, app))
    app.add_route("/v1/me", "GET", partial(me, app))
    app.add_route("/v1/org", "GET", partial(get_org, app))
    app.add_route("/v1/org", "PATCH", partial(patch_org, app))
    app.add_route("/v1/members", "GET", partial(list_members, app))
    app.add_route("/v1/members/invite", "POST", partial(invite_member, app))
    app.add_pattern("/v1/members/{id}", "PATCH", partial(patch_member, app))
    app.add_pattern("/v1/members/{id}", "DELETE", partial(delete_member, app))


__all__ = ["register"]
