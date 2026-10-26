"""OIDC authorization-code login with PKCE (FR-047, FR-048).

The claim rules live here, not in the signature verifier, so the whole matrix
is testable with a fake ``Verifier`` and no crypto. The default verifier uses
``cryptography`` (RS256/ES256) and is imported lazily; a missing dependency
raises :class:`~interlock.cloud.db.CloudDependencyMissing`.

Access and refresh tokens never leave :meth:`OIDCClient.exchange`: only the
validated ID-token claims are returned, and they are never logged.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlencode
from urllib.request import Request as UrllibRequest, urlopen

from ..db import CloudDependencyMissing, INSTALL_HINT

DISCOVERY_TTL = 600
HTTP_TIMEOUT = 10
CLOCK_SKEW = 60


class AuthError(Exception):
    """A claim or protocol check failed; ``code`` is safe to return."""

    def __init__(self, code: str, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _contains(audience: Any, client_id: str) -> bool:
    if isinstance(audience, str):
        return audience == client_id
    if isinstance(audience, (list, tuple)):
        return client_id in audience
    return False


def _default_http(method: str, url: str, data: Optional[bytes] = None,
                  headers: Optional[Mapping[str, str]] = None,
                  timeout: int = HTTP_TIMEOUT) -> Tuple[int, Dict[str, str], bytes]:
    """The stdlib transport used when no seam is injected."""
    request = UrllibRequest(url, data=data, method=method,
                            headers=dict(headers or {}))
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            return (int(response.status), dict(response.headers),
                    response.read())
    except Exception as exc:
        # Network errors are auth failures from the caller's point of view;
        # never include the URL (it may carry query parameters).
        raise AuthError("invalid_request",
                        "identity provider is unreachable") from exc


class JwtVerifier:
    """The default verifier: compact JWT signature check against a JWKS."""

    def __init__(self, jwks_uri: str, *, http: Any = None,
                 clock: Any = time.time) -> None:
        self.jwks_uri = jwks_uri
        self.http = http or _default_http
        self.clock = clock
        self._keys: Dict[str, Any] = {}
        self._keys_at = 0.0

    def verify(self, token: str, *, issuer: Optional[str] = None,
               audience: Optional[str] = None, nonce: Optional[str] = None,
               now: Optional[float] = None) -> Mapping[str, Any]:
        header, payload = self._split(token)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthError("bad_issuer", "token header has no key id")
        alg = str(header.get("alg") or "")
        key = self._key(kid)
        self._verify_signature(alg, key, token)
        return payload

    @staticmethod
    def _split(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthError("bad_issuer", "malformed identity token")
        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except (ValueError, UnicodeDecodeError):
            raise AuthError("bad_issuer", "malformed identity token") from None
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise AuthError("bad_issuer", "malformed identity token")
        return header, payload

    def _key(self, kid: str) -> Dict[str, Any]:
        now = self.clock()
        if not self._keys or now - self._keys_at >= DISCOVERY_TTL:
            status, _headers, body = self.http("GET", self.jwks_uri, None, None)
            if status != 200:
                raise AuthError("bad_issuer", "signing keys are unavailable")
            try:
                document = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise AuthError("bad_issuer", "malformed signing keys") from None
            keys = {}
            for item in document.get("keys", []):
                if isinstance(item, dict) and item.get("kid"):
                    keys[str(item["kid"])] = item
            self._keys = keys
            self._keys_at = now
        key = self._keys.get(kid)
        if key is None:
            raise AuthError("bad_issuer", "unknown signing key")
        return key

    @staticmethod
    def _verify_signature(alg: str, jwk: Mapping[str, Any], token: str) -> None:
        """Verify RS256/ES256 with ``cryptography``, imported lazily."""
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        except ImportError:
            raise CloudDependencyMissing(INSTALL_HINT) from None

        parts = token.split(".")
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        signature = _b64url_decode(parts[2])

        if alg == "RS256":
            n = int.from_bytes(_b64url_decode(str(jwk["n"])), "big")
            e = int.from_bytes(_b64url_decode(str(jwk["e"])), "big")
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            try:
                public_key.verify(signature, signing_input,
                                  padding.PKCS1v15(), hashes.SHA256())
            except InvalidSignature:
                raise AuthError("bad_issuer", "token signature is invalid") from None
        elif alg == "ES256":
            x = int.from_bytes(_b64url_decode(str(jwk["x"])), "big")
            y = int.from_bytes(_b64url_decode(str(jwk["y"])), "big")
            public_key = ec.EllipticCurvePublicNumbers(
                x, y, ec.SECP256R1()
            ).public_key()
            try:
                public_key.verify(signature, signing_input,
                                  ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                raise AuthError("bad_issuer", "token signature is invalid") from None
        else:
            raise AuthError("bad_issuer",
                            "unsupported signing algorithm {!r}".format(alg))


class OIDCClient:
    """Discovery, PKCE authorization URLs, token exchange and claim checks."""

    def __init__(self, issuer: str, client_id: str, client_secret: str,
                 redirect_uri: str, *, http: Any = None,
                 verifier: Any = None, clock: Any = time.time) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.http = http or _default_http
        self._verifier = verifier
        self.clock = clock
        self._discovery: Optional[Dict[str, Any]] = None
        self._discovery_at = 0.0
        #: Set by the login route so a two-argument ``exchange`` still checks
        #: the nonce the browser round-tripped.
        self.nonce: Optional[str] = None

    # -- discovery ------------------------------------------------------
    def discovery(self) -> Dict[str, Any]:
        now = self.clock()
        if self._discovery is not None and now - self._discovery_at < DISCOVERY_TTL:
            return self._discovery
        url = self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        status, _headers, body = self.http("GET", url, None, None)
        if status != 200:
            raise AuthError("bad_issuer", "discovery document is unavailable")
        try:
            document = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AuthError("bad_issuer", "malformed discovery document") from None
        if not isinstance(document, dict):
            raise AuthError("bad_issuer", "malformed discovery document")
        # Exact match: a substring check would let a hostile issuer pass.
        if document.get("issuer") != self.issuer:
            raise AuthError("bad_issuer", "discovery issuer mismatch")
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not document.get(field):
                raise AuthError("bad_issuer",
                                "discovery document lacks {}".format(field))
        self._discovery = document
        self._discovery_at = now
        return document

    # -- authorization --------------------------------------------------
    @staticmethod
    def pkce_pair() -> Tuple[str, str]:
        """Return ``(code_verifier, code_challenge)`` using S256."""
        verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return verifier, _b64url_encode(digest)

    def authorization_url(self, state: str, nonce: str,
                          code_challenge: str) -> str:
        document = self.discovery()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in document["authorization_endpoint"] else "?"
        return document["authorization_endpoint"] + separator + urlencode(params)

    # -- token exchange -------------------------------------------------
    def exchange(self, code: str, code_verifier: str, *,
                 nonce: Optional[str] = None) -> Dict[str, Any]:
        document = self.discovery()
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": code_verifier,
        }
        if self.client_secret:
            form["client_secret"] = self.client_secret
        status, _headers, body = self.http(
            "POST", document["token_endpoint"], urlencode(form).encode("ascii"),
            {"content-type": "application/x-www-form-urlencoded"},
        )
        if status != 200:
            raise AuthError("invalid_request", "token exchange failed")
        try:
            token_response = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AuthError("invalid_request", "malformed token response") from None
        if not isinstance(token_response, dict):
            raise AuthError("invalid_request", "malformed token response")
        if token_response.get("token_type") != "Bearer":
            raise AuthError("invalid_request", "token_type must be Bearer")
        id_token = token_response.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise AuthError("invalid_request", "token response has no id_token")

        expected_nonce = self.nonce if nonce is None else nonce
        verifier = self._verifier
        if verifier is None:
            verifier = JwtVerifier(document["jwks_uri"], http=self.http,
                                   clock=self.clock)
        claims = verifier.verify(
            id_token, issuer=self.issuer, audience=self.client_id,
            nonce=expected_nonce, now=self.clock(),
        )
        return self.validate_claims(claims, nonce=expected_nonce)

    def validate_claims(self, claims: Mapping[str, Any], *,
                        nonce: Optional[str] = None,
                        now: Optional[float] = None) -> Dict[str, Any]:
        """Apply FR-047's matrix; raise :class:`AuthError` on any failure."""
        if claims.get("iss") != self.issuer:
            raise AuthError("bad_issuer", "issuer does not match")
        audience = claims.get("aud")
        if not (_contains(audience, self.client_id)
                or claims.get("azp") == self.client_id):
            raise AuthError("bad_audience", "audience does not match")

        at = self.clock() if now is None else float(now)
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or exp <= at - CLOCK_SKEW:
            raise AuthError("expired", "identity token has expired")
        iat = claims.get("iat")
        if not isinstance(iat, (int, float)) or iat > at + CLOCK_SKEW:
            raise AuthError("expired", "identity token was issued in the future")
        if nonce is not None and claims.get("nonce") != nonce:
            raise AuthError("bad_nonce", "nonce does not match")
        if claims.get("email_verified") is not True:
            raise AuthError("email_unverified", "email is not verified")
        if not str(claims.get("sub") or ""):
            raise AuthError("missing_subject", "subject is missing")
        if not str(claims.get("email") or ""):
            raise AuthError("missing_subject", "email is missing")
        return dict(claims)


__all__ = [
    "AuthError",
    "OIDCClient",
    "JwtVerifier",
    "CLOCK_SKEW",
    "DISCOVERY_TTL",
    "HTTP_TIMEOUT",
]
