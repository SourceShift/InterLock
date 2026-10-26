"""Authentication, sessions, step-up and authorization for the plane.

Every module in this package imports only the standard library at module
scope. Optional dependencies (``cryptography``, ``webauthn``) are imported
inside the function that needs them.
"""
from __future__ import annotations

__all__ = ["oidc", "rbac", "sessions", "stepup"]
