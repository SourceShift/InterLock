"""Run identity carried across await boundaries via contextvars."""
from __future__ import annotations

import contextlib
import contextvars
import uuid
from typing import Iterator, Optional

_span_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "interlock_span_id", default=None
)
_principal: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "interlock_principal", default=None
)
_parent_principal: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "interlock_parent_principal", default=None
)


def new_span(
    principal: Optional[str] = None,
    parent_principal: Optional[str] = None,
) -> str:
    """Start a fresh span id for the current context and return it."""
    sid = uuid.uuid4().hex
    _span_id.set(sid)
    if principal is not None:
        _principal.set(principal)
    if parent_principal is not None:
        _parent_principal.set(parent_principal)
    return sid


def current_span() -> Optional[str]:
    return _span_id.get()


def current_principal() -> Optional[str]:
    return _principal.get()


def current_parent_principal() -> Optional[str]:
    """Who the current principal acts on behalf of, if it was delegated to."""
    return _parent_principal.get()


def set_principal(
    principal: Optional[str],
    parent_principal: Optional[str] = None,
) -> None:
    """Declare the acting principal for the current context.

    ``parent_principal`` is set only when given: a bare ``set_principal(x)``
    leaves any inherited delegation link intact rather than silently erasing
    provenance. Use :func:`span` for a link that should be restored on exit.
    """
    _principal.set(principal)
    if parent_principal is not None:
        _parent_principal.set(parent_principal)


@contextlib.contextmanager
def span(
    principal: Optional[str] = None,
    parent_principal: Optional[str] = None,
) -> Iterator[str]:
    """Scope a span id (and optional principal) to a block, then restore."""
    token_s = _span_id.set(uuid.uuid4().hex)
    token_p = _principal.set(principal) if principal is not None else None
    token_pp = (
        _parent_principal.set(parent_principal)
        if parent_principal is not None
        else None
    )
    try:
        yield _span_id.get()  # type: ignore[misc]
    finally:
        _span_id.reset(token_s)
        if token_p is not None:
            _principal.reset(token_p)
        if token_pp is not None:
            _parent_principal.reset(token_pp)
