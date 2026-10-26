"""One JSON object per log line, on stderr, with no tenant data.

The plane runs beside customer data, so its log line is a fixed envelope:
``ts``, ``level``, ``event`` and (when the caller has one) ``request_id`` plus
whatever non-tenant fields the event names. Callers must not pass headers,
cookies, query strings, bodies or preview text -- there is no redaction here
because there should be nothing to redact.
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any

LEVELS = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "warn": 30,
    "error": 40,
    "critical": 50,
}

_threshold = LEVELS["info"]


def configure(level: str) -> None:
    """Set the minimum level ``log_event`` writes (default ``info``)."""
    global _threshold
    _threshold = LEVELS.get(str(level).lower(), LEVELS["info"])


def log_event(level: str, event: str, request_id: Any = None, **fields: Any) -> None:
    """Write one JSON line to stderr, unless below the configured threshold."""
    name = str(level).lower()
    if LEVELS.get(name, LEVELS["info"]) < _threshold:
        return
    doc = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": name,
        "event": event,
    }
    if request_id is not None:
        doc["request_id"] = request_id
    doc.update(fields)
    sys.stderr.write(json.dumps(doc, separators=(",", ":")) + "\n")
