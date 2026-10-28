"""Sensor-side bounded queues.

The ring is the in-memory half of FR-011/FR-074; the disk spool lives in
:mod:`interlock.cloud.connector.spool`. Both share one kind/priority
vocabulary and one ``(host, sensor, sequence)`` identity.
"""
from __future__ import annotations

from .ring import DEFAULT_RING_BYTES, Entry, Ring

__all__ = ["DEFAULT_RING_BYTES", "Entry", "Ring"]
