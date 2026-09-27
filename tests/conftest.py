"""Shared fixtures for the sidecar tests.

The socket tests need a *short* path: a unix socket address is capped near 104
bytes, and pytest's ``tmp_path`` on macOS lives under ``/private/var/folders/``,
long enough that the bind fails with ``AF_UNIX path too long`` before any of the
behaviour under test is reached. ``/tmp`` is short and sticky, and a ``mkdtemp``
inside it is 0700, so the daemon's private-directory rule still holds.
"""
from __future__ import annotations

import os
import shutil
import tempfile

import pytest


@pytest.fixture
def socket_dir():
    """A short, private directory for a socket file."""
    directory = tempfile.mkdtemp(prefix="il-", dir="/tmp")
    os.chmod(directory, 0o700)
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture
def sock_path(socket_dir):
    """Factory for a socket path inside :func:`socket_dir`."""

    def make(name="g.sock"):
        return os.path.join(socket_dir, name)

    return make
