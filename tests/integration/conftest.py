"""Fixtures for the integration tests: a real outsider and a real secret file."""
import os

import pytest

from incident import Outsider


@pytest.fixture
def outsider():
    """A real loopback HTTP server that records what an agent exfiltrates."""
    box = Outsider()
    try:
        yield box
    finally:
        box.close()


@pytest.fixture
def system_secret_path():
    """A real, readable system file that agents should never ship off-box."""
    path = "/etc/passwd"
    if not os.access(path, os.R_OK):
        pytest.skip("/etc/passwd is not readable in this environment")
    return path
