"""Test bootstrap: put the repo root on sys.path and reset global state per test."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import interlock  # noqa: E402
from interlock import PolicyEngine  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_engine():
    # The policy engine is process-global; isolate every test from the last.
    interlock.install(engine=PolicyEngine())
    # So are the approver, its grants, and the dropped-receipt counter.
    from interlock import approval, receipt
    from interlock.interceptors import decorator
    decorator._MODES.clear()
    approval.set_approver(None)
    approval.grants().clear()
    receipt._dropped = 0
    receipt._last_drop_error = ""
    yield
