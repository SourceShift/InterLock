"""compile_profile bridges the policy plane to the confinement IR, and it
defaults closed: reach must be granted, never assumed. These tests pin that
contract so a future change cannot quietly widen what a sandbox may touch.
"""
from interlock.brace import SandboxProfile, compile_profile
from interlock.brace.profile import (
    EGRESS_TEMPLATE,
    FS_TEMPLATE,
    LIMITS_TEMPLATE,
)


def test_empty_policy_is_locked():
    prof = compile_profile({})
    assert prof.allow_network is False
    assert prof.allowed_hosts == ()
    assert prof.write_paths == ()
    assert prof.read_paths == ()


def test_none_policy_is_locked():
    assert compile_profile(None) == SandboxProfile.locked()


def test_egress_binding_grants_network():
    prof = compile_profile({EGRESS_TEMPLATE: {"allowed_hosts": ["api.internal", "b.co"]}})
    assert prof.allow_network is True
    assert set(prof.allowed_hosts) == {"api.internal", "b.co"}


def test_empty_egress_list_still_no_network():
    # A present-but-empty allowlist must not accidentally open the network.
    prof = compile_profile({EGRESS_TEMPLATE: {"allowed_hosts": []}})
    assert prof.allow_network is False


def test_fs_and_limit_bindings():
    prof = compile_profile(
        {
            FS_TEMPLATE: {"read_paths": ["/opt/data"], "write_paths": ["/tmp/out"]},
            LIMITS_TEMPLATE: {"cpu_seconds": 5, "memory_mb": 256},
        }
    )
    assert prof.read_paths == ("/opt/data",)
    assert prof.write_paths == ("/tmp/out",)
    assert prof.cpu_seconds == 5
    assert prof.memory_mb == 256


def test_single_host_string_is_accepted():
    # A scalar host, not a list, should still be understood as one allowed host.
    prof = compile_profile({EGRESS_TEMPLATE: {"allowed_hosts": "api.internal"}})
    assert prof.allowed_hosts == ("api.internal",)


def test_with_paths_is_additive_and_immutable():
    base = SandboxProfile.locked()
    grown = base.with_paths(read=["/a"], write=["/b"])
    assert base.write_paths == ()  # original unchanged
    assert grown.read_paths == ("/a",)
    assert grown.write_paths == ("/b",)


def test_base_env_does_not_leak_parent_env():
    # Nothing from os.environ unless explicitly passed.
    prof = compile_profile({}, base_env={"ONLY": "this"})
    assert dict(prof.env) == {"ONLY": "this"}
