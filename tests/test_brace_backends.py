"""The per-OS backends translate a profile into flags. The translation is a pure
function, so these tests assert on the exact argv / profile text a run would use
without spawning anything, and pin the privileged nftables path so it can never
touch the host firewall by accident.
"""
import pytest

from interlock.brace import SandboxProfile, available_backends, select_backend
from interlock.brace.backends import bubblewrap, nftables, sandbox_exec
from interlock.brace.backends.soft import SoftBackend


# --- soft backend: the always-available fallback -----------------------------
def test_soft_is_always_available():
    assert SoftBackend.is_available() is True
    assert "soft" in available_backends()


def test_soft_scrubs_env_and_sets_rlimit_token():
    prof = SandboxProfile(env={"KEEP": "1"}, cpu_seconds=2, memory_mb=64)
    plan = SoftBackend().wrap(prof, ["/bin/echo", "hi"])
    assert plan.exec_argv == ["/bin/echo", "hi"]  # soft does not wrap the argv
    assert plan.popen_kwargs["env"] == {"KEEP": "1"}
    assert "env" in plan.enforced
    assert "rlimit" in plan.enforced
    assert "preexec_fn" in plan.popen_kwargs


def test_soft_no_limits_no_preexec():
    plan = SoftBackend().wrap(SandboxProfile.locked(), ["/bin/echo"])
    assert "preexec_fn" not in plan.popen_kwargs
    assert "rlimit" not in plan.enforced


# --- bubblewrap: Linux argv builder (pure, no bwrap needed) ------------------
def test_bwrap_isolates_network_when_not_granted():
    argv, enforced = bubblewrap.build_argv(SandboxProfile.locked(), ["python", "x.py"])
    assert "--unshare-net" in argv
    assert "--unshare-pid" in argv
    assert "--clearenv" in argv
    assert "net" in enforced and "pid" in enforced
    assert argv[-2:] == ["python", "x.py"]  # after the -- separator


def test_bwrap_shares_network_when_granted():
    prof = SandboxProfile(allow_network=True, allowed_hosts=("api.internal",))
    argv, enforced = bubblewrap.build_argv(prof, ["curl", "api.internal"])
    assert "--unshare-net" not in argv
    assert "net" not in enforced  # network is open, so no isolation claim
    # resolv.conf is bound so DNS resolves inside the namespace
    assert "/etc/resolv.conf" in argv


def test_bwrap_binds_granted_paths():
    prof = SandboxProfile(read_paths=("/opt/ro",), write_paths=("/data/rw",))
    argv, _ = bubblewrap.build_argv(prof, ["cmd"])
    joined = " ".join(argv)
    assert "--ro-bind /opt/ro /opt/ro" in joined
    assert "--bind /data/rw /data/rw" in joined


# --- sandbox-exec: macOS Seatbelt profile builder ----------------------------
def test_seatbelt_denies_by_default_and_confines_writes():
    prof = SandboxProfile(write_paths=("/private/tmp/out",))
    sbpl = sandbox_exec.build_profile(prof)
    assert "(deny default)" in sbpl
    assert "(allow file-read*)" in sbpl  # reads broad by necessity on macOS
    assert '(subpath "/private/tmp/out")' in sbpl  # the granted write path
    assert "(allow network*)" not in sbpl  # no egress binding -> no network


def test_seatbelt_grants_network_when_allowed():
    prof = SandboxProfile(allow_network=True, allowed_hosts=("api.internal",))
    assert "(allow network*)" in sandbox_exec.build_profile(prof)


def test_seatbelt_enforced_tokens_omit_fs_ro():
    # macOS cannot confine reads; the honest token set must not claim fs-ro.
    _, enforced = sandbox_exec.build_argv(SandboxProfile.locked(), ["/bin/echo"])
    assert "fs-ro" not in enforced
    assert "fs-rw" in enforced and "net" in enforced


def test_seatbelt_locked_profile_grants_no_shared_temp_root_and_not_all_of_dev():
    """The locked profile writes only to the two device nodes a process needs.

    /dev as a whole includes /dev/fd (already granted) and every other device;
    the shared temp roots must stay closed so a per-run scratch grant means
    something.
    """
    sbpl = sandbox_exec.build_profile(SandboxProfile.locked())
    assert "(subpath \"/dev\")" not in sbpl
    assert "(literal \"/dev/null\")" in sbpl
    assert "(subpath \"/dev/fd\")" in sbpl
    assert "/private/tmp" not in sbpl
    assert "/private/var/folders" not in sbpl


def test_seatbelt_renders_device_nodes_as_literals_and_grants_as_subpaths():
    prof = SandboxProfile(write_paths=("/private/tmp/out",))
    sbpl = sandbox_exec.build_profile(prof)
    assert "(literal \"/dev/null\")" in sbpl
    assert "(subpath \"/dev/fd\")" in sbpl
    assert "(subpath \"/private/tmp/out\")" in sbpl


def test_seatbelt_escapes_a_path_that_could_inject_a_rule():
    """A quote or paren in a grant path must not add SBPL rules.

    Escaping only the quote leaves the injected text inside the string literal,
    which is semantically safe but still makes the rendered profile look like it
    contains a second grant; the parentheses are octal-escaped too, and
    Seatbelt decodes ``\\050``/``\\051`` back to parens for matching.
    """
    hostile = '/tmp/x" (allow network*) (allow file-write* "/'
    sbpl = sandbox_exec.build_profile(SandboxProfile(write_paths=(hostile,)))
    assert sbpl.count("(allow file-write*") == 1
    assert "(allow network*)" not in sbpl
    assert "\\050allow network*\\051" in sbpl


@pytest.mark.parametrize("bad", ["", "rel/path", "a\nb", "a\rb", "a\x00b"])
def test_seatbelt_rejects_invalid_grant_paths(bad):
    with pytest.raises(ValueError):
        sandbox_exec.build_profile(SandboxProfile(write_paths=(bad,)))


@pytest.mark.parametrize("bad", ["", "rel/path"])
def test_sandbox_exec_wrap_rejects_relative_paths_before_canonicalizing(bad):
    """realpath() would turn these into cwd-derived absolute paths; a relative
    grant must fail closed instead of silently granting something unnamed."""
    with pytest.raises(ValueError):
        sandbox_exec.SandboxExecBackend().wrap(
            SandboxProfile(write_paths=(bad,)), ["/bin/echo", "x"]
        )


def test_bwrap_binds_the_scratch_directory_after_the_tmpfs():
    """The per-run scratch lives under /tmp; its --bind must come after the
    --tmpfs /tmp pair or the tmpfs would hide it."""
    scratch = "/tmp/interlock-brace-abc123"
    argv, _ = bubblewrap.build_argv(
        SandboxProfile(write_paths=(scratch,)), ["cmd"]
    )
    assert argv.index("--tmpfs") < argv.index("--bind")
    assert argv[argv.index("--bind") + 1] == scratch


def test_bwrap_owns_its_session_so_the_spawner_must_not_repeat_it():
    """bwrap's --new-session already calls setsid(); a Popen start_new_session
    would make that second setsid() fail with EPERM and bwrap would exit
    before running anything."""
    plan = bubblewrap.BubblewrapBackend().wrap(SandboxProfile.locked(), ["cmd"])
    assert "--new-session" in plan.exec_argv
    assert plan.creates_session is True


# --- nftables: host-granular egress (pure builder + gated apply) -------------
def test_nft_ruleset_drops_by_default_and_allows_listed_ips():
    rs = nftables.build_ruleset(["10.0.0.1", "2001:db8::1"])
    assert "policy drop;" in rs
    assert "oifname lo accept" in rs
    assert "udp dport 53 accept" in rs  # DNS
    assert "ip daddr 10.0.0.1 accept" in rs
    assert "ip6 daddr 2001:db8::1 accept" in rs


def test_nft_resolve_skips_unresolvable_host():
    ips = nftables.resolve_hosts(["localhost", "this-host-does-not-exist.invalid"])
    assert any(ip.startswith("127.") or ip == "::1" for ip in ips)


def test_nft_apply_refuses_without_confirm():
    with pytest.raises(ValueError):
        nftables.apply_ruleset("table inet x {}", confirm=False)


def test_nft_apply_refuses_without_privilege(monkeypatch):
    monkeypatch.setattr(nftables, "can_apply", lambda: False)
    with pytest.raises(PermissionError):
        nftables.apply_ruleset("table inet x {}", confirm=True)


# --- selection ---------------------------------------------------------------
def test_select_unknown_backend_raises():
    with pytest.raises(ValueError):
        select_backend("does-not-exist")


def test_available_backends_best_first():
    names = available_backends()
    assert names[-1] == "soft"  # fallback is always last
