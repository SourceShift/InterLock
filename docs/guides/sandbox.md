# Sandbox subprocesses (BRACE)

interlock checks the calls it can see. A subprocess is out of its sight: once
your agent runs `python worker.py` or a shell command, that child can open
files, read environment secrets, and connect anywhere, and no in-process rule
is consulted. BRACE closes that gap. It turns your policy into a sandbox profile
and runs the command under the operating system's own isolation, so the child is
confined even though interlock can't watch what it does.

You'll need: interlock installed. On Linux, install `bubblewrap` (`bwrap`) for
real isolation. On macOS, `sandbox-exec` ships with the system.

## Run a command in a sandbox

The sandbox starts closed: no network, no writable paths, and an empty
environment. You grant only what the command needs. Here the agent process holds
an API key, and the child gets one writable workspace and nothing else:

```python
import os, sys, tempfile
os.environ["OPENAI_API_KEY"] = "sk-parent-secret"     # a secret the agent process holds
from interlock.brace import Sandbox, compile_profile

workspace = tempfile.mkdtemp(prefix="agent-ws-")
profile = compile_profile({"sandbox_fs": {"write_paths": [workspace]}})

script = r'''
import os, socket
open(os.path.join(WS, "out.txt"), "w").write("ok")
print("write in workspace: ok")
try:
    open(os.path.expanduser("~/.interlock-sandbox-test"), "w").write("x")
    print("write in home: ok (NOT confined)")
except OSError as e:
    print("write in home:", e.strerror)
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
    print("network: open")
except OSError as e:
    print("network:", e.strerror or e)
print("OPENAI_API_KEY in child:", os.environ.get("OPENAI_API_KEY"))
'''.replace("WS", repr(workspace))

result = Sandbox(profile).run([sys.executable, "-c", script])
print("backend:", result.backend)
print("enforced:", result.enforced)
print(result.stdout, end="")
```

On macOS:

```
backend: sandbox-exec
enforced: ['fs-rw', 'env', 'net']
write in workspace: ok
write in home: Operation not permitted
network: Operation not permitted
OPENAI_API_KEY in child: None
```

`result` is a `SandboxResult` with `backend`, `argv`, `returncode`, `stdout`,
`stderr`, `enforced`, and an `ok` property (`returncode == 0`). `run` also
accepts `timeout=` and `capture_output=`.

A `timeout=` that expires kills the sandbox's whole process group on POSIX, then
raises `subprocess.TimeoutExpired`. A descendant that calls `setsid()` itself
leaves that group and is not killed; confinement and per-process limits still
apply to it.

Use an absolute path for the program (`sys.executable` above). The child's
environment is empty, so there is no `PATH` from your shell to search.

### The per-run scratch directory

Each `run()` creates one private `0700` directory (`interlock-brace-…`), sets
`TMPDIR`, `TMP`, and `TEMP` to it, grants write access to it, and removes the
tree afterwards — on success, on failure, and on timeout. The one exception is
a descendant that escaped the process group via `setsid()` and still holds the
directory open when the timeout drain expires: the tree is then left in place
rather than pulled from under it. On macOS the shared temp roots
(`/private/tmp`, `/private/var/folders`) are **not** granted, so a runtime that
needs scratch space gets exactly one directory that dies with the run. The
scratch path is added only for the executed command: the policy
`process_spawn` event, `plan()`, and `result.argv` show the profile you passed.

## Grant what the command needs

`compile_profile` reads the same `{template_id: params}` dictionary that
[scopes](scopes.md) produce with `registry.resolve(...)`. Three bindings grant
reach. Anything not mentioned stays denied.

| Binding | Params | Grants |
|---|---|---|
| `egress_allowlist` | `allowed_hosts` | network access (see the warning below) |
| `sandbox_fs` | `read_paths`, `write_paths` | read-only and read-write paths |
| `sandbox_limits` | `cpu_seconds`, `memory_mb` | resource ceilings, applied on every backend |

```python
profile = compile_profile(registry.resolve(("root", "acme", "agent42")))
```

The environment comes from `base_env`, never from your process:

```python
profile = compile_profile(None, base_env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
Sandbox(profile).run([sys.executable, "-c", "import os; print(sorted(os.environ))"]).stdout
# -> "['LANG', 'PATH', 'TEMP', 'TMP', 'TMPDIR']\n"
```

`TEMP`, `TMP`, and `TMPDIR` are the run's private scratch directory, injected by
`run()`; everything else is exactly what you passed.

`compile_profile(None)` gives the fully locked profile, and so does `Sandbox()`
with no profile. `workdir=` sets the child's working directory on every backend.

CPU and memory limits are set on the child just before it starts, so they hold on
every backend, not only `soft`. Under `cpu_seconds=1`, a runaway
`while True: pass` is killed with SIGXCPU (`returncode -24`) under sandbox-exec
as well. Only `soft` reports the `rlimit` token in `enforced`, because only that
backend's claim is covered by the token tests.

`memory_mb` can't be enforced on macOS. The kernel refuses address-space limits
below roughly 1 TB, which a 64-bit process has already reserved, so any
smaller ceiling is rejected. Rather than drop the limit silently, `Sandbox(...)`
refuses the profile when you build it:

```python
Sandbox(compile_profile({"sandbox_limits": {"memory_mb": 256}}))
# -> LimitUnsupported: memory_mb=256 cannot be enforced on macOS: the kernel refuses RLIMIT_AS
#    and RLIMIT_DATA below the ~1 TB of address space a 64-bit process already reserves.
#    Remove memory_mb from the profile (the sandbox_limits binding), or run on Linux.
```

`LimitUnsupported` is exported from `interlock.brace`. On Windows, any limit
raises it.

> **Warning**
> Granting network opens it **fully**. Neither bubblewrap nor Seatbelt can limit
> egress to specific hosts without root. A profile with
> `allowed_hosts=["api.github.com"]` reaches any host, and the backend says so
> by leaving `net` out of `enforced`:
>
> ```
> plan enforced with network grant: ['fs-rw', 'env']
> reached 1.1.1.1 (not on the allowlist)
> ```
>
> Per-host filtering happens in-process, with `network_egress_guard` on the
> calls interlock can see. At the OS level only a root-only nftables backend
> exists, and it isn't selectable through `Sandbox`.

## Refuse to run without the isolation you need

BRACE picks the strongest backend available. On a machine without bubblewrap or
Seatbelt, that's `soft`, which is not a security boundary. If your code needs
real isolation, say so with `require=`. `run()` then refuses **before starting
anything** when the backend can't deliver every token you named:

```python
from interlock.brace import IsolationUnavailable

locked = compile_profile(None)
Sandbox(locked, require=("net", "fs-rw")).run([sys.executable, "-c", "print('hello from the sandbox')"]).stdout
# -> 'hello from the sandbox\n'

Sandbox(locked, backend="soft", require=("net", "fs-rw")).run([sys.executable, "-c", "print('should not run')"])
# -> IsolationUnavailable: refusing to run: the soft backend cannot enforce ['net', 'fs-rw']
#    for this profile (it enforces ['env'])
```

The exception carries `.backend`, `.missing`, and `.enforced`. A misspelled token
fails when you build the sandbox, not on every run:

```python
Sandbox(locked, require=("netw",))
# -> ValueError: unknown required token(s) ['netw']; known tokens are
#    ['env', 'fs-ro', 'fs-rw', 'net', 'pid', 'rlimit']
```

Checking `result.enforced` after `run()` tells you the same thing, but by then
the command has already run. To inspect a launch without running it, `plan()`
builds the wrapped command and its guarantees:

```python
p = Sandbox(locked).plan(["python3", "worker.py"])
p.exec_argv[:2], p.exec_argv[3:]
# -> (['sandbox-exec', '-p'], ['python3', 'worker.py'])     exec_argv[2] is the Seatbelt profile
p.enforced
# -> ['fs-rw', 'env', 'net']
```

`plan()` does not run the policy check described next. Only `run()` does.

To pin a backend, pass `backend=`. An unavailable backend raises instead of
quietly falling back:

```python
Sandbox(backend="bubblewrap")    # on macOS -> RuntimeError: backend not available on this host: bubblewrap
Sandbox(backend="nftables")      # -> ValueError: unknown backend: nftables
```

`available_backends()` lists what this machine offers, strongest first. On this
Mac it returns `['sandbox-exec', 'soft']`.

## Block or rewrite a launch with your rules

Before any process starts, `run()` sends the launch through your policy as a
`process_spawn` event. Every rule you've installed sees it, so you can block
programs or rewrite the command line.

The event's arguments:

```python
{'path': '/usr/local/bin/python3',
 'argv': ['/usr/local/bin/python3', '-c', 'import sys; print(sys.flags.isolated)'],
 'allow_network': False, 'allowed_hosts': [], 'write_paths': []}
```

`write_paths` is the profile you passed. The per-run scratch directory is
deliberately absent: the launch your rules approve happens before that directory
exists, and the scratch is an implementation detail of the run.


Block a program:

```python
import interlock
from interlock import Blocked, Decision, deny_when

interlock.install(rules=[
    deny_when(lambda e: e.action == "process_spawn" and "curl" in e.args.get("argv", []),
              reason="no curl in the sandbox"),
])
Sandbox(locked).run(["curl", "https://example.com"])
# -> Blocked: blocked action 'process_spawn': no curl in the sandbox
```

Rewrite it. A rule that returns a new `argv` changes what actually runs. This
one forces Python's isolated mode:

```python
def isolated_python(event):
    argv = event.args.get("argv") or []
    if event.action == "process_spawn" and argv and argv[0].endswith("python3") and "-I" not in argv:
        return Decision.modify({"argv": [argv[0], "-I"] + argv[1:]}, reason="force isolated mode")
    return None

interlock.install(rules=[isolated_python])
result = Sandbox(locked).run(["/usr/local/bin/python3", "-c", "import sys; print(sys.flags.isolated)"])
result.argv[1], result.stdout
# -> ('-I', '1\n')
```

`deny_tool("process_spawn")` blocks every sandbox launch. `Sandbox(...)` also
takes `engine=`, `enforcement="monitor"`, and `principal=` for this check.

## What each backend enforces

| Backend | Runs on | `enforced` tokens | Reads confined | CPU/memory limits | `workdir` |
|---|---|---|---|---|---|
| `bubblewrap` | Linux with `bwrap` | `fs-ro`, `fs-rw`, `env`, `pid`, `net`* | yes | applied (not reported) | yes |
| `sandbox-exec` | macOS | `fs-rw`, `env`, `net`* | no | CPU applied (not reported); memory refused | yes |
| `soft` | anywhere | `env`, `rlimit`** | no | yes (memory refused on macOS) | yes |

\* only when the profile grants no network.
\*\* only when the profile sets a limit.

What each token means:

- `env`: the child gets only the environment you passed, nothing from the parent.
- `fs-rw`: writes outside `write_paths` fail. Each run's private scratch
  directory is added to those grants. On macOS the shared temp roots and the
  rest of `/dev` are not, so only `/dev/null` and `/dev/fd` are writable by
  default; under bubblewrap `/tmp` and `/dev` are fresh trees private to the
  sandbox.
- `fs-ro`: only the granted paths, plus read-only system directories such as
  `/usr`, `/bin`, and `/etc/ssl`, exist inside the sandbox.
- `pid`: the child can't see or signal host processes.
- `net`: the child has no network.
- `rlimit`: the CPU and memory ceilings are applied.

Each token is a tested claim, not a description. For every backend and token,
`tests/integration/test_brace_token_matrix.py` runs the attack that token exists
to stop and asserts it fails. It then runs the same attack with only that one
protection relaxed and asserts it succeeds, so the block is the sandbox's doing.
A backend missing from the host is skipped with a reason (`pytest -rs`).

## Limits

> **Warning**
> **`soft` is not a security boundary.** It scrubs the environment and applies
> resource limits. Code that wants to escape it can. Treat it as damage control,
> and use `require=` so untrusted code never runs on it by accident.

- **macOS can't confine reads or processes.** Seatbelt allows all file reads
  (the dynamic loader needs them), so a sandboxed process can read
  `/etc/passwd` or your home directory. There is no PID isolation, and
  `read_paths` has no effect.
- **No memory limits on macOS.** `memory_mb` raises `LimitUnsupported` there.
  `cpu_seconds` works on every backend.
- **Only `soft` reports `rlimit`.** bubblewrap and sandbox-exec apply the
  limits but leave the token out, so `require=("rlimit",)` refuses them.
- **No per-host egress at the OS level.** Granting network grants all of it, as
  described above.
- **`sandbox-exec` is deprecated by Apple.** It works on current macOS but is
  not a supported API.

## Next

- [Scopes](scopes.md): give each tenant or agent its own sandbox grants
- [Security model](../security-model.md): what interlock does and doesn't protect
- [Python API reference](../reference/python-api.md): `Sandbox`, `SandboxProfile`, `compile_profile`
- [Production checklist](production.md)
