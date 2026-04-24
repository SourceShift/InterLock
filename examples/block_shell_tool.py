"""M0 demo: block a destructive shell tool before it runs.

Run it:  python examples/block_shell_tool.py
"""
import subprocess

import interlock
from interlock import Blocked, deny_when, guard, span


@guard(policy_id="shell.exec.v1")
def run_shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def looks_destructive(event) -> bool:
    cmd = str(event.args.get("cmd", ""))
    bad = ("rm -rf", ":(){", "mkfs", "dd if=", "> /dev/sd")
    return any(token in cmd for token in bad)


def main() -> None:
    interlock.install(
        rules=[
            deny_when(
                looks_destructive,
                reason="destructive shell command blocked",
                policy_id="shell.exec.v1",
            )
        ]
    )

    with span(principal="agent-demo"):
        print("allowed :", run_shell("echo hello from the agent").strip())
        try:
            run_shell("rm -rf /tmp/does-not-exist-interlock")
            print("ERROR   : destructive command was NOT blocked")
        except Blocked as blocked:
            print("blocked :", blocked)


if __name__ == "__main__":
    main()
