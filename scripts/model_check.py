#!/usr/bin/env python3
import subprocess


def check(source_branch: str, target_branch: str) -> None:
    child = subprocess.run(
        [
            "git", "diff", "--compact-summary",
            f"{source_branch}..{target_branch}", "faraday/migrations/"
        ],
        stdout=subprocess.PIPE
    )
    assert child.returncode == 0, (child.stdout, child.returncode)
    assert b"insertion" not in child.stdout


if __name__ == '__main__':
    check("origin/white/dev", "origin/black/dev")
