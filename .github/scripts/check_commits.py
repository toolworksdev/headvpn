#!/usr/bin/env python3
"""Check commit subjects against the project convention.

    <type>(<scope>)!: <gitmoji> <subject>

The gitmoji is required: it is what makes `git log` readable at a glance, and
the squash commit on `main` is the pull request title, so the title is checked
with the same rule.

Usage: check_commits.py <subject> [<subject> ...]   (one argument per subject)
Exit 1 and one line per offender when something does not match.
"""
from __future__ import annotations

import re
import sys
import unicodedata

TYPES = "feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert"
HEAD = re.compile(rf"^(?:{TYPES})(?:\([a-z0-9._-]+\))?!?: (?P<rest>.+)$")


def starts_with_emoji(s: str) -> bool:
    """True when s opens with a pictographic symbol (gitmoji), optionally followed
    by a variation selector, and then a space and text."""
    if not s:
        return False
    c = s[0]
    if c.isascii() or unicodedata.category(c) not in ("So", "Sk", "Cn"):
        return False
    i = 1
    while i < len(s) and (0xFE00 <= ord(s[i]) <= 0xFE0F or ord(s[i]) == 0x200D or not s[i].isascii() and unicodedata.category(s[i]) in ("So", "Mn", "Sk")):
        i += 1
    return s[i:i + 1] == " " and s[i + 1:].strip() != ""


def problem(subject: str) -> str | None:
    if subject.startswith(("Merge ", "Revert \"")):
        return None
    m = HEAD.match(subject)
    if not m:
        return "type prefix missing or wrong (feat|fix|docs|…: )"
    if not starts_with_emoji(m.group("rest")):
        return "a gitmoji must open the subject (e.g. `feat: ✨ add …`)"
    return None


def main(argv: list[str]) -> int:
    bad = 0
    for s in argv:
        p = problem(s)
        if p:
            print(f"✗ {s}\n    {p}")
            bad += 1
    if bad:
        print(f"\n{bad} subject(s) do not follow CONTRIBUTING.md → Commit messages.")
        return 1
    print(f"{len(argv)} subject(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
