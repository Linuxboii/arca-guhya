"""A compact implementation of the commonly used parts of .gitignore syntax.

Supported: comments, blank lines, ``*``, ``?``, ``[...]``, ``**`` (leading,
trailing and in the middle), ``!`` negation, trailing ``/`` for directories,
anchoring via a leading or inner ``/``, and nested ``.gitignore`` files whose
patterns apply relative to their own directory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class _Rule:
    regex: re.Pattern
    negate: bool
    dir_only: bool
    base: str  # posix path of the directory holding the ignore file ("" = root)


def _translate(pattern: str) -> str:
    out = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == n:
            out.append("/.*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        else:
            ch = pattern[i]
            if ch == "*":
                out.append("[^/]*")
            elif ch == "?":
                out.append("[^/]")
            elif ch == "[":
                j = pattern.find("]", i + 1)
                if j == -1:
                    out.append(re.escape(ch))
                else:
                    body = pattern[i + 1:j]
                    if body.startswith("!"):
                        body = "^" + body[1:]
                    out.append("[" + body.replace("\\", "\\\\") + "]")
                    i = j
            elif ch == "\\" and i + 1 < n:
                i += 1
                out.append(re.escape(pattern[i]))
            else:
                out.append(re.escape(ch))
            i += 1
    return "".join(out)


def compile_pattern(line: str, base: str = "") -> _Rule | None:
    line = line.rstrip("\n").rstrip("\r")
    if not line.strip() or line.startswith("#"):
        return None
    # Trailing spaces are ignored unless escaped.
    stripped = line.rstrip(" ")
    if line.endswith("\\ "):
        stripped = line[:-1]
    line = stripped
    negate = line.startswith("!")
    if negate:
        line = line[1:]
    elif line.startswith("\\!") or line.startswith("\\#"):
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    if not line:
        return None
    anchored = "/" in line
    line = line.lstrip("/")
    body = _translate(line)
    regex = ("^" if anchored else "^(?:.*/)?") + body + "$"
    return _Rule(re.compile(regex), negate, dir_only, base.strip("/"))


class IgnoreMatcher:
    def __init__(self):
        self._rules: list[_Rule] = []

    def add_patterns(self, lines, base: str = "") -> None:
        for line in lines:
            rule = compile_pattern(line, base)
            if rule is not None:
                self._rules.append(rule)

    def add_file(self, path: str, base: str = "") -> None:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self.add_patterns(fh.read().splitlines(), base)
        except OSError:
            pass

    def is_ignored(self, relpath: str, is_dir: bool) -> bool:
        """``relpath`` is a posix path relative to the scan root."""
        relpath = relpath.strip("/")
        ignored = False
        for rule in self._rules:
            if rule.base:
                prefix = rule.base + "/"
                if not relpath.startswith(prefix):
                    continue
                sub = relpath[len(prefix):]
            else:
                sub = relpath
            if rule.dir_only and not is_dir:
                continue
            if rule.regex.match(sub):
                ignored = not rule.negate
        return ignored
