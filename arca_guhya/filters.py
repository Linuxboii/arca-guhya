"""Allowlist and baseline handling."""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import re
from dataclasses import dataclass, field

from . import __version__
from .scanner import Finding

DEFAULT_ALLOWLIST = ".arca-allowlist"


@dataclass
class Allowlist:
    """Suppression entries, one per line::

        # comment
        rule:stripe-test-key        suppress a rule everywhere
        path:tests/fixtures/*       glob on the relative path (bare lines are paths too)
        regex:^AKIAIOSFODNN7        regex searched in the secret value
        fingerprint:3f2a9c0d1e...   one specific finding
    """

    entries: list[tuple[str, object]] = field(default_factory=list)

    @classmethod
    def parse(cls, lines) -> "Allowlist":
        entries: list[tuple[str, object]] = []
        for lineno, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, sep, value = line.partition(":")
            kind = kind.strip().lower()
            if not sep or kind not in ("rule", "path", "regex", "fingerprint"):
                kind, value = "path", line
            value = value.strip()
            if kind == "regex":
                try:
                    entries.append((kind, re.compile(value)))
                except re.error as exc:
                    raise ValueError(f"allowlist line {lineno}: invalid regex {value!r}: {exc}") from None
            else:
                entries.append((kind, value))
        return cls(entries)

    @classmethod
    def load(cls, path: str) -> "Allowlist":
        with open(path, encoding="utf-8") as fh:
            return cls.parse(fh.read().splitlines())

    def matches(self, finding: Finding) -> bool:
        for kind, value in self.entries:
            if kind == "rule" and finding.rule_id == value:
                return True
            if kind == "fingerprint" and finding.fingerprint == value:
                return True
            if kind == "regex" and value.search(finding.secret):
                return True
            if kind == "path" and (fnmatch.fnmatch(finding.path, value)
                                   or finding.path.startswith(value.rstrip("/") + "/")):
                return True
        return False


def write_baseline(path: str, findings: list[Finding]) -> None:
    """Record current findings (fingerprints only - never secret values)."""
    data = {
        "tool": "arca-guhya",
        "version": __version__,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": sorted(
            ({"fingerprint": f.fingerprint, "rule": f.rule_id, "path": f.path} for f in findings),
            key=lambda d: (d["path"], d["rule"], d["fingerprint"]),
        ),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def load_baseline(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "findings" in data:
        return {item["fingerprint"] for item in data["findings"]}
    if isinstance(data, list):
        return {item if isinstance(item, str) else item["fingerprint"] for item in data}
    raise ValueError(f"{path}: not an arca-guhya baseline file")


def apply_filters(findings: list[Finding], allowlist: Allowlist, baseline: set[str] | None = None):
    """Return ``(kept, counts)`` where counts has 'allowlist' and 'baseline'."""
    baseline = baseline or set()
    kept: list[Finding] = []
    counts = {"allowlist": 0, "baseline": 0}
    for f in findings:
        if f.fingerprint in baseline:
            counts["baseline"] += 1
        elif allowlist.matches(f):
            counts["allowlist"] += 1
        else:
            kept.append(f)
    return kept, counts
