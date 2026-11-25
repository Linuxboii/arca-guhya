"""Scan text and directory trees for secrets."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from .entropy import is_hex, looks_random, shannon_entropy
from .ignore import IgnoreMatcher
from .masking import mask
from .rules import ENTROPY_RULE, RULES, SECRET_KEYWORDS, Rule

INLINE_ALLOW_MARKERS = ("arca:allow", "arca-guhya:allow")

DEFAULT_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
                     ".mypy_cache", ".pytest_cache", ".tox"}
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".psd",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".pyc", ".pyo", ".whl",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav",
    ".ogg", ".webm", ".sqlite", ".db",
}
# Files full of hashes: regex rules still run, the entropy heuristic does not.
NO_ENTROPY_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
                    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "uv.lock"}
NO_ENTROPY_SUFFIXES = (".min.js", ".min.css", ".map", ".svg")


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    path: str
    line: int
    column: int
    secret: str
    snippet: str
    fingerprint: str
    entropy: float | None = None
    redact: bool = True

    @property
    def masked(self) -> str:
        return mask(self.secret) if self.redact else self.secret

    def to_dict(self) -> dict:
        data = {
            "rule": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "secret": self.masked,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
        }
        if self.entropy is not None:
            data["entropy"] = round(self.entropy, 3)
        return data


def fingerprint(rule_id: str, path: str, secret: str) -> str:
    """Stable ID that survives the secret moving to another line."""
    return hashlib.sha256(f"{rule_id}\0{path}\0{secret}".encode("utf-8", "replace")).hexdigest()[:16]


def _snippet(line: str, secrets: list[str], limit: int = 160) -> str:
    text = line.strip()
    for s in secrets:
        text = text.replace(s, mask(s))
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def scan_text(text: str, path: str, rules: list[Rule] | None = None, entropy: bool = True) -> list[Finding]:
    """Return findings for ``text`` attributed to ``path`` (posix, relative)."""
    rules = RULES if rules is None else rules
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if any(marker in line for marker in INLINE_ALLOW_MARKERS):
            continue
        spans: list[tuple[int, int]] = []
        line_hits: list[tuple[Rule, int, str, float | None]] = []
        for rule in rules:
            for m in rule.pattern.finditer(line):
                group = 1 if m.re.groups else 0
                secret = m.group(group)
                start = m.start(group)
                end = m.end(group)
                if any(s < end and start < e for s, e in spans):
                    continue
                spans.append((start, end))
                line_hits.append((rule, start, secret, None))
        if entropy:
            keyword = bool(SECRET_KEYWORDS.search(line))
            for m in ENTROPY_RULE.pattern.finditer(line):
                candidate = m.group(1)
                start, end = m.start(1), m.end(1)
                if any(s < end and start < e for s, e in spans):
                    continue
                if is_hex(candidate) and not keyword:
                    continue  # bare hex is usually a hash/commit id
                if not looks_random(candidate):
                    continue
                spans.append((start, end))
                line_hits.append((ENTROPY_RULE, start, candidate, shannon_entropy(candidate)))
        if not line_hits:
            continue
        redactable = [secret for rule, _, secret, _ in line_hits if rule.redact]
        snippet = _snippet(line, redactable)
        for rule, start, secret, ent in sorted(line_hits, key=lambda h: h[1]):
            findings.append(Finding(
                rule_id=rule.id,
                description=rule.description,
                severity=rule.severity,
                path=path,
                line=lineno,
                column=start + 1,
                secret=secret,
                snippet=snippet,
                fingerprint=fingerprint(rule.id, path, secret),
                entropy=ent,
                redact=rule.redact,
            ))
    return findings


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)


def _is_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def iter_files(root: str, use_gitignore: bool = True, extra_excludes: list[str] | None = None,
               stats: ScanStats | None = None):
    """Yield ``(abs_path, rel_posix_path)`` for files under ``root``."""
    stats = stats if stats is not None else ScanStats()
    matcher = IgnoreMatcher()
    if extra_excludes:
        matcher.add_patterns(extra_excludes, base="")
    root = os.path.abspath(root)
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        if use_gitignore and ".gitignore" in filenames:
            matcher.add_file(os.path.join(dirpath, ".gitignore"), base=rel_dir)
        keep = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if d in DEFAULT_SKIP_DIRS or matcher.is_ignored(rel, True):
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if matcher.is_ignored(rel, False):
                stats.files_skipped += 1
                stats.skipped.append((rel, "ignored"))
                continue
            yield os.path.join(dirpath, name), rel


def scan_path(root: str, use_gitignore: bool = True, entropy: bool = True, max_bytes: int = 1_048_576,
              excludes: list[str] | None = None, rules: list[Rule] | None = None):
    """Scan a file or directory. Returns ``(findings, stats)``."""
    stats = ScanStats()
    findings: list[Finding] = []
    for abs_path, rel in iter_files(root, use_gitignore, excludes, stats):
        name = os.path.basename(rel)
        ext = os.path.splitext(name)[1].lower()
        if ext in BINARY_EXTENSIONS:
            stats.files_skipped += 1
            stats.skipped.append((rel, "binary extension"))
            continue
        try:
            size = os.path.getsize(abs_path)
            if size > max_bytes:
                stats.files_skipped += 1
                stats.skipped.append((rel, f"larger than {max_bytes} bytes"))
                continue
            with open(abs_path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            stats.files_skipped += 1
            stats.skipped.append((rel, f"unreadable: {exc.strerror or exc}"))
            continue
        if _is_binary(data[:8192]):
            stats.files_skipped += 1
            stats.skipped.append((rel, "binary content"))
            continue
        text = data.decode("utf-8", errors="replace")
        use_entropy = entropy and name not in NO_ENTROPY_FILES and not name.endswith(NO_ENTROPY_SUFFIXES)
        stats.files_scanned += 1
        stats.bytes_scanned += len(data)
        findings.extend(scan_text(text, rel, rules=rules, entropy=use_entropy))
    return findings, stats
