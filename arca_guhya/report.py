"""Output formats: plain text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .colors import Painter
from .rules import ALL_RULES, SEVERITIES, rule_by_id
from .scanner import Finding

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SEVERITY_COLOR = {"critical": ("red", "bold"), "high": ("red",), "medium": ("yellow",), "low": ("cyan",)}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def summarise(findings: list[Finding]) -> dict:
    counts = Counter(f.severity for f in findings)
    return {"total": len(findings), **{s: counts.get(s, 0) for s in reversed(SEVERITIES)}}


def to_json(findings: list[Finding], stats: dict | None = None) -> str:
    return json.dumps({
        "tool": "arca-guhya",
        "version": __version__,
        "summary": summarise(findings),
        "stats": stats or {},
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    rule_ids = [r.id for r in ALL_RULES]
    rules = []
    for rid in rule_ids:
        r = rule_by_id(rid)
        rules.append({
            "id": r.id,
            "name": "".join(part.capitalize() for part in r.id.split("-")),
            "shortDescription": {"text": r.description},
            "fullDescription": {"text": f"{r.description} detected in source. Rotate the credential and remove it from history."},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security", "secrets"], "security-severity": SECURITY_SEVERITY[r.severity]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_ids.index(f.rule_id),
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.description}: {f.masked}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line, "startColumn": f.column,
                               "endColumn": f.column + len(f.secret)},
                }
            }],
            "partialFingerprints": {"arcaGuhya/v1": f.fingerprint},
            "properties": {"severity": f.severity},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "arca-guhya",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_text(findings: list[Finding], paint: Painter, stats=None, suppressed=None) -> str:
    lines = []
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    for f in sorted(findings, key=lambda x: (order[x.severity], x.path, x.line)):
        sev = paint(f"{f.severity.upper():<8}", *SEVERITY_COLOR[f.severity])
        loc = paint(f"{f.path}:{f.line}:{f.column}", "bold")
        lines.append(f"{sev}  {f.rule_id:<22} {loc}")
        detail = f.description
        if f.entropy is not None:
            detail += f" (entropy {f.entropy:.2f} bits/char)"
        lines.append(f"          {detail}")
        lines.append(f"          {paint(f.snippet, 'dim')}")
        lines.append(f"          {paint('fingerprint ' + f.fingerprint, 'grey')}")
    if lines:
        lines.append("")
    summary = summarise(findings)
    parts = [f"{summary[s]} {s}" for s in reversed(SEVERITIES) if summary[s]]
    head = f"{summary['total']} finding(s)" + (": " + ", ".join(parts) if parts else "")
    if summary["total"]:
        head = paint(head, "bold", "red")
    else:
        head = paint(head, "bold", "green")
    tail = []
    if stats is not None:
        tail.append(f"scanned {stats.files_scanned} file(s), skipped {stats.files_skipped}")
    if suppressed:
        if suppressed.get("baseline"):
            tail.append(f"{suppressed['baseline']} suppressed by baseline")
        if suppressed.get("allowlist"):
            tail.append(f"{suppressed['allowlist']} allowlisted")
    lines.append(head + (paint("  (" + "; ".join(tail) + ")", "dim") if tail else ""))
    return "\n".join(lines)
