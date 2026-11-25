"""Command-line interface for arca-guhya."""

from __future__ import annotations

import argparse
import dataclasses
import os
import sys

from . import __version__
from .colors import Painter, should_color
from .filters import DEFAULT_ALLOWLIST, Allowlist, apply_filters, load_baseline, write_baseline
from .report import to_json, to_sarif, to_text
from .rules import ALL_RULES, SEVERITIES, severity_rank
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="arca-guhya",
        description="Scan a directory or file for leaked secrets (API keys, tokens, private keys, "
                    "high-entropy strings). Secrets are always masked in output.",
    )
    p.add_argument("path", nargs="?", default=".", help="directory or file to scan (default: current directory)")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="output format (default text)")
    p.add_argument("--json", action="store_true", help="shorthand for --format json")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--allowlist", metavar="FILE",
                   help=f"allowlist file (default: <path>/{DEFAULT_ALLOWLIST} if present)")
    p.add_argument("--baseline", metavar="FILE", help="suppress findings recorded in this baseline file")
    p.add_argument("--write-baseline", metavar="FILE",
                   help="record all current findings to FILE (accepting them) and exit 0")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low", help="only report this severity and above")
    p.add_argument("--no-gitignore", action="store_true", help="do not honour .gitignore files")
    p.add_argument("--no-entropy", action="store_true", help="disable the generic high-entropy string detector")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="extra gitignore-style pattern to skip (repeatable)")
    p.add_argument("--max-size", type=int, default=1024, metavar="KB", help="skip files larger than this (default 1024 KB)")
    p.add_argument("--list-rules", action="store_true", help="list detection rules and exit")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fmt = "json" if args.json else args.format
    to_file = args.output is not None
    paint = Painter(not to_file and not args.no_color and should_color(sys.stdout))

    if args.list_rules:
        for r in ALL_RULES:
            print(f"{r.id:<24} {r.severity:<9} {r.description}")
        return 0

    if not os.path.exists(args.path):
        print(f"arca-guhya: error: path not found: {args.path}", file=sys.stderr)
        return 2

    try:
        allowlist = Allowlist()
        if args.allowlist:
            allowlist = Allowlist.load(args.allowlist)
        elif os.path.isdir(args.path) and os.path.isfile(os.path.join(args.path, DEFAULT_ALLOWLIST)):
            allowlist = Allowlist.load(os.path.join(args.path, DEFAULT_ALLOWLIST))
        baseline = load_baseline(args.baseline) if args.baseline else set()
    except (OSError, ValueError) as exc:
        print(f"arca-guhya: error: {exc}", file=sys.stderr)
        return 2

    findings, stats = scan_path(
        args.path,
        use_gitignore=not args.no_gitignore,
        entropy=not args.no_entropy,
        max_bytes=args.max_size * 1024,
        excludes=args.exclude,
    )
    floor = severity_rank(args.min_severity)
    findings = [f for f in findings if severity_rank(f.severity) >= floor]

    if args.write_baseline:
        kept, _ = apply_filters(findings, allowlist, set())
        write_baseline(args.write_baseline, kept)
        print(f"arca-guhya: wrote {len(kept)} finding(s) to baseline {args.write_baseline}", file=sys.stderr)
        return 0

    kept, suppressed = apply_filters(findings, allowlist, baseline)

    if fmt == "json":
        stats_dict = dataclasses.asdict(stats)
        stats_dict["skipped"] = [{"path": p, "reason": r} for p, r in stats.skipped]
        stats_dict["suppressed"] = suppressed
        output = to_json(kept, stats_dict)
    elif fmt == "sarif":
        output = to_sarif(kept)
    else:
        output = to_text(kept, paint, stats, suppressed)

    if to_file:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)
    return 1 if kept else 0
