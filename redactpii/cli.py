"""``redact-pii`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .core import KINDS, find_pii, redact, redaction_report

__version__ = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redact-pii",
        description="Detect and redact personal data in text, logs, and files.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="report what would be redacted")
    scan.add_argument("files", nargs="*", help="files to scan; '-' reads stdin")
    scan.add_argument("--kinds", default="", help="comma-separated subset of: " + ", ".join(KINDS))
    scan.add_argument("--json", action="store_true", help="machine-readable output")
    scan.add_argument("--fail-on-found", action="store_true",
                      help="exit 1 when anything is detected")

    red = sub.add_parser("redact", help="write redacted text")
    red.add_argument("files", nargs="*", help="files to redact; '-' reads stdin")
    red.add_argument("--kinds", default="", help="comma-separated subset of: " + ", ".join(KINDS))
    red.add_argument("--stable", action="store_true",
                     help="give identical values identical tokens")
    red.add_argument("-o", "--output", help="output file (default: stdout)")
    red.add_argument("--fail-on-found", action="store_true",
                     help="exit 1 when anything was redacted")
    return parser


def _kinds(value: str) -> Optional[List[str]]:
    if not value:
        return None
    wanted = [part.strip() for part in value.split(",") if part.strip()]
    unknown = [kind for kind in wanted if kind not in KINDS]
    if unknown:
        raise SystemExit("unknown kind(s): " + ", ".join(unknown))
    return wanted


def _read(files: List[str]) -> List[tuple]:
    if not files:
        return [("<stdin>", sys.stdin.read())]
    documents = []
    for name in files:
        if name == "-":
            documents.append(("<stdin>", sys.stdin.read()))
        else:
            path = Path(name)
            try:
                documents.append((name, path.read_text(encoding="utf-8", errors="replace")))
            except OSError as exc:
                raise SystemExit("cannot read %s: %s" % (name, exc))
    return documents


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    kinds = _kinds(getattr(args, "kinds", ""))

    if args.command == "scan":
        documents = _read(args.files)
        results = []
        found = 0
        for name, text in documents:
            report = redaction_report(text, kinds)
            found += report["total"]
            results.append({"source": name, **report})
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for report in results:
                print("%s: %d finding(s)" % (report["source"], report["total"]))
                for kind, count in sorted(report["counts"].items()):
                    print("  %-6s %d" % (kind, count))
        return 1 if (found and args.fail_on_found) else 0

    documents = _read(args.files)
    rendered = [redact(text, kinds, stable=args.stable) for _, text in documents]
    blocked = sum(len(find_pii(text, kinds)) for _, text in documents)
    output = "\n".join(rendered)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print("wrote %s (%d redaction(s))" % (args.output, blocked), file=sys.stderr)
    else:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")
    return 1 if (blocked and args.fail_on_found) else 0
