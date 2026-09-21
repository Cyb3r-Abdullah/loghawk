"""Command-line interface. ``python -m loghawk --help``"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .detections import DetectionConfig, build_detections, rule_catalog
from .engine import Engine
from .models import Severity
from .parsers import available_parsers, parse_paths
from .report import ConsoleReporter, to_csv, to_json, to_markdown

DEFAULT_DB = "loghawk.db"
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loghawk",
        description="LogHawk - blue-team log analysis and detection engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  loghawk demo\n"
            "  loghawk scan /var/log/auth.log --verbose\n"
            "  loghawk scan ./logs --min-severity high --format markdown -o incident.md\n"
            "  loghawk scan ./logs --db loghawk.db && loghawk serve\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"LogHawk {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyze log files or directories")
    scan.add_argument("paths", nargs="+", help="log files and/or directories")
    scan.add_argument("--format", choices=("console", "json", "csv", "markdown"),
                      default="console", help="output format (default: console)")
    scan.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    scan.add_argument("--min-severity", choices=[s.value for s in Severity],
                      help="hide alerts below this severity")
    scan.add_argument("--rule", help="only run/report a single rule id, e.g. LH-004")
    scan.add_argument("--disable", action="append", default=[],
                      metavar="RULE_ID", help="disable a rule (repeatable)")
    scan.add_argument("--year", type=int, default=None,
                      help="year for syslog timestamps (default: current year)")
    scan.add_argument("--db", nargs="?", const=DEFAULT_DB, default=None,
                      help=f"persist results to SQLite (default file: {DEFAULT_DB})")
    scan.add_argument("-v", "--verbose", action="store_true",
                      help="include evidence lines and recommended actions")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    scan.add_argument("--fail-on", choices=[s.value for s in Severity],
                      help="exit non-zero if any alert reaches this severity (for CI)")

    demo = sub.add_parser("demo", help="regenerate the bundled sample logs and scan them")
    demo.add_argument("-v", "--verbose", action="store_true")
    demo.add_argument("--db", nargs="?", const=DEFAULT_DB, default=None)

    rules = sub.add_parser("rules", help="list the detection catalog")
    rules.add_argument("--json", action="store_true", help="emit the catalog as JSON")

    serve = sub.add_parser("serve", help="run the FastAPI dashboard and REST API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--db", default=DEFAULT_DB)
    serve.add_argument("--reload", action="store_true", help="auto-reload on code changes")

    return parser


def _severity(value: str | None) -> Severity | None:
    return Severity(value) if value else None


def cmd_scan(args: argparse.Namespace) -> int:
    year = args.year or datetime.now(timezone.utc).year
    events, sources = parse_paths(args.paths, year=year)
    if not events:
        print("No parsable log events found. Supported formats:", file=sys.stderr)
        for parser in available_parsers():
            print(f"  - {parser.name}: {parser.description}", file=sys.stderr)
        return 2

    config = DetectionConfig()
    detections = build_detections(
        config,
        enabled=[args.rule] if getattr(args, "rule", None) else None,
        disabled=args.disable,
    )
    if not detections:
        print(f"No rules selected (check --rule / --disable).", file=sys.stderr)
        return 2

    result = Engine(config, detections).analyze(events, sources)

    min_sev = _severity(args.min_severity)
    if min_sev:
        result.alerts = result.filter(min_severity=min_sev)

    if args.format == "console":
        # None lets ConsoleReporter auto-detect a TTY, so piping to a file or
        # to `less` yields clean text without the caller passing --no-color.
        color = False if (args.no_color or args.output) else None
        output = ConsoleReporter(color=color).render(result, verbose=args.verbose)
    elif args.format == "json":
        output = to_json(result)
    elif args.format == "csv":
        output = to_csv(result.alerts)
    else:
        output = to_markdown(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Report written to {args.output} "
              f"({len(result.alerts)} alerts, risk {result.risk_score}/100)")
    else:
        sys.stdout.write(output)

    if args.db:
        from .store import AlertStore  # imported lazily: scanning alone needs no DB

        scan_id = AlertStore(args.db).save_scan(result)
        print(f"Saved scan #{scan_id} to {args.db}", file=sys.stderr)

    if args.fail_on:
        threshold = Severity(args.fail_on)
        if any(a.severity.rank >= threshold.rank for a in result.alerts):
            return 1
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    generator = os.path.join(SAMPLES_DIR, "generate_samples.py")
    if os.path.exists(generator):
        sys.path.insert(0, SAMPLES_DIR)
        import generate_samples  # type: ignore[import-not-found]

        generate_samples.main()
        print()

    scan_args = argparse.Namespace(
        paths=[SAMPLES_DIR], format="console", output=None, min_severity=None,
        rule=None, disable=[], year=2026, db=args.db, verbose=args.verbose,
        no_color=False, fail_on=None,
    )
    return cmd_scan(scan_args)


def cmd_rules(args: argparse.Namespace) -> int:
    catalog = rule_catalog()
    if args.json:
        print(json.dumps(catalog, indent=2))
        return 0

    print(f"\nLogHawk detection catalog - {len(catalog)} rules\n")
    for rule in catalog:
        techniques = ", ".join(f"{m['id']} ({m['tactic']})" for m in rule["mitre"])
        print(f"  {rule['rule_id']}  {rule['title']}")
        print(f"      severity : {rule['default_severity']} (base score {rule['base_score']})")
        print(f"      ATT&CK   : {techniques}")
        print(f"      {rule['description']}")
        print()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    # Check every import the API needs, not just one: uvicorn alone is often
    # present without fastapi, and letting uvicorn discover that itself
    # produces a stack trace instead of an actionable message.
    missing = []
    for module in ("fastapi", "uvicorn"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        print(
            f"The dashboard needs {' and '.join(missing)}, which "
            f"{'is' if len(missing) == 1 else 'are'} not installed.\n"
            "Install them with:  pip install -r requirements.txt\n"
            "Every other command (scan, demo, rules) works without them.",
            file=sys.stderr,
        )
        return 2

    os.environ["LOGHAWK_DB"] = args.db
    import uvicorn

    print(f"LogHawk dashboard -> http://{args.host}:{args.port}")
    print(f"API docs          -> http://{args.host}:{args.port}/docs")
    uvicorn.run("loghawk.api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


COMMANDS = {"scan": cmd_scan, "demo": cmd_demo, "rules": cmd_rules, "serve": cmd_serve}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except FileNotFoundError as exc:
        print(f"File not found: {exc.filename}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
