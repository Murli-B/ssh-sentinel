"""Command-line interface for SSH Sentinel."""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from . import __version__
from .detector import analyze, read_events


def _color(text: str, code: str) -> str:
    """Use ANSI color only in an interactive terminal and unless disabled."""
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return text
    return f"\033[{code}m{text}\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-sentinel",
        description="Offline, read-only detection of repeated SSH login failures.",
        epilog="This analyzes a log file; it does not monitor continuously or block traffic.",
    )
    parser.add_argument("logfile", type=Path, help="SSH auth log file to inspect")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="failed attempts from one IP that trigger a medium alert (default: 5)",
    )
    parser.add_argument(
        "--success-after",
        type=int,
        default=3,
        help="failures before a later successful login is high severity (default: 3)",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="rolling detection window in minutes (default: 10)",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="year for classic syslog timestamps that omit the year",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.threshold < 1 or args.success_after < 1 or args.window_minutes < 1:
        parser.error("threshold, success-after, and window-minutes must be at least 1")

    try:
        events, line_count, skipped_timestamps = read_events(args.logfile, args.year)
    except OSError as error:
        print(f"Error: cannot read {args.logfile}: {error}", file=sys.stderr)
        return 2

    failure_count = sum(event.kind == "failed" for event in events)
    success_count = sum(event.kind == "success" for event in events)
    window = timedelta(minutes=args.window_minutes)
    alerts = analyze(
        events,
        threshold=args.threshold,
        success_after_threshold=args.success_after,
        window=window,
    )

    print(_color("SSH SENTINEL  /  LOCAL SSH LOG TRIAGE", "1;36"))
    print(_color("Offline  •  Read-only  •  No runtime dependencies", "2"))
    print(f"Log: {args.logfile}")
    print(
        f"Scanned {line_count} lines; parsed {failure_count} failed and "
        f"{success_count} successful SSH login events."
    )
    print(
        f"Rule: {args.threshold}+ failures from one IP in {args.window_minutes} min; "
        f"HIGH if a success follows {args.success_after}+ failures."
    )

    if alerts:
        print("\nAlerts:")
        for alert in alerts:
            color_code = "1;31" if alert.startswith("HIGH") else "1;33"
            print(f"- {_color(alert, color_code)}")
    elif events:
        print(_color("\nNo alert matched these rules in the parsed events.", "1;32"))
    else:
        print(
            "\nNo recognizable SSH login events were found. Check that this is an "
            "OpenSSH auth log with timestamps supported by this tool."
        )

    if skipped_timestamps:
        print(
            f"\nNote: skipped {skipped_timestamps} matching SSH event(s) with "
            "unrecognized timestamps. Expected Linux syslog or ISO timestamps."
        )
    print("\nReview alerts in context. This tool does not block traffic and can miss threats.")
    return 0
