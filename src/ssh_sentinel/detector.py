"""Core, offline SSH authentication log analysis."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Examples: "Oct  2 10:01:11" (traditional syslog) and
# "2026-10-02T10:01:11+05:30" (journal/export timestamp).
SYSLOG_TIME_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\b"
)
ISO_TIME_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
)
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)(?=\s|$)"
FAILED_RE = re.compile(
    r"\bFailed\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+" + _IP,
    re.IGNORECASE,
)
SUCCESS_RE = re.compile(
    r"\bAccepted\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?P<user>\S+)\s+from\s+" + _IP,
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AuthEvent:
    """One parsed SSH authentication event."""

    timestamp: datetime
    kind: str  # "failed" or "success"
    ip: str
    user: str
    line_number: int


def parse_timestamp(line: str, year: int) -> datetime | None:
    """Parse an ISO or classic syslog timestamp into a comparable datetime.

    Classic syslog timestamps have no year, so ``year`` is supplied by the
    caller. ISO timestamps with an offset are normalized to UTC.
    """
    match = ISO_TIME_RE.match(line)
    if match:
        raw = match.group("timestamp").replace("Z", "+00:00")
        try:
            value = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    match = SYSLOG_TIME_RE.match(line)
    if not match:
        return None
    raw = f"{year} {match.group('month')} {match.group('day')} {match.group('clock')}"
    try:
        return datetime.strptime(raw, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _canonical_ip(raw_ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return None


def read_events(path: Path, year: int) -> tuple[list[AuthEvent], int, int]:
    """Read recognizable OpenSSH events from a local log file.

    Returns ``(events, total_lines, matching_events_with_unparsed_timestamps)``.
    The log is only read; this function performs no network or system actions.
    """
    events: list[AuthEvent] = []
    total_lines = 0
    skipped_timestamps = 0

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            total_lines += 1
            if "sshd" not in line.lower():
                continue

            match = FAILED_RE.search(line)
            kind = "failed"
            if match is None:
                match = SUCCESS_RE.search(line)
                kind = "success"
            if match is None:
                continue

            timestamp = parse_timestamp(line, year)
            ip = _canonical_ip(match.group("ip"))
            if ip is None:
                continue
            if timestamp is None:
                skipped_timestamps += 1
                continue

            events.append(
                AuthEvent(
                    timestamp=timestamp,
                    kind=kind,
                    ip=ip,
                    user=match.group("user"),
                    line_number=line_number,
                )
            )

    return events, total_lines, skipped_timestamps


def largest_failure_burst(failures: list[AuthEvent], window: timedelta) -> int:
    """Return the largest count of failures in any rolling time window."""
    timestamps = sorted(event.timestamp for event in failures)
    left = 0
    largest = 0
    for right, timestamp in enumerate(timestamps):
        while timestamp - timestamps[left] > window:
            left += 1
        largest = max(largest, right - left + 1)
    return largest


def success_after_repeated_failures(
    failures: list[AuthEvent],
    successes: list[AuthEvent],
    minimum_failures: int,
    window: timedelta,
) -> tuple[AuthEvent, int] | None:
    """Find a successful login preceded by repeated failures from the same IP."""
    failure_times = sorted(event.timestamp for event in failures)
    for success in sorted(successes, key=lambda event: event.timestamp):
        recent_count = sum(
            1
            for timestamp in failure_times
            if success.timestamp - window <= timestamp <= success.timestamp
        )
        if recent_count >= minimum_failures:
            return success, recent_count
    return None


def analyze(
    events: list[AuthEvent],
    threshold: int = 5,
    success_after_threshold: int = 3,
    window: timedelta = timedelta(minutes=10),
) -> list[str]:
    """Create human-readable alerts using simple per-IP rolling-window rules."""
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    alerts: list[str] = []
    window_minutes = int(window.total_seconds() // 60)
    for ip in sorted(by_ip):
        ip_events = by_ip[ip]
        failures = [event for event in ip_events if event.kind == "failed"]
        successes = [event for event in ip_events if event.kind == "success"]
        if not failures:
            continue

        burst = largest_failure_burst(failures, window)
        successful_after_failures = success_after_repeated_failures(
            failures, successes, success_after_threshold, window
        )

        if successful_after_failures is not None:
            event, count = successful_after_failures
            alerts.append(
                f"HIGH   {ip} — successful SSH login for '{event.user}' after "
                f"{count} failed attempts within {window_minutes} min "
                f"(at {event.timestamp:%Y-%m-%d %H:%M:%S})."
            )
        elif burst >= threshold:
            alerts.append(
                f"MEDIUM {ip} — {burst} failed SSH login attempts within a "
                f"{window_minutes} min window."
            )

    return alerts
