from __future__ import annotations

import unittest
from datetime import datetime, timedelta
from pathlib import Path

from ssh_sentinel.detector import AuthEvent, analyze, parse_timestamp, read_events


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOG = ROOT / "examples" / "sample_auth.log"


class DetectorTests(unittest.TestCase):
    def make_events(self, failure_count: int, with_success: bool = False) -> list[AuthEvent]:
        start = datetime(2026, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=start + timedelta(minutes=index),
                kind="failed",
                ip="192.0.2.44",
                user="admin",
                line_number=index + 1,
            )
            for index in range(failure_count)
        ]
        if with_success:
            events.append(
                AuthEvent(
                    timestamp=start + timedelta(minutes=failure_count),
                    kind="success",
                    ip="192.0.2.44",
                    user="admin",
                    line_number=failure_count + 1,
                )
            )
        return events

    def test_demo_log_parses_and_triggers_high_alert(self) -> None:
        events, line_count, skipped = read_events(SAMPLE_LOG, year=2026)
        self.assertEqual(line_count, 7)
        self.assertEqual(skipped, 0)
        self.assertEqual(sum(event.kind == "failed" for event in events), 6)
        self.assertEqual(sum(event.kind == "success" for event in events), 1)

        alerts = analyze(events)
        self.assertEqual(len(alerts), 1)
        self.assertIn("HIGH", alerts[0])
        self.assertIn("203.0.113.10", alerts[0])

    def test_failure_burst_triggers_medium_alert(self) -> None:
        alerts = analyze(self.make_events(5), threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].startswith("MEDIUM"))

    def test_success_after_repeated_failures_triggers_high_alert(self) -> None:
        alerts = analyze(self.make_events(3, with_success=True), threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].startswith("HIGH"))

    def test_below_threshold_without_success_has_no_alert(self) -> None:
        self.assertEqual(analyze(self.make_events(4), threshold=5), [])

    def test_syslog_timestamp_uses_supplied_year(self) -> None:
        parsed = parse_timestamp("Oct  2 10:01:11 host sshd[10]: Failed password", 2026)
        self.assertEqual(parsed, datetime(2026, 10, 2, 10, 1, 11))

    def test_iso_timestamp_normalizes_offset_to_utc(self) -> None:
        parsed = parse_timestamp("2026-10-02T10:00:00+05:30 host sshd[10]: Accepted", 2026)
        self.assertEqual(parsed, datetime(2026, 10, 2, 4, 30, 0))


if __name__ == "__main__":
    unittest.main()
