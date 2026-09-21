"""End-to-end tests: parse -> analyze -> persist -> export."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from helpers import SAMPLES, event

from loghawk.engine import Engine
from loghawk.models import Alert, EventType, MitreTechnique, Severity
from loghawk.parsers import parse_paths
from loghawk.report import ConsoleReporter, to_csv, to_json, to_markdown
from loghawk.store import AlertStore


def scan_samples():
    events, sources = parse_paths([SAMPLES], year=2026)
    return Engine().analyze(events, sources)


class TestModels(unittest.TestCase):
    def test_severity_thresholds(self):
        self.assertEqual(Severity.from_score(100), Severity.CRITICAL)
        self.assertEqual(Severity.from_score(85), Severity.CRITICAL)
        self.assertEqual(Severity.from_score(84), Severity.HIGH)
        self.assertEqual(Severity.from_score(65), Severity.HIGH)
        self.assertEqual(Severity.from_score(40), Severity.MEDIUM)
        self.assertEqual(Severity.from_score(0), Severity.LOW)

    def test_severity_ordering(self):
        ranks = [s.rank for s in (Severity.LOW, Severity.MEDIUM,
                                  Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(ranks, sorted(ranks))

    def test_score_is_clamped_and_evidence_capped(self):
        e = event(EventType.AUTH_FAILURE, user="x", ip="1.2.3.4")
        alert = Alert(
            rule_id="T", title="t", description="d", severity=Severity.LOW, score=400,
            first_seen=e.timestamp, last_seen=e.timestamp,
            evidence=[f"line {i}" for i in range(20)],
        )
        self.assertEqual(alert.score, 100)
        self.assertEqual(len(alert.evidence), Alert.MAX_EVIDENCE)

    def test_mitre_url_handles_subtechniques(self):
        self.assertTrue(
            MitreTechnique("T1110.001", "x", "y").url.endswith("/T1110/001/")
        )
        self.assertTrue(MitreTechnique("T1078", "x", "y").url.endswith("/T1078/"))

    def test_naive_timestamps_become_utc(self):
        from datetime import datetime
        e = Alert(rule_id="T", title="t", description="d", severity=Severity.LOW,
                  score=1, first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1))
        self.assertEqual(e.duration_seconds, 0.0)


class TestEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan_samples()

    def test_the_full_attack_chain_is_reconstructed(self):
        fired = {a.rule_id for a in self.result.alerts}
        self.assertEqual(
            fired,
            {f"LH-{n:03d}" for n in range(1, 11)},
            f"expected all 10 rules to fire on the sample intrusion, got {sorted(fired)}",
        )

    def test_no_rule_raised_an_exception(self):
        self.assertEqual(self.result.errors, [])

    def test_alerts_are_ranked_by_score(self):
        scores = [a.score for a in self.result.alerts]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_confirmed_compromise_outranks_every_attempt(self):
        self.assertEqual(self.result.alerts[0].rule_id, "LH-004")

    def test_risk_score_is_dominated_by_the_worst_finding(self):
        self.assertGreaterEqual(self.result.risk_score, 90)
        self.assertLessEqual(self.result.risk_score, 100)

    def test_empty_input_produces_an_empty_result(self):
        empty = Engine().analyze([])
        self.assertEqual(empty.alerts, [])
        self.assertEqual(empty.risk_score, 0)
        self.assertEqual(empty.severity_counts["critical"], 0)

    def test_scanning_twice_is_deterministic(self):
        again = scan_samples()
        self.assertEqual(
            [a.fingerprint for a in self.result.alerts],
            [a.fingerprint for a in again.alerts],
        )

    def test_a_broken_rule_does_not_abort_the_scan(self):
        from loghawk.detections.base import BaseDetection

        class Exploding(BaseDetection):
            rule_id = "LH-BOOM"

            def run(self, events):
                raise RuntimeError("detection blew up")

        events, _ = parse_paths([SAMPLES], year=2026)
        result = Engine(detections=[Exploding()]).analyze(events)
        self.assertEqual(result.alerts, [])
        self.assertEqual(len(result.errors), 1)
        self.assertIn("LH-BOOM", result.errors[0])

    def test_filter_by_severity_and_rule(self):
        criticals = self.result.filter(min_severity=Severity.CRITICAL)
        self.assertTrue(all(a.severity == Severity.CRITICAL for a in criticals))
        self.assertTrue(len(criticals) < len(self.result.alerts))
        self.assertTrue(all(a.rule_id == "LH-009"
                            for a in self.result.filter(rule_id="LH-009")))

    def test_top_offenders_ranks_the_attacker_first(self):
        self.assertEqual(self.result.top_offenders[0]["ip"], "45.83.91.22")


class TestReporters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan_samples()

    def test_json_round_trips(self):
        data = json.loads(to_json(self.result))
        self.assertEqual(data["alert_count"], len(self.result.alerts))
        self.assertEqual(len(data["alerts"]), len(self.result.alerts))
        self.assertIn("mitre", data["alerts"][0])

    def test_csv_has_a_header_and_one_row_per_alert(self):
        lines = to_csv(self.result.alerts).strip().splitlines()
        self.assertEqual(len(lines), len(self.result.alerts) + 1)
        self.assertTrue(lines[0].startswith("alert_id,rule_id"))

    def test_markdown_contains_every_finding(self):
        md = to_markdown(self.result)
        self.assertIn("# LogHawk detection report", md)
        for alert in self.result.alerts:
            self.assertIn(alert.rule_id, md)

    def test_console_output_is_plain_when_colour_is_off(self):
        text = ConsoleReporter(color=False).render(self.result, verbose=True)
        self.assertNotIn("\033[", text)
        self.assertIn("SCAN SUMMARY", text)

    def test_console_handles_zero_alerts(self):
        text = ConsoleReporter(color=False).render(Engine().analyze([]))
        self.assertIn("No detections fired", text)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        self.store = AlertStore(self.db)
        self.result = scan_samples()

    def tearDown(self):
        if os.path.exists(self.db):
            os.remove(self.db)

    def test_save_and_count(self):
        self.store.save_scan(self.result)
        self.assertEqual(self.store.stats()["total_alerts"], len(self.result.alerts))

    def test_rescanning_does_not_duplicate_alerts(self):
        self.store.save_scan(self.result)
        self.store.save_scan(self.result)
        self.store.save_scan(scan_samples())
        self.assertEqual(self.store.stats()["total_alerts"], len(self.result.alerts))

    def test_triage_status_survives_a_rescan(self):
        self.store.save_scan(self.result)
        alert_id = self.store.query_alerts(limit=1)[0]["id"]
        self.assertTrue(self.store.set_status(alert_id, "escalated", "confirmed"))
        self.store.save_scan(scan_samples())
        row = self.store.get_alert(alert_id)
        self.assertEqual(row["status"], "escalated")
        self.assertEqual(row["notes"], "confirmed")

    def test_unknown_alert_id_returns_false(self):
        self.store.save_scan(self.result)
        self.assertFalse(self.store.set_status("deadbeefdeadbeef", "resolved"))
        self.assertIsNone(self.store.get_alert("deadbeefdeadbeef"))

    def test_invalid_status_is_rejected(self):
        self.store.save_scan(self.result)
        alert_id = self.store.query_alerts(limit=1)[0]["id"]
        with self.assertRaises(ValueError):
            self.store.set_status(alert_id, "not-a-status")

    def test_filters(self):
        self.store.save_scan(self.result)
        criticals = self.store.query_alerts(min_severity=Severity.CRITICAL)
        self.assertTrue(all(r["severity"] == "critical" for r in criticals))
        by_rule = self.store.query_alerts(rule_id="LH-004")
        self.assertEqual(len(by_rule), 1)
        by_ip = self.store.query_alerts(src_ip="45.83.91.22")
        self.assertTrue(all(r["src_ip"] == "45.83.91.22" for r in by_ip))

    def test_pagination(self):
        self.store.save_scan(self.result)
        page1 = self.store.query_alerts(limit=5, offset=0)
        page2 = self.store.query_alerts(limit=5, offset=5)
        self.assertEqual(len(page1), 5)
        self.assertTrue(set(r["id"] for r in page1).isdisjoint(r["id"] for r in page2))

    def test_json_columns_are_decoded(self):
        self.store.save_scan(self.result)
        row = self.store.query_alerts(rule_id="LH-004")[0]
        self.assertIsInstance(row["evidence"], list)
        self.assertIsInstance(row["mitre"], list)
        self.assertIsInstance(row["context"], dict)

    def test_stats_shape(self):
        self.store.save_scan(self.result)
        stats = self.store.stats()
        self.assertEqual(len(stats["by_rule"]), 10)  # one entry per rule, not per variant
        self.assertIsNotNone(stats["last_scan"])
        self.assertEqual(stats["last_scan"]["event_count"], self.result.event_count)


if __name__ == "__main__":
    unittest.main(verbosity=2)
