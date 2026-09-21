"""CLI tests: exit codes, output formats, and rule selection."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from helpers import SAMPLES

from loghawk.cli import main


def run(*argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCLI(unittest.TestCase):
    def test_rules_listing(self):
        code, out, _ = run("rules")
        self.assertEqual(code, 0)
        self.assertIn("10 rules", out)
        for n in range(1, 11):
            self.assertIn(f"LH-{n:03d}", out)

    def test_rules_json_is_valid(self):
        code, out, _ = run("rules", "--json")
        catalog = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(len(catalog), 10)
        self.assertIn("mitre", catalog[0])

    def test_scan_console(self):
        code, out, _ = run("scan", SAMPLES, "--year", "2026", "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("SCAN SUMMARY", out)
        self.assertIn("LH-004", out)
        self.assertNotIn("\033[", out)

    def test_scan_json_output_parses(self):
        code, out, _ = run("scan", SAMPLES, "--year", "2026", "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["alert_count"], len(data["alerts"]))
        self.assertGreater(data["event_count"], 100)

    def test_min_severity_filters(self):
        _, all_out, _ = run("scan", SAMPLES, "--year", "2026", "--format", "json")
        _, crit_out, _ = run("scan", SAMPLES, "--year", "2026", "--format", "json",
                             "--min-severity", "critical")
        total = json.loads(all_out)["alert_count"]
        crit = json.loads(crit_out)["alert_count"]
        self.assertLess(crit, total)
        self.assertTrue(all(a["severity"] == "critical"
                            for a in json.loads(crit_out)["alerts"]))

    def test_single_rule_selection(self):
        _, out, _ = run("scan", SAMPLES, "--year", "2026", "--format", "json",
                        "--rule", "LH-004")
        alerts = json.loads(out)["alerts"]
        self.assertEqual({a["rule_id"] for a in alerts}, {"LH-004"})

    def test_disable_flag(self):
        _, out, _ = run("scan", SAMPLES, "--year", "2026", "--format", "json",
                        "--disable", "LH-009", "--disable", "LH-010")
        rules = {a["rule_id"] for a in json.loads(out)["alerts"]}
        self.assertNotIn("LH-009", rules)
        self.assertNotIn("LH-010", rules)

    def test_output_file_is_written(self):
        path = tempfile.mktemp(suffix=".md")
        try:
            code, out, _ = run("scan", SAMPLES, "--year", "2026",
                               "--format", "markdown", "-o", path)
            self.assertEqual(code, 0)
            self.assertIn("Report written to", out)
            with open(path, encoding="utf-8") as fh:
                self.assertIn("# LogHawk detection report", fh.read())
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_fail_on_gives_a_ci_friendly_exit_code(self):
        code, _, _ = run("scan", SAMPLES, "--year", "2026", "--format", "csv",
                         "--fail-on", "critical")
        self.assertEqual(code, 1)
        code, _, _ = run("scan", SAMPLES, "--year", "2026", "--format", "csv",
                         "--rule", "LH-006", "--fail-on", "critical")
        self.assertEqual(code, 0)

    def test_unparsable_path_exits_two(self):
        empty = tempfile.mkdtemp()
        try:
            code, _, err = run("scan", empty)
            self.assertEqual(code, 2)
            self.assertIn("No parsable log events", err)
        finally:
            os.rmdir(empty)

    def test_db_persistence_from_cli(self):
        db = tempfile.mktemp(suffix=".db")
        try:
            code, _, err = run("scan", SAMPLES, "--year", "2026",
                               "--format", "csv", "--db", db)
            self.assertEqual(code, 0)
            self.assertIn("Saved scan #1", err)
            from loghawk.store import AlertStore

            self.assertGreater(AlertStore(db).stats()["total_alerts"], 0)
        finally:
            if os.path.exists(db):
                os.remove(db)


if __name__ == "__main__":
    unittest.main(verbosity=2)
