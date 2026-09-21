"""API tests.

These use FastAPI's TestClient when FastAPI is installed and skip cleanly when
it is not, so ``python run_tests.py`` works on a machine with only the stdlib.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from helpers import SAMPLES

try:
    from fastapi.testclient import TestClient

    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    FASTAPI_AVAILABLE = False


@unittest.skipUnless(FASTAPI_AVAILABLE, "fastapi not installed")
class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = tempfile.mktemp(suffix=".db")
        os.environ["LOGHAWK_DB"] = cls.db
        import loghawk.api as api

        api.DB_PATH = cls.db
        api._store = None
        cls.api = api
        cls.client = TestClient(api.app)
        response = cls.client.post(
            "/api/scan", json={"paths": [SAMPLES], "year": 2026, "persist": True}
        )
        assert response.status_code == 200, response.text
        cls.scan = response.json()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.db):
            os.remove(cls.db)

    def test_health(self):
        body = self.client.get("/api/health").json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["rules_loaded"], 10)

    def test_rules_catalog(self):
        self.assertEqual(len(self.client.get("/api/rules").json()), 10)

    def test_scan_found_the_intrusion(self):
        self.assertGreater(self.scan["event_count"], 100)
        self.assertGreaterEqual(self.scan["risk_score"], 90)
        self.assertIn("scan_id", self.scan)

    def test_list_and_filter_alerts(self):
        body = self.client.get("/api/alerts").json()
        self.assertEqual(body["count"], len(body["alerts"]))

        crit = self.client.get("/api/alerts?min_severity=critical").json()
        self.assertTrue(all(a["severity"] == "critical" for a in crit["alerts"]))

        by_rule = self.client.get("/api/alerts?rule_id=LH-004").json()
        self.assertEqual(by_rule["count"], 1)

        by_ip = self.client.get("/api/alerts?src_ip=45.83.91.22").json()
        self.assertTrue(all(a["src_ip"] == "45.83.91.22" for a in by_ip["alerts"]))

    def test_alert_detail_and_404(self):
        alert_id = self.client.get("/api/alerts?limit=1").json()["alerts"][0]["id"]
        self.assertEqual(self.client.get(f"/api/alerts/{alert_id}").status_code, 200)
        self.assertEqual(self.client.get("/api/alerts/deadbeef").status_code, 404)

    def test_triage_workflow(self):
        alert_id = self.client.get("/api/alerts?limit=1").json()["alerts"][0]["id"]
        response = self.client.patch(
            f"/api/alerts/{alert_id}",
            json={"status": "escalated", "notes": "confirmed via session logs"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "escalated")

        bad = self.client.patch(f"/api/alerts/{alert_id}", json={"status": "bogus"})
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(
            self.client.patch("/api/alerts/deadbeef", json={"status": "resolved"}).status_code,
            404,
        )

    def test_stats(self):
        stats = self.client.get("/api/stats").json()
        self.assertGreater(stats["total_alerts"], 0)
        self.assertEqual(len(stats["by_rule"]), 10)
        self.assertIsNotNone(stats["last_scan"])

    def test_exports(self):
        csv_body = self.client.get("/api/export/csv").text
        self.assertTrue(csv_body.startswith("alert_id,rule_id"))
        md_body = self.client.get("/api/export/markdown").text
        self.assertIn("# LogHawk detection report", md_body)
        self.assertEqual(self.client.get("/api/export/xml").status_code, 400)

    def test_scan_rejects_a_missing_path(self):
        response = self.client.post("/api/scan", json={"paths": ["/nope"]})
        self.assertEqual(response.status_code, 400)

    def test_upload_scan(self):
        with open(os.path.join(SAMPLES, "auth.log"), "rb") as fh:
            response = self.client.post(
                "/api/scan/upload?year=2026&persist=false",
                files={"files": ("auth.log", fh, "text/plain")},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertGreater(response.json()["alert_count"], 0)

    def test_dashboard_is_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("LogHawk", response.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
