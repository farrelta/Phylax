from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from sentinelot.core import Store


ROOT = Path(__file__).resolve().parents[1]


class VerticalSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "test.sqlite")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def load_demo(self) -> None:
        with (ROOT / "examples/assets.csv").open(encoding="utf-8") as stream:
            self.assertEqual(self.store.import_csv(stream)["imported"], 4)
        self.store.ingest_fixture(ROOT / "examples/vulnerability-fixture.json")

    def test_csv_import_validation_and_export_round_trip(self) -> None:
        csv_data = "ip_address,asset_type,zone,criticality,identity_confidence\n192.0.2.1,PLC,OT,high,high\n192.0.2.1,PLC,OT,high,high\nnot-an-ip,PLC,OT,high,high\n,PLC,OT,high,high\n192.0.2.2,spaceship,OT,low,low\n"
        result = self.store.import_csv(io.StringIO(csv_data))
        self.assertEqual(result["imported"], 2)
        self.assertEqual(len(result["errors"]), 3)
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 1)
        out = io.StringIO()
        self.store.export_assets_csv(out)
        self.assertIn("192.0.2.1", out.getvalue())
        self.assertEqual(self.store.import_csv(io.StringIO(out.getvalue()))["imported"], 1)

    def test_correlates_confirmed_and_incomplete_without_overclaiming(self) -> None:
        self.load_demo()
        counts = self.store.correlate()
        self.assertEqual(counts["CONFIRMED_MATCH"], 1)
        self.assertEqual(counts["POTENTIAL_MATCH"], 1)
        self.assertEqual(counts["NEEDS_REVIEW"], 1)
        data = self.store.dashboard()
        self.assertEqual(data["confirmed_assets"], 1)
        self.assertEqual(data["potential_assets"], 1)
        self.assertEqual(data["kev_findings"], 2)
        self.assertEqual(data["unacknowledged_alerts"], 2)
        report = json.loads(self.store.report("json"))
        statuses = {item["status"] for item in report["findings"]}
        self.assertIn("CONFIRMED_MATCH", statuses)
        self.assertIn("POTENTIAL_MATCH", statuses)
        confirmed = next(item for item in report["findings"] if item["status"] == "CONFIRMED_MATCH")
        self.assertIn("explicitly listed", " ".join(json.loads(confirmed["evidence"])))
        self.assertIn("does not establish compromise", report["known_limitations"][-1])

    def test_same_manufacturer_different_product_does_not_match(self) -> None:
        csv_data = "asset_id,ip_address,asset_type,vendor,product,version,zone,criticality,identity_confidence\na,192.0.2.5,PLC,Example Controls,Unrelated Controller,1.2.3,OT,high,high\n"
        self.store.import_csv(io.StringIO(csv_data))
        self.store.ingest_fixture(ROOT / "examples/vulnerability-fixture.json")
        self.assertEqual(self.store.correlate(), {})
        self.assertEqual(self.store.dashboard()["unacknowledged_alerts"], 0)

    def test_alert_acknowledgement_and_csv_report(self) -> None:
        self.load_demo()
        self.store.correlate()
        alert_id = self.store.dashboard()["alerts"][0]["alert_id"]
        self.assertTrue(self.store.acknowledge(alert_id))
        self.assertEqual(self.store.dashboard()["unacknowledged_alerts"], 1)
        report = self.store.report("csv")
        self.assertIn("status", next(csv.reader(io.StringIO(report))))
        self.assertIn("SYNTHETIC", report)

    def test_fixture_rejects_bad_identifier_and_duplicate_is_upsert(self) -> None:
        with self.assertRaises(ValueError):
            self.store.ingest_fixture({"vulnerabilities": [{"cve_id": "not-a-cve", "summary": "bad"}]})
        fixture = json.loads((ROOT / "examples/vulnerability-fixture.json").read_text())
        self.store.ingest_fixture(fixture)
        self.store.ingest_fixture(fixture)
        count = self.store.connection.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
