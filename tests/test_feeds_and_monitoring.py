from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from phylax.core import Store
from phylax.feeds import ICS_RSS_URL, KEV_URL, normalize_ics_rss, normalize_kev, normalize_nvd, nvd_pages, sync_store
from phylax.monitoring import NetworkEvent, evaluate, ingest_file, is_modbus_write, parse_zeek


NVD_ROW = {
    "cve": {
        "id": "CVE-2024-12345", "published": "2024-01-01T00:00:00.000", "lastModified": "2024-01-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
        "references": [{"url": "https://vendor.example/advisory"}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:example_controls:demo_plc:1.2.3:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:o:example_controls:demo_plc:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"},
        ]}]}],
    }
}


class FeedTests(unittest.TestCase):
    def test_nvd_normalization_preserves_exact_version_only(self) -> None:
        result = normalize_nvd(NVD_ROW, "2026-10-29T00:00:00Z")
        self.assertEqual(result["cve_id"], "CVE-2024-12345")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["cvss"], 8.1)
        self.assertEqual(result["affected_products"], [{"vendor": "example_controls", "product": "demo_plc", "versions": [], "conditions_unresolved": False}])
        self.assertEqual(result["source_url"], "https://vendor.example/advisory")
        self.assertEqual(result["references"], ["https://vendor.example/advisory"])

    def test_nvd_configuration_prerequisites_force_review(self) -> None:
        record = json.loads(json.dumps(NVD_ROW))
        record["cve"]["configurations"][0]["nodes"][0]["operator"] = "AND"
        result = normalize_nvd(record, "2026-10-29T00:00:00Z")
        self.assertTrue(result["affected_products"][0]["conditions_unresolved"])

    def test_nvd_pagination_uses_offsets_and_stops_at_total(self) -> None:
        calls = []
        def fetcher(url: str) -> bytes:
            calls.append(url)
            offset = int(url.split("startIndex=")[1].split("&")[0])
            row = {"cve": {**NVD_ROW["cve"], "id": f"CVE-2024-{12345 + offset}"}}
            return json.dumps({"vulnerabilities": [row] if offset < 2 else [], "totalResults": 2}).encode()
        items = list(nvd_pages(page_size=1, fetcher=fetcher))
        self.assertEqual(len(items), 2)
        self.assertEqual(len(calls), 2)

    def test_kev_and_ics_keep_source_limits_explicit(self) -> None:
        kev = normalize_kev({"vulnerabilities": [{"cveID": "CVE-2024-12345", "vendorProject": "Acme", "product": "Controller", "dateAdded": "2024-01-01", "requiredAction": "Apply vendor mitigations.", "knownRansomwareCampaignUse": "Unknown"}]})[0]
        self.assertTrue(kev["kev"])
        self.assertEqual(kev["affected_products"][0]["versions"], [])
        self.assertIn("Apply vendor", kev["mitigation"])
        rss = b'<rss><channel><item><guid>ICS-2026-01</guid><title>Controller Advisory</title><link>https://cisa.gov/advisory</link><description>Review vendor notice.</description></item></channel></rss>'
        records = normalize_ics_rss(rss, "2026-10-29T00:00:00Z")
        self.assertEqual(records[0]["title"], "Controller Advisory")
        self.assertEqual(records[0]["link"], "https://cisa.gov/advisory")

    def test_sync_records_independent_source_health_and_offline_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "feed.sqlite")
            def fetcher(url: str) -> bytes:
                if url.startswith("https://services.nvd.nist.gov"):
                    return json.dumps({"vulnerabilities": [NVD_ROW], "totalResults": 1}).encode()
                if url == KEV_URL:
                    return json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-12345", "vendorProject": "example_controls", "product": "demo_plc", "requiredAction": "Use vendor guidance."}]}).encode()
                if url == ICS_RSS_URL:
                    return b"<rss><channel><item><guid>ICS-1</guid><title>Advisory</title><link>https://cisa.gov/ics-1</link></item></channel></rss>"
                self.fail(f"Unexpected URL: {url}")
            progress = []
            results = sync_store(store, fetcher=fetcher, progress=lambda source, stage, message: progress.append((source, stage, message)))
            self.assertTrue(all(item["ok"] for item in results.values()))
            self.assertEqual({source for source, stage, _ in progress if stage == "start"}, {"NVD API 2.0", "CISA KEV", "CISA ICS advisories RSS"})
            self.assertEqual({source for source, stage, _ in progress if stage == "done"}, {"NVD API 2.0", "CISA KEV", "CISA ICS advisories RSS"})
            self.assertTrue(any(stage == "progress" and "page 1" in message for _, stage, message in progress))
            row = store.connection.execute("SELECT * FROM vulnerabilities WHERE cve_id='CVE-2024-12345'").fetchone()
            self.assertEqual(row["source"], "NVD API 2.0")
            self.assertEqual(row["kev"], 1)
            self.assertEqual(len(store.source_health()), 3)
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM ics_advisories").fetchone()[0], 1)
            change_count = store.connection.execute("SELECT COUNT(*) FROM intelligence_changes").fetchone()[0]
            sync_store(store, fetcher=fetcher)
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM intelligence_changes").fetchone()[0], change_count)
            self.assertGreaterEqual(len(store.dashboard()["recent_intelligence"]), 1)
            store.close()

    def test_nvd_sync_saves_pages_and_resumes_from_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "resume.sqlite")
            offsets = []
            def fetcher(url: str) -> bytes:
                if url.startswith("https://services.nvd.nist.gov"):
                    offset = int(url.split("startIndex=")[1].split("&")[0])
                    offsets.append(offset)
                    row = {"cve": {**NVD_ROW["cve"], "id": f"CVE-2024-{12345 + offset}"}}
                    return json.dumps({"vulnerabilities": [row] if offset < 2 else [], "totalResults": 2}).encode()
                if url == KEV_URL:
                    return b'{"vulnerabilities": []}'
                if url == ICS_RSS_URL:
                    return b"<rss><channel></channel></rss>"
                self.fail(f"Unexpected URL: {url}")

            def interrupt_after_page(source: str, stage: str, message: str) -> None:
                if source == "NVD API 2.0" and stage == "progress":
                    raise RuntimeError("simulated interruption after committed page")

            failed = sync_store(store, fetcher=fetcher, progress=interrupt_after_page, nvd_page_size=1)
            self.assertFalse(failed["NVD API 2.0"]["ok"])
            checkpoint = store.sync_checkpoint("NVD API 2.0")
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["next_start_index"], 1)
            first_start = checkpoint["window_start"]
            first_end = checkpoint["window_end"]
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0], 1)

            resumed = sync_store(store, fetcher=fetcher, nvd_page_size=1)
            self.assertTrue(resumed["NVD API 2.0"]["ok"])
            self.assertEqual(offsets, [0, 1])
            self.assertIsNone(store.sync_checkpoint("NVD API 2.0"))
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0], 2)
            success = store.connection.execute("SELECT last_success_at FROM intelligence_sources WHERE source='NVD API 2.0'").fetchone()[0]
            self.assertEqual(success, first_end)
            self.assertEqual(first_start, checkpoint["window_start"])
            store.close()

    def test_source_health_marks_old_success_stale_without_erasing_timestamp(self) -> None:
        from datetime import datetime, timedelta, timezone
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "stale.sqlite")
            previous = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
            store.set_source_health("CISA KEV", "healthy", records=1, message="ok", attempted_at=previous)
            status = store.source_health()[0]
            self.assertEqual(status["health"], "stale")
            self.assertEqual(status["last_success_at"], previous)
            store.close()

    def test_nvd_configuration_prerequisite_never_becomes_confirmed(self) -> None:
        record = json.loads(json.dumps(NVD_ROW))
        record["cve"]["configurations"][0]["nodes"][0]["operator"] = "AND"
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "conditions.sqlite")
            store.import_csv(io.StringIO("asset_id,ip_address,asset_type,vendor,product,version,zone,criticality,identity_confidence\nplc,192.0.2.10,PLC,example controls,demo plc,1.2.3,OT,critical,high\n"))
            store.ingest_normalized([normalize_nvd(record, "2026-10-29T00:00:00Z")])
            counts = store.correlate()
            self.assertEqual(counts["NEEDS_REVIEW"], 1)
            status = store.connection.execute("SELECT status FROM findings").fetchone()["status"]
            self.assertEqual(status, "NEEDS_REVIEW")
            store.close()


POLICY = {
    "protected_assets": ["192.0.2.10"],
    "allowed_communications": [{"source_ip": "192.0.2.30", "destination_ip": "192.0.2.10", "protocol": "tcp", "destination_port": 502}],
    "authorized_writers": {"192.0.2.10": ["192.0.2.30"]},
    "maintenance_windows_utc": [{"days": [3], "start": "01:00", "end": "03:00"}],
}


class MonitoringTests(unittest.TestCase):
    def event(self, operation: str = "6", source: str = "192.0.2.99", destination: str = "192.0.2.10") -> NetworkEvent:
        return NetworkEvent("2026-10-29T04:00:00Z", source, 40000, destination, 502, "tcp", operation, "modbus", "uid-1", "modbus.log", {"func": operation})

    def test_zeek_json_and_tsv_normalization(self) -> None:
        json_log = io.StringIO('{"ts":1793246400.0,"uid":"C1","id.orig_h":"192.0.2.30","id.orig_p":50100,"id.resp_h":"192.0.2.10","id.resp_p":502,"proto":"tcp","service":"modbus"}\n')
        parsed = list(parse_zeek(json_log, kind="conn"))
        self.assertTrue(parsed[0].event_ref.startswith("C1:connection:"))
        self.assertEqual(parsed[0].event_type, "connection")
        tsv = io.StringIO("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tfunc\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\n1793246400\tM1\t192.0.2.30\t40000\t192.0.2.10\t502\ttcp\t6\n")
        tsv_rows = list(parse_zeek(tsv, kind="modbus"))
        self.assertEqual(tsv_rows[0].operation, "6")
        self.assertTrue(is_modbus_write(tsv_rows[0]))

    def test_rules_authorized_write_unapproved_write_unexpected_peer_and_missing_data(self) -> None:
        detections, diagnostics = evaluate(self.event(), POLICY)
        self.assertEqual({item.rule_id for item in detections}, {"unauthorized_modbus_writer", "write_outside_maintenance_window"})
        self.assertEqual(diagnostics, [])
        authorized = self.event(source="192.0.2.30")
        detections, _ = evaluate(authorized, POLICY)
        self.assertEqual({item.rule_id for item in detections}, {"write_outside_maintenance_window"})
        during_window = NetworkEvent("2026-10-29T02:00:00Z", "192.0.2.30", 40000, "192.0.2.10", 502, "tcp", "6", "modbus", "maintenance")
        detections, diagnostics = evaluate(during_window, POLICY)
        self.assertEqual(detections, [])
        self.assertEqual(diagnostics, [])
        connection = NetworkEvent("2026-10-29T04:00:00Z", "192.0.2.99", 1234, "192.0.2.10", 502, "tcp", "", "connection", "conn-1")
        detections, _ = evaluate(connection, POLICY)
        self.assertEqual([item.rule_id for item in detections], ["unexpected_communication"])
        missing = NetworkEvent("2026-10-29T04:00:00Z", "192.0.2.99", 1234, "192.0.2.10", 502, "tcp", "", "modbus", "missing")
        detections, diagnostics = evaluate(missing, POLICY)
        self.assertEqual(detections, [])
        self.assertTrue(any("missing Modbus" in item for item in diagnostics))

    def test_icsnpp_fields_and_function_hex_do_not_alert_on_response(self) -> None:
        request = {"ts": "2026-10-29T04:05:00Z", "uid": "ICSNPP-1", "source_h": "192.0.2.99", "source_p": 40000, "destination_h": "192.0.2.10", "destination_p": 502, "func": "0x06", "request_response": "REQUEST"}
        event = next(parse_zeek(io.StringIO(json.dumps(request) + "\n"), kind="modbus"))
        self.assertEqual(event.source_ip, "192.0.2.99")
        self.assertEqual(event.destination_ip, "192.0.2.10")
        self.assertTrue(is_modbus_write(event))
        detections, _ = evaluate(event, POLICY)
        self.assertIn("unauthorized_modbus_writer", {item.rule_id for item in detections})
        named = NetworkEvent(event.timestamp, event.source_ip, event.source_port, event.destination_ip, event.destination_port, event.protocol, "Read/Write Multiple Registers", "modbus", "named-write")
        self.assertTrue(is_modbus_write(named))
        response = {**request, "source_h": "192.0.2.10", "source_p": 502, "destination_h": "192.0.2.99", "destination_p": 40000, "request_response": "RESPONSE"}
        response_event = next(parse_zeek(io.StringIO(json.dumps(response) + "\n"), kind="modbus"))
        detections, diagnostics = evaluate(response_event, POLICY)
        self.assertEqual(detections, [])
        self.assertEqual(diagnostics, [])

    def test_policy_validation_rejects_invalid_addresses_and_windows(self) -> None:
        from phylax.monitoring import validate_policy
        with self.assertRaises(ValueError):
            validate_policy({"protected_assets": ["controller-01"]})
        with self.assertRaises(ValueError):
            validate_policy({"maintenance_windows_utc": [{"days": [8], "start": "25:00", "end": "03:00"}]})

    def test_ingestion_deduplicates_events_and_persists_alert_evidence(self) -> None:
        log = '{"ts":"2026-10-29T04:00:00Z","uid":"M-1","id.orig_h":"192.0.2.99","id.orig_p":40000,"id.resp_h":"192.0.2.10","id.resp_p":502,"proto":"tcp","func":6}\n'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "modbus.log"
            path.write_text(log)
            store = Store(Path(temp) / "network.sqlite")
            first = ingest_file(store, path, kind="modbus", policy=POLICY)
            replay = ingest_file(store, path, kind="modbus", policy=POLICY)
            self.assertEqual(first["events_inserted"], 1)
            self.assertEqual(first["alerts_created"], 2)
            self.assertEqual(replay["duplicates_skipped"], 1)
            data = store.dashboard()
            self.assertEqual(data["network_events"], 1)
            self.assertEqual(len(data["network_alerts"]), 2)
            alert = data["network_alerts"][0]
            self.assertTrue(alert["event_ref"].startswith("M-1:modbus:"))
            self.assertEqual(alert["source_ip"], "192.0.2.99")
            observed = {asset["ip_address"]: asset for asset in store.assets()}
            self.assertEqual(set(observed), {"192.0.2.99", "192.0.2.10"})
            self.assertEqual(observed["192.0.2.99"]["identity_confidence"], "low")
            self.assertEqual(observed["192.0.2.99"]["product"], "")
            store.close()

    def test_malformed_log_rolls_back_partial_import(self) -> None:
        content = '{"ts":"2026-10-29T04:00:00Z","uid":"GOOD","id.orig_h":"192.0.2.99","id.resp_h":"192.0.2.10"}\nnot-json\n'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "conn.log"
            path.write_text(content)
            store = Store(Path(temp) / "rollback.sqlite")
            with self.assertRaises(ValueError):
                ingest_file(store, path, policy={})
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM network_events").fetchone()[0], 0)
            store.close()

    def test_e2e_inventory_fixture_correlation_network_alert_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "e2e.sqlite")
            store.import_csv(Path(__file__).resolve().parents[1] / "examples/assets.csv")
            store.ingest_fixture(Path(__file__).resolve().parents[1] / "examples/vulnerability-fixture.json")
            self.assertEqual(store.correlate()["CONFIRMED_MATCH"], 1)
            logs = Path(__file__).resolve().parents[1] / "examples/modbus.log"
            policy = json.loads((Path(__file__).resolve().parents[1] / "examples/network-policy.json").read_text())
            self.assertEqual(ingest_file(store, logs, kind="modbus", policy=policy)["alerts_created"], 2)
            report = json.loads(store.report("json"))
            self.assertTrue(any(item["status"] == "CONFIRMED_MATCH" for item in report["findings"]))
            self.assertTrue(any(item["rule_id"] == "unauthorized_modbus_writer" for item in report["network_alerts"]))
            self.assertTrue(any("MODBUS-DEMO-WRITE" in item["event_ref"] for item in report["network_alerts"]))
            from phylax.web import assets_page, intelligence_page, network_page, page
            self.assertIn("controller-01", assets_page(store, "Demo PLC"))
            self.assertIn("CVE-2099-0001", intelligence_page(store))
            self.assertIn("MODBUS-DEMO-WRITE", network_page(store))
            self.assertIn("Recent intelligence updates", page(store))
            store.close()


if __name__ == "__main__":
    unittest.main()
