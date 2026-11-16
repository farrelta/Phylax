from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

from phylax.ai import AIConfig
from phylax.core import Store
from phylax.remediation import compose_plan, template_guidance
from phylax.web import attack_surface_page, remediation_page


class PassiveSurfaceAndAITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.db")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def prepare_finding(self) -> str:
        self.store.import_csv(io.StringIO("asset_id,ip_address,hostname,asset_type,vendor,product,version,zone,criticality,identity_confidence,verified\nlocal-plc,192.0.2.10,secret-host,PLC,Acme,Controller,1.2,OT,critical,high,true\n"))
        self.store.ingest_fixture({"vulnerabilities": [{
            "cve_id": "CVE-2025-12345", "summary": "Public advisory summary", "source": "NVD",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-12345",
            "references": ["https://vendor.example/advisory"], "severity": "HIGH", "cvss": 8.0,
            "affected_products": [{"vendor": "Acme", "product": "Controller", "versions": ["1.2"]}], "synthetic": False,
        }]})
        self.store.correlate()
        return self.store.dashboard()["findings"][0]["finding_id"]

    def test_attack_surface_joins_inventory_and_imported_flows_and_preserves_unknowns(self) -> None:
        self.store.import_csv(io.StringIO("asset_id,ip_address,hostname,asset_type,vendor,product,version,zone,criticality,identity_confidence,verified\nknown,192.0.2.10,controller,PLC,Acme,Controller,1.2,OT,critical,high,true\ninventory-only,192.0.2.12,workstation,engineering workstation,,,,IT,medium,medium,false\n"))
        self.store.connection.execute("INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
            "event1", "ref1", "2026-10-29T00:00:00Z", "192.0.2.11", None, "192.0.2.10", 502,
            "tcp", "", "conn", "capture.log", "{}"))
        self.store.connection.commit()
        view = self.store.attack_surface()
        peers = {node["ip_address"]: node for node in view["nodes"]}
        self.assertEqual(peers["192.0.2.11"]["identity"], "Unknown peer")
        self.assertEqual(peers["192.0.2.11"]["identity_confidence"], "unknown")
        self.assertEqual(peers["192.0.2.12"]["visibility"], "Inventory only; no imported traffic observed")
        self.assertEqual(view["edges"][0]["destination_port"], 502)
        self.assertIn("Unknown peer", attack_surface_page(self.store))
        self.assertIn("Unseen traffic is not evidence of absence", attack_surface_page(self.store))
        self.assertIn("<svg", attack_surface_page(self.store))
        self.assertIn("no trust boundaries are inferred", attack_surface_page(self.store))

    def test_ai_disabled_without_all_environment_settings(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch("builtins.open", side_effect=FileNotFoundError):
            self.assertIsNone(AIConfig.from_env())

    def test_ai_settings_load_from_dotenv_with_process_environment_precedence(self) -> None:
        contents = "PHYLAX_AI_PROVIDER=gemini\nGEMINI_API_KEY='file-key'\nPHYLAX_AI_MODEL=gemini-3.8-flash\nIGNORED=value\n"
        with patch.dict(os.environ, {}, clear=True), patch("builtins.open", mock_open(read_data=contents)):
            config = AIConfig.from_env()
            self.assertEqual((config.provider, config.model, config.api_key), ("gemini", "gemini-3.8-flash", "file-key"))
        with patch.dict(os.environ, {"PHYLAX_AI_PROVIDER": "gemini", "GEMINI_API_KEY": "process-key", "PHYLAX_AI_MODEL": "gemini-3.8-flash"}, clear=True), patch("builtins.open", mock_open(read_data=contents)):
            config = AIConfig.from_env()
            self.assertEqual(config.api_key, "process-key")

    def test_free_provider_presets_select_their_documented_endpoints(self) -> None:
        with patch.dict(os.environ, {"PHYLAX_AI_PROVIDER": "gemini", "GEMINI_API_KEY": "g-key", "PHYLAX_AI_MODEL": "gemini-flash"}, clear=True), patch("builtins.open", side_effect=FileNotFoundError):
            config = AIConfig.from_env()
            self.assertEqual((config.provider, config.base_url, config.model, config.api_key), ("gemini", "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-flash", "g-key"))
        with patch.dict(os.environ, {"PHYLAX_AI_PROVIDER": "groq", "GROQ_API_KEY": "r-key", "PHYLAX_AI_MODEL": "active-model"}, clear=True), patch("builtins.open", side_effect=FileNotFoundError):
            self.assertEqual(AIConfig.from_env().base_url, "https://api.groq.com/openai/v1")
        with patch.dict(os.environ, {"PHYLAX_AI_PROVIDER": "openrouter", "OPENROUTER_API_KEY": "o-key"}, clear=True), patch("builtins.open", side_effect=FileNotFoundError):
            config = AIConfig.from_env()
            self.assertEqual(config.model, "openrouter/free")
            self.assertEqual(config.base_url, "https://openrouter.ai/api/v1")

    def test_ai_timeout_can_be_configured_with_safe_bounds(self) -> None:
        settings = {"PHYLAX_AI_PROVIDER": "gemini", "GEMINI_API_KEY": "key", "PHYLAX_AI_MODEL": "gemini-3.8-flash", "PHYLAX_AI_TIMEOUT_SECONDS": "120"}
        with patch.dict(os.environ, settings, clear=True), patch("builtins.open", side_effect=FileNotFoundError):
            self.assertEqual(AIConfig.from_env().timeout_seconds, 120)
        settings["PHYLAX_AI_TIMEOUT_SECONDS"] = "999"
        with patch.dict(os.environ, settings, clear=True), patch("builtins.open", side_effect=FileNotFoundError):
            self.assertEqual(AIConfig.from_env().timeout_seconds, 90)

    def test_valid_guidance_persists_without_changing_finding_alert_or_risk(self) -> None:
        finding_id = self.prepare_finding()
        before = dict(self.store.connection.execute("SELECT status,priority FROM findings WHERE finding_id=?", (finding_id,)).fetchone())
        alert = self.store.connection.execute("SELECT alert_id,acknowledged FROM alerts WHERE finding_id=?", (finding_id,)).fetchone()
        self.assertIsNotNone(alert)
        guidance = {"summary": "Review the vendor advisory.", "steps": ["Confirm affected version."], "validation": "Check release notes.", "source_urls": ["https://vendor.example/advisory"], "vendor_guidance": "source-provided"}
        finding = self.store.finding(finding_id)
        for key in ('evidence', 'missing_evidence'):
            finding[key] = json.loads(finding[key])
        plan = compose_plan(finding, self.store.public_vulnerability_for_finding(finding_id))
        plan.update(ai_summary=guidance["summary"], ai_steps=guidance["steps"],
                    ai_validation=guidance["validation"], ai_source_references=guidance["source_urls"])
        self.store.create_remediation_plan(finding_id, "test-provider", "test-model", plan, guidance["source_urls"])
        stored = self.store.get_remediation_plan(finding_id)
        self.assertEqual(stored["plan"]["ai_summary"], guidance["summary"])
        self.assertEqual(stored["plan"]["ai_steps"], guidance["steps"])
        self.assertEqual(stored["source_urls"], guidance["source_urls"])
        self.assertEqual(stored["model"], "test-model")
        self.assertIn(guidance["summary"], remediation_page(self.store, finding_id=finding_id))
        after = dict(self.store.connection.execute("SELECT status,priority FROM findings WHERE finding_id=?", (finding_id,)).fetchone())
        alert_after = self.store.connection.execute("SELECT alert_id,acknowledged FROM alerts WHERE finding_id=?", (finding_id,)).fetchone()
        self.assertEqual(before, after)
        self.assertEqual(tuple(alert), tuple(alert_after))

    def test_remediation_lifecycle_requires_review_and_verification_evidence(self) -> None:
        finding_id = self.prepare_finding()
        finding = next(item for item in self.store.dashboard()["findings"] if item["finding_id"] == finding_id)
        finding["evidence"] = json.loads(finding["evidence"])
        finding["missing_evidence"] = json.loads(finding["missing_evidence"])
        finding["references"] = json.loads(finding["references_json"])
        public = self.store.public_vulnerability_for_finding(finding_id)
        plan = compose_plan(finding, public)
        self.assertTrue(plan["human_approval_required"])
        self.assertIn("request vendor guidance", plan["preferred_remediation"] if not public["mitigation"] else plan["validation_steps"][1])
        saved = self.store.create_remediation_plan(finding_id, "template-fallback", "", plan, plan["source_references"])
        self.assertEqual(saved["status"], "Recommended")
        self.store.update_remediation_plan(finding_id, "Under Review", reviewer="operator", change_notes="Checking source evidence")
        with self.assertRaisesRegex(ValueError, "Reviewer is required"):
            self.store.update_remediation_plan(finding_id, "Approved")
        self.store.update_remediation_plan(finding_id, "Approved", reviewer="OT owner", change_notes="Record the simulated mitigation in the approved maintenance window")
        self.store.update_remediation_plan(finding_id, "Implemented", reviewer="OT owner", change_notes="Simulated change recorded")
        with self.assertRaisesRegex(ValueError, "Verification evidence"):
            self.store.update_remediation_plan(finding_id, "Verified")
        verified = self.store.update_remediation_plan(finding_id, "Verified", reviewer="operator", verification_evidence="Synthetic fixture verification only")
        self.assertEqual(verified["status"], "Verified")
        self.assertEqual(len(verified["history"]), 5)
        report = json.loads(self.store.report("json"))
        self.assertEqual(report["remediation_plans"][0]["status"], "Verified")
        self.assertIn("remediation_plan", self.store.report("csv"))
        regenerated = self.store.create_remediation_plan(finding_id, "template-fallback", "", plan, plan["source_references"])
        self.assertEqual(regenerated["status"], "Recommended")
        self.assertEqual(regenerated["reviewer"], "")
        self.assertEqual(regenerated["verification_evidence"], "")
        self.assertIn("prior review and verification were cleared", regenerated["history"][-1]["notes"])

    def test_template_fallback_states_when_vendor_guidance_is_missing(self) -> None:
        plan = template_guidance({"cve_id": "CVE-2024-12345", "status": "NEEDS_REVIEW", "missing_evidence": ["version"], "references": []})
        self.assertEqual(plan["vendor_guidance_status"], "none available")
        self.assertIn("No verified vendor", plan["preferred_remediation"])
        self.assertIn("not a confirmed exposure", plan["validation_steps"][0])


if __name__ == "__main__":
    unittest.main()
