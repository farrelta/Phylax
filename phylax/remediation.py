"""Evidence-aware remediation plan composition and deterministic fallback."""

from __future__ import annotations

from typing import Any, Protocol

from .ai import AIConfig, generate_guidance
from .prioritization import prioritize


class RemediationProvider(Protocol):
    name: str
    model: str

    def generate(self, public_record: dict[str, Any]) -> dict[str, Any] | None: ...


class HostedModelProvider:
    """Hosted provider receives the public advisory record only."""

    def __init__(self, config: AIConfig):
        self.config = config
        self.model = config.model
        self.name = f"{config.provider}-public-data-only"

    def generate(self, public_record: dict[str, Any]) -> dict[str, Any]:
        result = generate_guidance(public_record, self.config)
        self.model = result["model"]
        return result


class TemplateFallbackProvider:
    """Local deterministic path; it makes no network request."""

    name = "template-fallback"
    model = ""

    def generate(self, public_record: dict[str, Any]) -> None:
        return None


def template_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a safe local recommendation when AI is disabled or unavailable."""
    mitigation = str(finding.get("mitigation") or "").strip()
    if mitigation:
        preferred = mitigation
        source_status = "source-provided mitigation; vendor authorship and fix are unverified"
    else:
        preferred = "No verified vendor fix or mitigation is stored. Review the official vendor advisory and request vendor guidance."
        source_status = "none available"
    missing = finding.get("missing_evidence", [])
    if isinstance(missing, str):
        import json
        try:
            missing = json.loads(missing)
        except ValueError:
            missing = [missing]
    steps = [
        "Confirm the asset identity and installed version with the asset owner before selecting a change.",
        "Review the cited vendor guidance and applicable prerequisites with the OT operations owner.",
        "Assess availability, safety, dependencies, maintenance-window, and rollback requirements before approval.",
    ]
    if finding.get("status") not in {"CONFIRMED_MATCH", "POTENTIAL_MATCH"}:
        steps.insert(0, "Resolve applicability evidence with the asset owner; this finding is not a confirmed exposure.")
    assessment = prioritize(finding,finding,finding.get('status','NEEDS_REVIEW'))
    priority_factors = [f"{f['input']}: {f['value']} (+{f['points']})" for f in assessment['factors']]
    priority_factors.extend(assessment['uncertainty'])
    return {
        "finding_summary": f"{finding.get('cve_id', 'Finding')} · {finding.get('status', 'Unknown applicability')}: {finding.get('summary', '')}",
        "evidence": list(finding.get("evidence", [])),
        "confidence_and_questions": {"applicability": finding.get("status", "NEEDS_REVIEW"), "identity_confidence": finding.get("identity_confidence", "unknown"), "unresolved": list(missing)},
        "recommended_priority": finding.get("priority", "unknown"),
        "priority_explanation": f"Existing deterministic Phylax priority: {finding.get('priority', 'unknown')}. Inputs: " + "; ".join(priority_factors) + ". Plan generation does not recalculate or change it.",
        "priority_factors": priority_factors,
        "preferred_remediation": preferred,
        "vendor_guidance_status": source_status,
        "alternative_controls": ["Review whether documented, approved network restrictions or monitoring controls are appropriate; validate impact before any change."],
        "operational_impact": "Unknown until the OT owner reviews equipment dependencies, safety requirements, and availability constraints.",
        "preconditions": ["Confirm asset identity, product, and version.", "Confirm vendor applicability and supported change procedure.", "Obtain operational-owner approval and an approved maintenance window."],
        "validation_steps": steps,
        "rollback_considerations": ["Document a vendor-supported rollback or recovery method before an approved change; do not improvise controller recovery steps."],
        "human_approval_required": True,
        "post_remediation_verification": ["Record the installed version or control state using an approved, non-disruptive verification method.", "Reassess the finding and retain verification evidence; a plan or approval alone does not mean remediated."],
        "source_references": list(finding.get("references", [])),
        "provider_note": "Deterministic local template; no model request was made.",
    }


def compose_plan(finding: dict[str, Any], public_record: dict[str, Any], hosted_guidance: dict[str, Any] | None = None) -> dict[str, Any]:
    plan = template_guidance(finding)
    if hosted_guidance:
        guidance = hosted_guidance["guidance"]
        # Model text is an explicitly unverified supplement. Keep all local
        # evidence, priority, uncertainty, and workflow decisions deterministic.
        plan["provider_note"] = f"AI-generated, unverified public-advisory supplement from model {hosted_guidance['model']}. Local asset evidence was not sent."
        plan["ai_summary"] = guidance["summary"]
        plan["ai_steps"] = guidance["steps"]
        plan["ai_validation"] = guidance["validation"]
        plan["ai_source_references"] = list(guidance["source_urls"])
        plan["requested_model"] = hosted_guidance.get("requested_model",hosted_guidance["model"])
        plan["returned_model"] = hosted_guidance["model"]
        plan["source_references"] = list(dict.fromkeys(plan["source_references"] + hosted_guidance["source_urls"]))
    if public_record.get("cisa_required_action"):
        plan["cisa_required_action"] = public_record["cisa_required_action"]
    if not public_record.get("mitigation"):
        plan["preferred_remediation"] = "No verified vendor remediation is present in stored source data; request vendor guidance and manually review before planning a change."
        plan["vendor_guidance_status"] = "none available"
    return plan

