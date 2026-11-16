"""Evidence-aware remediation plan composition and deterministic fallback."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from .prioritization import prioritize

CONFIRMED = 'CONFIRMED_MATCH'
EXCLUDED = 'NO_MATCH_TO_THIS_ADVISORY'


def stored_mitigation(finding):
    return str(finding.get('mitigation') or '').strip()


def next_step(status, mitigation):
    if status == EXCLUDED:
        return 'No fix needed for this advisory.'
    if status == CONFIRMED:
        return 'Review vendor guidance.' if mitigation else 'Consult the advisory or document a mitigation.'
    if status == 'POTENTIAL_MATCH':
        return 'Verify device identity and version.'
    return 'Resolve missing or conflicting evidence.'


def _evidence_list(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return [value]
    return list(value) if isinstance(value, (list, tuple)) else []


def finding_revision(finding):
    content = [finding['status'], _evidence_list(finding.get('evidence')),
               _evidence_list(finding.get('missing_evidence')), finding.get('priority'),
               stored_mitigation(finding), _evidence_list(finding.get('references_json', finding.get('references')))]
    return sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def plan_finding_context(finding):
    return {'finding_status': finding['status'], 'priority': finding['priority'],
            'current_identity_confidence': finding['identity_confidence'],
            'current_missing_evidence': _evidence_list(finding['missing_evidence']),
            'current_mitigation': stored_mitigation(finding),
            'current_finding_revision': finding_revision(finding)}


def template_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a safe local recommendation when AI is disabled or unavailable."""
    mitigation = stored_mitigation(finding)
    if mitigation:
        preferred = mitigation
        source_status = "source-provided mitigation; vendor authorship and fix are unverified"
    else:
        preferred = "No verified vendor fix or mitigation is stored. Review the official vendor advisory and request vendor guidance."
        source_status = "none available"
    missing = _evidence_list(finding.get('missing_evidence'))
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
        "evidence": _evidence_list(finding.get('evidence')),
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
        "source_references": _evidence_list(finding.get('references_json', finding.get('references'))),
        "provider_note": "Deterministic local template; no model request was made.",
    }


def compose_plan(finding: dict[str, Any], public_record: dict[str, Any]) -> dict[str, Any]:
    plan = template_guidance(finding)
    plan['finding_revision'] = finding_revision(finding)
    if public_record.get("cisa_required_action"):
        plan["cisa_required_action"] = public_record["cisa_required_action"]
    return plan

