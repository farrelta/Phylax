"""Persist an explicitly reviewed plan against the evidence that produced it."""
import json

from .remediation import compose_plan


def generate_plan(store, finding_id):
    with store.atomic('reviewed_plan'):
        store.connection.execute('UPDATE findings SET updated_at=updated_at WHERE finding_id=?', (finding_id,))
        finding = store.finding(finding_id)
        public = store.public_vulnerability_for_finding(finding_id)
        if finding is None or public is None:
            raise ValueError('Finding not found')
        for key in ('evidence', 'missing_evidence'):
            finding[key] = json.loads(finding[key])
        finding['references'] = json.loads(finding['references_json'])
        plan = compose_plan(finding, public)
        store.create_remediation_plan(finding_id, 'template-fallback', '', plan, plan['source_references'], commit=False)
        store.audit('plan_generated', finding_id, {'provider': 'template-fallback', 'model': '', 'hosted': False})
    return 'Saved remediation draft for operator review.'
