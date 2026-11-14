"""Persist an explicitly reviewed plan against the evidence that produced it."""
import json

from .assistant_workflows import fingerprint
from .remediation import compose_plan


def remediation_version(store, finding_id):
    return fingerprint(store.finding(finding_id), store.public_vulnerability_for_finding(finding_id),
                       store.get_remediation_plan(finding_id))


def generate_plan(store, finding_id, *, expected_version=None, result=None):
    provider, model = 'template-fallback', ''
    with store.atomic('reviewed_plan'):
        store.connection.execute('UPDATE findings SET updated_at=updated_at WHERE finding_id=?', (finding_id,))
        if expected_version is not None and remediation_version(store, finding_id) != expected_version:
            raise ValueError('Finding or plan changed. Review the current evidence and draft again.')
        finding = store.finding(finding_id)
        public = store.public_vulnerability_for_finding(finding_id)
        if finding is None or public is None:
            raise ValueError('Finding not found')
        for key in ('evidence', 'missing_evidence'):
            finding[key] = json.loads(finding[key])
        finding['references'] = json.loads(finding['references_json'])
        supplement = None
        if result:
            provider, model = result['provider'], result['model']
            draft = result['draft']
            supplement = {'model': model, 'requested_model': result['requested_model'], 'source_urls': [],
                          'guidance': {'summary': draft['summary'], 'steps': [draft['next_step']],
                                       'validation': draft['reason'], 'source_urls': []}}
        plan = compose_plan(finding, public, supplement)
        if supplement:
            plan['provider_note'] = 'AI-generated guidance. Review the saved evidence and vendor advisory before approving a change.'
        store.create_remediation_plan(finding_id, provider, model, plan, plan['source_references'], commit=False)
        store.audit('plan_generated', finding_id, {'provider': provider, 'model': model, 'hosted': bool(result and result['mode'] == 'hosted')})
    return 'Saved remediation draft for operator review.'
