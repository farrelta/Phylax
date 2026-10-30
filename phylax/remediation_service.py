"""One tested operation for operator-triggered hosted guidance and local plans."""
from __future__ import annotations
import json
from .ai import AIConfig
from .core import Store
from .remediation import HostedModelProvider,TemplateFallbackProvider,compose_plan


def generate_plan(store: Store, finding_id: str) -> str:
    finding=store.finding(finding_id)
    public_record=store.public_vulnerability_for_finding(finding_id)
    if finding is None or public_record is None:raise ValueError('Finding not found')
    for key in ('evidence','missing_evidence'):finding[key]=json.loads(finding[key])
    finding['references']=json.loads(finding['references_json'])
    config=AIConfig.from_env()
    hosted=None;reason='';selected=TemplateFallbackProvider()
    if finding['synthetic']:
        reason='Synthetic fixture: generated a local plan; hosted AI was intentionally skipped.'
    elif not config:
        reason='Hosted AI is not configured; generated a local plan.'
    elif not public_record.get('public_trusted'):
        reason='Hosted AI skipped: no trusted public feed snapshot is stored. Refresh this CVE from its official source.'
    else:
        selected=HostedModelProvider(config)
        # Provider call happens outside an open write transaction.
        try:hosted=selected.generate(public_record)
        except (RuntimeError,ValueError) as exc:
            reason=f'Hosted guidance unavailable or invalid ({exc}).'
            selected=TemplateFallbackProvider()
    # Input may change while a remote request is running. Never attach output to
    # a different assessment or clear approvals against changed evidence.
    current=store.finding(finding_id)
    if current is None or any(current[k] != finding[k] for k in ('status','priority','updated_at')):
        raise ValueError('Finding changed during generation; review the current assessment and retry')
    existing=store.get_remediation_plan(finding_id)
    if reason and existing and existing['provider']!=TemplateFallbackProvider.name:
        store.audit('guidance_failed',finding_id,{'reason':reason,'previous_plan_kept':True})
        store.connection.commit()
        return reason+' The previous hosted plan was kept.'
    plan=compose_plan(finding,public_record,hosted)
    store.create_remediation_plan(finding_id,selected.name,selected.model,plan,plan['source_references'])
    store.audit('plan_generated',finding_id,{'provider':selected.name,'model':selected.model,'hosted':bool(hosted)})
    store.connection.commit()
    return reason or ('Generated an AI-assisted plan with local evidence retained on this host.' if hosted else 'Generated a local remediation plan.')
