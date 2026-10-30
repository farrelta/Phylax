"""Consistent, evidence-bearing JSON/CSV/Markdown exports."""
from __future__ import annotations
import csv
import html
import json
from io import StringIO
from typing import TYPE_CHECKING, Any
from .prioritization import prioritize
from .validation import csv_value
if TYPE_CHECKING:
    from .core import Store

LIMITATIONS = [
    'No active scanning or device control is performed.',
    'Version matching uses exact source versions and numeric dotted ranges only; unsupported CPE/version conditions require review.',
    'Incomplete or unverified identities are not treated as safe.',
    'Imported observations define the visible surface; unseen traffic is not evidence of absence.',
    'Observed traffic does not prove reachability or exploitation. KEV membership does not prove a local attack.',
    'AI output and source mitigation text require independent vendor and operational review.',
    'A missing match does not establish that an asset is safe.',
    'A vulnerability finding does not establish compromise.',
]


def report_data(store: Store) -> dict[str, Any]:
    from .core import utc_now
    data = store.dashboard()
    findings=[]
    for item in data['findings']:
        row=dict(item)
        row['references']=json.loads(row.pop('references_json','[]'))
        for name in ('evidence','missing_evidence'):
            row[name]=json.loads(row[name])
        assessment=prioritize(row,row,row['status'])
        row['priority_factors']=assessment['factors']
        row['priority_score']=assessment['score']
        row['priority_uncertainty']=assessment['uncertainty']
        row['priority_rule_version']=assessment['rule_version']
        row['source_provenance']=store.vulnerability_provenance(row['cve_id'])
        for source in row['source_provenance']:
            source.pop('record_json',None)
        row['recommended_next_steps']=row['mitigation'] or 'Verify asset/version and source conditions with the asset owner; consult the vendor advisory before proposing a change.'
        findings.append(row)
    network=[]
    for row in store.connection.execute("""SELECT a.*,e.event_ref,e.timestamp AS event_timestamp,e.source_ip,e.destination_ip,e.source_file,
        COALESCE(l.state,'active') AS lifecycle_state,l.policy_id FROM network_alerts a JOIN network_events e USING(event_id)
        LEFT JOIN network_alert_lifecycle l USING(alert_id) ORDER BY a.created_at DESC"""):
        item=dict(row);item['policy_evidence']=json.loads(item['policy_evidence'])
        asset=store.connection.execute('SELECT asset_id,identity_confidence FROM assets WHERE ip_address=? ORDER BY verified DESC LIMIT 1',(item['destination_ip'],)).fetchone()
        item['asset_id']=asset['asset_id'] if asset else ''
        item['identity_confidence']=asset['identity_confidence'] if asset else 'unknown'
        item['recommended_next_steps']='Review the cited event, writer/communication policy and maintenance authorization with the OT owner. Preserve the original capture/log; an alert alone does not prove compromise.'
        network.append(item)
    diagnostics=[dict(r) for r in store.connection.execute('SELECT * FROM event_evaluations WHERE diagnostics_json!=? ORDER BY evaluated_at DESC',('[]',))]
    for item in diagnostics:item['diagnostics']=json.loads(item.pop('diagnostics_json'))
    return {'generated_at':utc_now(),'scope':'local inventory and locally stored intelligence','known_limitations':LIMITATIONS,
            'findings':findings,'asset_identity_reviews':data['identity_review_assets'],'network_alerts':network,
            'evaluation_diagnostics':diagnostics,'remediation_plans':data['remediation_plans'],
            'source_health':data['source_health'],'priority_rule_version':'2',
            'archived_plans':[dict(r) | {'snapshot':json.loads(r['snapshot_json'])} for r in store.connection.execute('SELECT * FROM archived_plans ORDER BY created_at DESC')]}


def export_report(store: Store, format: str) -> str:
    payload=report_data(store)
    if format=='json':return json.dumps(payload,indent=2)
    if format=='markdown':
        lines=['# Phylax investigation report',f"Generated: {payload['generated_at']}",'', '## Vulnerability assessments']
        for row in payload['findings']:
            lines.extend([f"### {html.escape(row['cve_id'])} · {html.escape(row['asset_id'])}",
                f"Applicability: {row['status']} · severity: {row['severity'] or 'unknown'} · priority: {row['priority']} · identity confidence: {row['identity_confidence']}",
                html.escape(row['summary']), 'Evidence: '+html.escape('; '.join(row['evidence'])),
                'Missing evidence: '+html.escape('; '.join(row['missing_evidence']) or 'None recorded'),
                'References: '+html.escape('; '.join(row['references'])),
                'Next steps: '+html.escape(row['recommended_next_steps']),''])
        lines.append('## Network findings')
        for row in payload['network_alerts']:
            lines.extend([f"- {row['rule_id']} · {row['lifecycle_state']} · {row['event_timestamp']} · event {html.escape(row['event_ref'])}",
                          '  '+html.escape(row['explanation']), '  Next steps: '+row['recommended_next_steps']])
        lines.extend(['','## Known limitations']+['- '+text for text in LIMITATIONS])
        return '\n'.join(lines)+'\n'
    if format!='csv':raise ValueError('format must be json, csv, or markdown')
    out=StringIO()
    columns=['record_type','generated_at','known_limitations','asset_id','ip_address','hostname','vendor','product','version','identity_confidence','cve_id','status','priority','priority_score','priority_factors','priority_uncertainty','severity','kev','summary','evidence','missing_evidence','source','source_url','references','source_provenance','mitigation','recommended_next_steps','rule_id','alert_id','event_ref','timestamp','source_ip','destination_ip','policy_evidence','lifecycle_state','policy_id','remediation_status','provider','model','reviewer','change_notes','verification_evidence']
    writer=csv.DictWriter(out,fieldnames=columns,extrasaction='ignore');writer.writeheader()
    def write(row):
        fields={'generated_at':payload['generated_at'],'known_limitations':'; '.join(LIMITATIONS),**row}
        writer.writerow({key:csv_value(json.dumps(value,ensure_ascii=False) if isinstance(value,(list,dict)) else value) for key,value in fields.items()})
    write({'record_type':'report_metadata','summary':'Local evidence export; absence of findings does not establish safety.'})
    for row in payload['findings']:write({**row,'record_type':'vulnerability_finding'})
    for row in payload['asset_identity_reviews']:
        write({**row,'record_type':'asset_identity_review','status':'NEEDS_REVIEW','summary':'Asset identity needs review. No CVE conclusion was made.', 'missing_evidence':[k for k in ('vendor','product') if not row[k]],'recommended_next_steps':'Verify inventory identity with its owner.'})
    for row in payload['network_alerts']:write({**row,'record_type':'network_alert','timestamp':row['event_timestamp'],'summary':row['explanation']})
    for row in payload['remediation_plans']:write({**row,'record_type':'remediation_plan','status':row['finding_status'],'remediation_status':row['status'],'summary':row['plan']['finding_summary'],'references':row['source_urls']})
    return out.getvalue()
