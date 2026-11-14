"""Consistent, evidence-bearing JSON/CSV/Markdown exports."""
from __future__ import annotations
import csv
import html
import json
from io import StringIO
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit
from .prioritization import prioritize
from .validation import csv_value
from .i18n import translate_text
if TYPE_CHECKING:
    from .core import Store

LIMITATIONS = [
    'Network evidence comes from imported records. Phylax performs no active scans or device control.',
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
        row['component_sources']=[dict(component) for component in store.connection.execute(
            '''SELECT s.component_id,s.source_file,s.event_ref FROM component_assessments c
               JOIN software_components s USING(component_id) WHERE c.finding_id=?''', (row['finding_id'],))]
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
    from .triage import release_data
    extension=release_data(store)
    extension['sensor_evidence']=[dict(row) for row in store.connection.execute('''
        SELECT kind,ip,observed_at,source_file,event_ref FROM observations
        WHERE kind IN ('modbus-identity','wazuh_inventory')
        UNION ALL SELECT event_type,source_ip,timestamp,source_file,event_ref
        FROM network_events WHERE event_type='suricata_flow'
        ORDER BY observed_at,event_ref''')]
    label=store.connection.execute("SELECT value FROM schema_meta WHERE key='dataset_label'").fetchone()
    return {'dataset_label':label[0] if label else '', 'asset_intelligence':extension,'generated_at':utc_now(),'scope':'local inventory and locally stored intelligence','known_limitations':LIMITATIONS,
            'findings':findings,'asset_identity_reviews':data['identity_review_assets'],'network_alerts':network,
            'evaluation_diagnostics':diagnostics,'remediation_plans':data['remediation_plans'],
            'source_health':data['source_health'],'priority_rule_version':'2',
            'archived_plans':[dict(r) | {'snapshot':json.loads(r['snapshot_json'])} for r in store.connection.execute('SELECT * FROM archived_plans ORDER BY created_at DESC')]}


def selected_report_markdown(rows, focus, links, language, dataset_label):
    def text(value):
        safe = html.escape(' '.join(str(value).split()), quote=False)
        for char in ('\\', '`', '*', '_', '[', ']', '#', '|', '~', '$'):
            safe = safe.replace(char, '\\' + char)
        return safe

    def t(value):
        return translate_text(value, language)

    lines = [t('# Phylax investigation report'), '', t('Scope: Selected vulnerability findings.'), '']
    if dataset_label:
        lines += [text(dataset_label), '']
    if focus:
        lines += [t('AI-organized review'), t(focus), '']
    for row in rows:
        ref = row['evidence']
        lines += [f"## {text(row['advisory'])} · {text(row['name'])}",
                  f"{t('Applicability')} · {text(t(row['applicability']))}",
                  f"{t('Urgency')} · {text(t(row['priority']))}",
                  f"[{t('Open vulnerability finding')} · {ref}](<{links[ref]}>)", '']
        if row['synthetic']:
            lines += [t('Simulated finding'), '']
        for title, items in (
            ('Evidence', row['recorded_evidence']), ('Missing evidence', row['missing_evidence']),
        ):
            if items:
                lines += [t(title)] + ['- ' + text(item) for item in items] + ['']
        if row['references']:
            lines += [t('References')]
            for value in row['references']:
                try:
                    url = urlsplit(value)
                    public_link = url.scheme in {'http', 'https'} and url.hostname and not url.username and not url.password
                except ValueError:
                    public_link = False
                if public_link:
                    target = quote(value, safe=":/?#@!$&'()*+,;=%[]")
                    lines += [f"- [{text(value)}](<{target}>)"]
                else:
                    lines += ['- ' + text(value)]
            lines += ['']
    lines += [t('## Known limitations'), '- ' + t('A vulnerability finding does not establish compromise.'),
              '- ' + t('A missing match does not establish that an asset is safe.')]
    return '\n'.join(lines) + '\n'


def export_report(store: Store, format: str, *, language: str = 'en') -> str:
    payload=report_data(store)
    if format=='json':return json.dumps(payload,indent=2)
    if format=='markdown':
        def t(value):return translate_text(value, language)
        lines=[t('# Phylax investigation report'),t(f"Generated: {payload['generated_at']}"),payload['dataset_label'],'', t('## Vulnerability assessments')]
        for row in payload['findings']:
            lines.extend([f"### {html.escape(row['cve_id'])} · {html.escape(row['asset_id'])}",
                t(f"Applicability: {row['status']} · severity: {row['severity'] or 'unknown'} · priority: {row['priority']} · identity confidence: {row['identity_confidence']}"),
                html.escape(row['summary']), t('Evidence:')+' '+html.escape('; '.join(t(v) for v in row['evidence'])),
                t('Missing evidence:')+' '+html.escape('; '.join(t(v) for v in row['missing_evidence']) or t('None recorded')),
                t('References:')+' '+html.escape('; '.join(row['references'])),
                t('Next steps:')+' '+html.escape(row['mitigation'] or t(row['recommended_next_steps'])),''])
        lines.append(t('## Network findings'))
        for row in payload['network_alerts']:
            lines.extend([f"- {row['rule_id']} · {t(row['lifecycle_state'])} · {row['event_timestamp']} · {t('Event')} {html.escape(row['event_ref'])}",
                          '  '+html.escape(t(row['explanation'])), '  '+t('Next steps:')+' '+t(row['recommended_next_steps'])])
        lines.extend(['',t('## Asset intelligence and operational context')])
        extension=payload['asset_intelligence']
        for category in ('management','asset_context','processes','process_links','asset_changes','software_components','sensor_evidence','scan_runs','triage','collectors'):
            lines.append('### '+t(category.replace('_',' ').title()))
            for row in extension[category]:lines.append('- '+html.escape(json.dumps(row,ensure_ascii=False)))
        lines.extend(['',t('## Known limitations')]+['- '+t(text) for text in LIMITATIONS])
        return '\n'.join(lines)+'\n'
    if format!='csv':raise ValueError('format must be json, csv, or markdown')
    out=StringIO()
    columns=['record_type','generated_at','known_limitations','asset_id','ip_address','hostname','vendor','product','version','identity_confidence','cve_id','status','priority','priority_score','priority_factors','priority_uncertainty','severity','kev','summary','evidence','missing_evidence','source','source_url','references','source_provenance','mitigation','recommended_next_steps','rule_id','alert_id','event_ref','timestamp','source_ip','destination_ip','policy_evidence','lifecycle_state','policy_id','remediation_status','provider','model','reviewer','change_notes','verification_evidence','management_status','operational_context','software_components','network_priority','observed_at','ingested_at','record_data']
    writer=csv.DictWriter(out,fieldnames=columns,extrasaction='ignore');writer.writeheader()
    def write(row):
        fields={'generated_at':payload['generated_at'],'known_limitations':'; '.join(LIMITATIONS),**row}
        writer.writerow({key:csv_value(json.dumps(value,ensure_ascii=False) if isinstance(value,(list,dict)) else value) for key,value in fields.items()})
    write({'record_type':'report_metadata','summary':payload['dataset_label']+' Local evidence export; absence of findings does not establish safety.'})
    for row in payload['findings']:write({**row,'record_type':'vulnerability_finding','record_data':row['component_sources']})
    for row in payload['asset_identity_reviews']:
        write({**row,'record_type':'asset_identity_review','status':'NEEDS_REVIEW','summary':'Asset identity needs review. No CVE conclusion was made.', 'missing_evidence':[k for k in ('vendor','product') if not row[k]],'recommended_next_steps':'Verify inventory identity with its owner.'})
    for row in payload['network_alerts']:write({**row,'record_type':'network_alert','timestamp':row['event_timestamp'],'summary':row['explanation']})
    for row in payload['remediation_plans']:write({**row,'record_type':'remediation_plan','status':row['finding_status'],'remediation_status':row['status'],'summary':row['plan']['finding_summary'],'references':row['source_urls']})
    for category,rows in payload['asset_intelligence'].items():
        for row in rows:
            write({'record_type':category,'asset_id':row.get('asset_id',''),'ip_address':row.get('ip',''),'status':row.get('status',''),
                   'observed_at':row.get('observed_at',''),'ingested_at':row.get('ingested_at',''),
                   'event_ref':row.get('event_ref',''),'source':row.get('source_file',''),'record_data':row})
    return out.getvalue()
