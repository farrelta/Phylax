"""Local operator configuration and manual inventory forms."""
from __future__ import annotations
import html
import json
from urllib.parse import urlencode
from .ai import AIConfig, local_config
from .core import Store,ASSET_FIELDS,ASSET_TYPES,ZONES,CRITICALITIES,CONFIDENCES
from .theme import layout
from .monitoring import active_policy
from .ui import e,error_summary,assist_link

ASSET_LABELS={name:name.replace('_',' ').capitalize() for name in ASSET_FIELDS}
ASSET_LABELS.update(asset_id='Asset ID',ip_address='IP address',mac_address='MAC address',last_seen='Last seen (UTC)')


def shell(title: str, body: str, *, asset_id: str = '') -> str:
    active={'Edit asset':'/assets','Add asset':'/assets','Passive network policy':'/policy','Settings and data sources':'/settings','Reports':'/reports'}.get(title,'')
    return layout(title,body,active,asset_id=asset_id)



def inventory_form(store: Store, asset_id: str = '', *, submitted=None,error='') -> str:
    row=store.connection.execute('SELECT * FROM assets WHERE asset_id=?',(asset_id,)).fetchone() if asset_id else None
    if asset_id and not row and submitted is None:raise ValueError('Asset not found')
    asset=dict(row) if row else {}
    if submitted is not None:asset.update(submitted)
    error_field=next((k for k in ASSET_FIELDS if k in error),'last_seen' if 'timestamp' in error else '')
    for name,label in ASSET_LABELS.items():error=error.replace(name,label)
    options={'asset_type':ASSET_TYPES,'zone':ZONES,'criticality':CRITICALITIES,'identity_confidence':CONFIDENCES,'verified':{'true','false'}}
    body=error_summary(error,[('asset-'+error_field,'Review '+ASSET_LABELS[error_field])] if error_field else []) if error else ''
    body+='<p>Enter operator-supplied identity evidence. Confirmed matches require verified high-confidence identity; an IP address never establishes a model or version.</p>'
    if row:
        body+='<nav class="controls" aria-label="This asset"><a href="/processes?'+e(urlencode({'asset_id':row['asset_id']}))+'">Operational context for this asset</a><a href="/approvals?'+e(urlencode({'ip':row['ip_address']}))+'">Management decisions for '+e(row['ip_address'])+'</a></nav>'
        body+='<p>'+assist_link('identity', 'Explain identity evidence', row['asset_id'], identity_type='asset')+'</p>'
    body+='<form method="post" action="/assets/save">'
    groups=(
        ('Address and identity',('asset_id','ip_address','mac_address','hostname','asset_type')),
        ('Product and software',('vendor','product','version','operating_system')),
        ('Verification and source',('identification_source','identity_confidence','verified','last_seen')),
        ('Operational classification and notes',('zone','criticality','notes')),
    )
    help_text={
        'identification_source':'Record where the identity evidence came from, such as an operator record or a passive observation.',
        'identity_confidence':'How certain is the vendor and product identity? High confidence requires supporting identity evidence. Confidence is separate from whether an operator has reviewed it.',
        'verified':'Records an operator review of the identity evidence. Verified and high confidence are both required for confirmed applicability. Verification does not approve management or grant scan permission.',
    }
    option_labels={'true':'Verified by operator','false':'Not verified','high':'High','medium':'Medium','low':'Low','critical':'Critical','unknown':'Unknown','engineering workstation':'Engineering workstation','server':'Server','network device':'Network device','gateway':'Gateway'}
    def control(name):
        value=str(asset.get(name,''))
        if name=='verified' and (submitted is None or name not in submitted):value='true' if asset.get(name) else 'false'
        if name=='identification_source' and not value:value='manual'
        if name=='last_seen' and not value:value=''
        invalid=bool(error and name==error_field)
        described=([f'asset-{name}-help'] if name in help_text else [])+([f'asset-{name}-error'] if invalid else [])
        attrs=f' id="asset-{name}" aria-labelledby="asset-{name}-label"'+(' aria-invalid="true"' if invalid else '')
        if described:attrs+=' aria-describedby="'+' '.join(described)+'"'
        result=f'<label><span id="asset-{name}-label">{e(ASSET_LABELS[name])}</span>'
        if name in options:
            defaults={'asset_type':'unknown','zone':'unknown','criticality':'medium','identity_confidence':'low','verified':'false'}
            value=value or defaults[name]
            choices=sorted(options[name])
            if value not in choices:choices.insert(0,value)
            result+=f'<select name="{name}"{attrs}>'+''.join(f'<option value="{html.escape(v,quote=True)}"'+(' selected' if v==value else '')+f'>{e(option_labels.get(v,v))}</option>' for v in choices)+'</select>'
        else:
            required=' required' if name=='ip_address' else ''
            readonly=' readonly' if name=='asset_id' and row else ''
            result+=f'<input name="{name}" value="{html.escape(value,quote=True)}" maxlength="4000"{attrs}{required}{readonly}>'
        if name in help_text:result+=f'<small id="asset-{name}-help">{e(help_text[name])}</small>'
        if invalid:result+=f'<small class="field-error" id="asset-{name}-error">{e(error)}</small>'
        return result+'</label>'
    for title,names in groups:
        body+='<fieldset class="editor"><legend>'+e(title)+'</legend><div class="form-grid">'+''.join(control(name) for name in names)+'</div></fieldset>'
    body+='<button class="primary">Save inventory and reassess findings</button></form>'
    return shell('Edit asset' if row else 'Add asset',body,asset_id=row['asset_id'] if row else '')


def policy_page(store: Store,*,submitted=None,error='') -> str:
    policy=active_policy(store)
    text=submitted.get('policy_json','') if submitted is not None else json.dumps(policy if policy is not None else {},indent=2)
    body=error_summary(error,[('policy-json','Review policy JSON')]) if error else ''
    body+='<p>'+assist_link('policy', 'Draft network policy')+'</p>'
    body+='<details class="cardx workflow"><summary>How rules work</summary><p>Policies apply only to stored passive observations. An absent rule is not a deny-all rule. An explicit empty maintenance window list prohibits writes at all times; omit that key if no maintenance restriction is configured. Overnight windows use the start day; end times are exclusive.</p>'
    body+='<p>Keys: protected_assets, allowed_communications, authorized_writers, maintenance_windows_utc. Day numbers: Monday 0 through Sunday 6. Times are UTC.</p></details>'
    body+='<section class="cardx wide" aria-labelledby="current-policy-summary"><h2 id="current-policy-summary">Current saved policy</h2>'
    if policy is None:
        body+='<p>No active policy is saved. The editor below has not been applied.</p>'
    else:
        protected=policy.get('protected_assets',[]);communications=policy.get('allowed_communications',[]);writers=policy.get('authorized_writers',{})
        def preview(items):
            return '; '.join(items[:3])+(' · '+str(len(items)-3)+' more in the policy JSON' if len(items)>3 else '')
        body+='<ul><li>'+str(len(protected))+' protected destination'+('' if len(protected)==1 else 's')+' for unexpected-communication review. '+str(len(communications))+' expected communication rule'+('' if len(communications)==1 else 's')+' recorded.</li>'
        if protected:body+='<li>Protected destinations: '+e(preview(protected))+'.</li>'
        if communications:
            rules=[str(rule['source_ip'])+' → '+str(rule['destination_ip'])+' · '+(str(rule.get('protocol') or 'any protocol'))+' · '+('destination port '+str(rule['destination_port']) if rule.get('destination_port') is not None else 'any destination port') for rule in communications]
            body+='<li>Expected communication: '+e(preview(rules))+'.</li>'
        body+='<li>Modbus writer lists are configured for '+str(len(writers))+' destination'+('' if len(writers)==1 else 's')+'. An empty writer list permits no writers for that destination; an omitted destination has no writer rule.</li>'
        if writers:
            rules=[address+': '+(', '.join(sources) if sources else 'no writers permitted') for address,sources in writers.items()]
            body+='<li>Allowed Modbus writers by destination: '+e(preview(rules))+'.</li>'
        if 'maintenance_windows_utc' not in policy:
            body+='<li>No maintenance restriction is configured.</li>'
        elif not policy['maintenance_windows_utc']:
            body+='<li>No Modbus write times are approved: the saved maintenance window list is empty.</li>'
        else:
            body+='<li>'+str(len(policy['maintenance_windows_utc']))+' approved UTC maintenance window'+('' if len(policy['maintenance_windows_utc'])==1 else 's')+'. Observed Modbus writes outside these windows raise a policy alert.</li>'
            days=('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
            windows=[(', '.join(days[day] for day in window['days']) or 'No days')+' · '+window['start']+'–'+window['end']+' UTC' for window in policy['maintenance_windows_utc']]
            body+='<li>Maintenance windows: '+e(preview(windows))+'.</li>'
        for source,destination in policy.get('denied_zone_pairs',[]):
            body+='<li>Denied zone pair: '+e(source)+' → '+e(destination)+'</li>'
        body+='</ul><p class="muted">This summary describes the saved policy. Edits below take effect only after saving and reevaluating stored events.</p>'
    body+='</section>'
    example={'protected_assets':['192.0.2.10'],'allowed_communications':[{'source_ip':'192.0.2.30','destination_ip':'192.0.2.10','protocol':'tcp','destination_port':502}],'authorized_writers':{'192.0.2.10':['192.0.2.30']},'maintenance_windows_utc':[{'days':[0,1,2,3,4],'start':'01:00','end':'02:00'}]}
    example.update(zone_subnets={'IT':['198.51.100.0/24'],'DMZ':['203.0.113.0/24'],'OT':['192.0.2.0/24']},
                   denied_zone_pairs=[['IT','OT']])
    body+='<details class="workflow"><summary>Example policy JSON — illustrative addresses, not applied</summary><p>This valid example protects one destination, records an expected TCP connection and Modbus writer, and approves writes Monday–Friday from 01:00 up to 02:00 UTC. Replace the documentation addresses with reviewed local evidence before use.</p><pre>'+e(json.dumps(example,indent=2))+'</pre></details>'
    attrs=' aria-invalid="true" aria-describedby="policy-json-error"' if error else ''
    body+=f'<form method="post" action="/policy/apply"><label><span id="policy-json-label">Policy JSON</span><textarea id="policy-json" aria-labelledby="policy-json-label" name="policy_json" rows="24" maxlength="100000"{attrs}>{html.escape(text)}</textarea>'
    if error:body+='<small class="field-error" id="policy-json-error">'+e(error)+'</small>'
    body+='</label><button class="primary">Save policy and reevaluate stored events</button></form>'
    rows=store.connection.execute('SELECT policy_id,created_at FROM network_policies ORDER BY created_at DESC LIMIT 20').fetchall()
    body+='<h2>Stored policy versions</h2><ul>'+''.join(f'<li>{r["policy_id"]} · {r["created_at"]}</li>' for r in rows)+'</ul>'
    return shell('Passive network policy',body)


def settings_page(store: Store) -> str:
    config=AIConfig.from_env()
    local = local_config()
    description=f'Configured: {config.provider} · requested model {config.model} · timeout {config.timeout_seconds} seconds' if config else 'Hosted AI disabled: configure a provider, model and key in the server environment or project .env.'
    from .ui import form,field,select,table
    from .asset_intelligence import collectors
    tone={'healthy':'','ok':'','stale':'amber','failed':'red','error':'red'}
    sources=''.join('<li><i class="sev '+tone.get(str(r['health']).lower(),'amber')+'"></i><b>'+e(r['source'])+' · '+e(r['health'])+'</b><small>'
                    +html.escape(f"last success {r['last_success_at'] or 'never'} · {r['message']}")+'</small></li>' for r in store.source_health())
    body='<div class="cards"><section class="cardx"><header><h2>Public intelligence sources</h2><a class="aux" href="/intelligence">Open intelligence</a></header>'
    body+=('<ul class="status-list">'+sources+'</ul>' if sources else '<p>No feed synchronization recorded.</p>')
    body+='<p class="muted">Source health is based on stored attempts and becomes stale after 24 hours. Opening this page performs no connectivity check.</p></section>'
    body+='<section class="cardx"><header><h2>Collection health</h2></header><div class="panel">'+table(collectors(store),[(k,k.replace('_',' ').title()) for k in ('kind','status','heartbeat','last_success','message')])+'</div></section></div>'
    body+='<section class="cardx wide"><header><h2>Recent finalized-log imports</h2></header><div class="panel">'+table([dict(r) for r in store.connection.execute('SELECT path,status,message,processed_at FROM ingestion_files ORDER BY processed_at DESC LIMIT 50')],[('path','Local file'),('status','Outcome'),('message','Diagnostics'),('processed_at','Processed UTC')])+'</div></section>'
    body+='<details class="cardx workflow"><summary>AI assistance</summary><p>'+assist_link('settings', 'Explain data and settings')+'</p><h2>Local AI</h2><p>'+e(local.model if local else 'Local AI is not configured.')+'</p>'
    body+='<h2>Hosted guidance</h2><p>'+html.escape(description)+'</p><p>Hosted requests require confirmation of the redacted request. Returned guidance remains unverified.</p></details>'
    body+='<details class="cardx workflow"><summary>Selected structured CISA advisories</summary><p>Configure official CSAF document URLs. Synchronization checks only these documents, using local cache and conditional requests.</p>'
    body+=form('/sources/csaf',field('url','Official CSAF document HTTPS URL',required=True)+select('enabled','Source',[('true','Enabled'),('false','Disabled')]),'Save advisory source')
    body+=table([dict(r) for r in store.connection.execute('SELECT url,enabled,retrieved_at FROM csaf_documents')],[('url','Document'),('enabled','Enabled'),('retrieved_at','Retrieved UTC')])+'</details>'
    body+='<details class="cardx workflow"><summary>Advanced assessment tools</summary><p>Inventory and intelligence imports reassess findings automatically. Use manual correlation to rebuild assessments from stored evidence when troubleshooting.</p>'+form('/correlate','','Reassess stored findings')+'</details>'
    return shell('Settings and data sources',body)


def reports_page(store: Store) -> str:
    from .theme import icon
    down=icon('download')
    cards=[('Readable report','Best for reading, printing or sharing with your team.','/report.md','Markdown report'),
           ('Spreadsheet','Open in Excel to sort and filter the evidence.','/report.csv','CSV report'),
           ('Complete data','Everything, including uncertainty and sources, for other tools or archiving.','/report.json','JSON report'),
           ('Device list only','Just the devices, without findings, alerts or fix plans.','/assets.csv','Inventory CSV')]
    body='<div class="report-grid">'+''.join('<section class="cardx"><h2>'+e(title)+'</h2><p>'+e(text)+'</p><a class="btn" href="'+href+'">'+down+e(label)+'</a></section>' for title,text,href,label in cards)+'</div>'
    body+='<section class="cardx wide"><header><h2>Need a short summary?</h2></header><p>Let the assistant draft a summary of the current findings for a briefing.</p><p>'+assist_link('report', 'Draft report summary')+'</p></section>'
    body+='<p class="muted">Exports contain locally stored evidence. Findings do not establish compromise.</p>'
    return shell('Reports',body)
