"""Decision evidence first; original records remain inspectable separately."""
from urllib.parse import urlencode
from .ui import verbatim, e,field,select,form,hidden,raw_record,evidence_lines,evidence_url,assist_link
from .triage import ZONE_RULE, alert_url, triage, zone_pair
from .theme import PLAIN_STATUS, pill
from .topology import alert_topology_url


def plain(text):
    for code,label in PLAIN_STATUS.items():
        text=str(text).replace(code,label)
    return text


def details_list(pairs):
    return '<dl class="facts">'+''.join('<div><dt>'+e(label)+'</dt><dd>'+e(value if value not in ('',None) else 'Unknown')+'</dd></div>' for label,value in pairs)+'</dl>'


def policy_lines(policy):
    lines=[]
    if 'source_zone' in policy:
        lines.append('Denied zone pair: '+zone_pair(policy))
        lines.append('Policy version: '+policy['policy_id'])
    if 'configured_authorized_writers' in policy:
        lines.append('Authorized writers: '+(', '.join(policy['configured_authorized_writers']) or 'No writers permitted.'))
    if 'expected_communications' in policy:
        for r in policy['expected_communications']:
            lines.append('Allowed: '+str(r.get('source_ip','unknown'))+' → '+str(r.get('destination_ip','unknown'))+' · '+str(r.get('protocol') or 'any protocol')+' · destination port '+str(r.get('destination_port') if r.get('destination_port') is not None else 'any'))
    for key in ('approved_maintenance_windows_utc','maintenance_windows_utc','configured_windows','approved_windows'):
        if key in policy:
            if not policy[key]:lines.append('No approved maintenance windows in this policy.')
            for window in policy[key]:
                days=['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
                lines.append('Approved UTC window: '+', '.join(days[d] for d in window.get('days',[]) if type(d) is int and 0<=d<7)+' '+str(window.get('start','unknown'))+'–'+str(window.get('end','unknown')))
    return lines or ['Review the policy evidence in the original record.']


def triage_page(store,query,offset):
    alert_id=query.get('alert',[''])[0]
    filters={k:query.get(k,[''])[0] for k in ('category','priority','acknowledged','q')}
    if alert_id:
        rows,count=triage(store,alert_id=alert_id,history=True)
        body='<p><a href="/triage">View all alerts</a></p>'
        if not rows:
            return body+'<p class="empty">This network alert could not be found.</p>',count
    else:
        rows,count=triage(store,limit=50,offset=offset,filters=filters)
        body=''
        if not any(filters.values()):
            _,new=triage(store,limit=1,filters={'category':'','priority':'','acknowledged':'no','q':''})
            if not count:
                body+='<section class="hero hero-ok"><div><strong>No active alerts</strong><p>This only covers the data loaded so far. No alerts does not mean the devices are safe.</p></div></section>'
            elif new:
                body+=f'<section class="hero hero-bad"><div><strong>{new} alerts need a look</strong><p>Open an alert, read what happened and what to do, then acknowledge it. Acknowledging only records that someone reviewed it. It changes nothing on the device.</p></div><a class="btn primary" href="/triage?acknowledged=no">Show new alerts</a></section>'
            else:
                body+=f'<section class="hero hero-ok"><div><strong>All {count} alerts have been reviewed</strong><p>New alerts appear here after new data is imported.</p></div></section>'
        body+=f'<p>{count} active alert(s)'+(' matching your filters.' if any(filters.values()) else '.')+' Acknowledgement records review; it does not resolve a finding, approve a device or grant scan permission.</p>'
        body+='<form method="get" class="filter-bar">'+field('q','Search asset, address, CVE or explanation',filters['q'])
        body+=select('category','Category',[('','All categories'),('exposure','Vulnerability exposure'),('network','Network policy'),('endpoint','Device management')],filters['category'])
        body+=select('priority','Urgency',[('','All urgency levels')]+[(v,v.replace('_',' ').title()) for v in ('critical','high','medium','low','not_applicable')],filters['priority'])
        body+=select('acknowledged','Review state',[('','All review states'),('no','Unacknowledged'),('yes','Acknowledged')],filters['acknowledged'])
        body+='<button>Filter alerts</button><a href="/triage">Clear filters</a></form>'
        if not rows:
            return body+('<p class="empty">No alerts match these filters. <a href="/triage">Clear filters</a>.</p>' if any(filters.values()) else '<p class="empty">No active alerts in stored data. <a href="/network">Inspect imported events</a> or <a href="/settings">check source and collector health</a>. No alerts does not establish safety.</p>'),count
    for row in rows:
        asset=row['context'];ctx=asset.get('operational_context',{});urgency=row['urgency'];ev=row['evidence']
        name=asset.get('hostname') or row['ip'];category={'exposure':'Vulnerability exposure','network':'Network policy','endpoint':'Device management'}[row['category']]
        applicability=PLAIN_STATUS.get(row['applicability'],'Not assessed (network / management alert)')
        priority=urgency['priority'].replace('_',' ').title()
        rule=row.get('rule_id','').replace('_',' ').title()
        title=row.get('cve_id') or rule or row['explanation']
        review='Acknowledged' if row['acknowledged'] else 'Unacknowledged'
        missing=len(row.get('missing_evidence') or [])
        cue=(str(missing)+' missing evidence item'+('' if missing==1 else 's') if missing else 'No missing evidence recorded') if row['category']=='exposure' else ('Observed policy event' if row['category']=='network' else 'Identity evidence needs review')
        zone_violation=row.get('rule_id')==ZONE_RULE
        tone={'critical':'crit','high':'high','medium':'info'}.get(urgency['priority'],'none')
        if row['category']=='exposure':
            what_to_do='Check that the device\'s make, model and version are correct, then read the finding and create a fix plan if it applies.'
        elif zone_violation:
            what_to_do='Find out whether this connection was expected. If it was not, contact the device owner and check the network rules.'
        elif row['category']=='network':
            what_to_do='Check whether this network activity was expected, for example a planned maintenance change. If not, review the network rules and ask the device owner.'
        else:
            what_to_do='Confirm whether this device should be on this network, then record a decision on the Approvals page.'
        expanded=alert_id or query.get('case',[''])[0]==row['alert_id']
        body+='<details class="triage-case" id="alert-'+e(row['alert_id'])+'"'+(' open' if expanded else '')+'><summary>'
        address=' <span class="mono">'+e(row['ip'])+'</span>' if name!=row['ip'] else ''
        body+='<span class="case-title">'+verbatim(name)+address+' '+pill(priority.lower(),tone)+'</span><span class="case-subject">'+e(title)+'</span>'
        body+='<span class="case-state">'+e(priority)+' urgency · '+e(category)+' · '+e(review)+'</span><span class="case-meta">'+e(row['timestamp'])+' UTC · '+e(cue)+'</span><span class="case-inspect">Inspect alert</span></summary><div class="case-detail triage-record"><h3>What to do</h3><p>'+e(what_to_do)+'</p>'
        back_values={k:v for k,v in filters.items() if v}
        back_values.update(page=query.get('page',['1'])[0],case=row['alert_id'])
        return_to=alert_url(alert_id) if alert_id else '/triage?'+urlencode(back_values)+'#alert-'+row['alert_id']
        if row['state']=='resolved':
            body+='<p class="notice">This policy alert was resolved after reevaluation.</p>'
        body+='<p>'+assist_link('alert', 'Explain alert', row['alert_id'])+'</p>'
        if zone_violation:
            obs=row['observed'];policy=ev['policy']
            body+='<h3>Observed connection</h3><p class="mono">'+e(obs['source_ip']+' → '+obs['destination_ip'])+'</p>'
            body+='<p>'+e(plain(row['explanation']))+'</p><ul>'+''.join('<li>'+e(line)+'</li>' for line in policy_lines(policy))+'</ul>'
            body+='<div class="record-actions"><a class="btn" href="'+e(evidence_url(ev['event_ref'],return_to))+'">Original event</a>'
            body+='<a href="'+e(alert_topology_url(row['alert_id']))+'">Show on topology</a></div>'
            body+=details_list([('Event / update time UTC',row['timestamp']),('Protocol',obs['protocol']),
                                ('Destination port',obs['destination_port']),('Severity',row['severity']),
                                ('Evidence confidence',row['evidence_confidence'])])
        else:
            body+='<p class="muted">Owner: '+(verbatim(ctx['owner']) if ctx.get('owner') else e('Unknown'))+' · Supports: '+(verbatim(', '.join(p['name'] for p in asset['processes'])) if asset.get('processes') else e('No confirmed process relationships'))+'</p>'
            body+='<p>'+e(plain(row['explanation']))+'</p>'
            body+=details_list([('Address',row['ip']),('Event / update time UTC',row['timestamp']),('Severity',row['severity']),('Applicability',applicability),('Evidence confidence',row['evidence_confidence']),('Review state',review)])
            body+='<h3>Observed evidence</h3>'
        if row['category']=='network' and not zone_violation:
            obs=row['observed']
            body+=details_list([('Source',obs['source_ip']),('Destination',obs['destination_ip']),('Destination port',obs['destination_port']),('Protocol',obs['protocol']),('Operation',obs['operation']),('Rule',row['rule_id'].replace('_',' ').title())])
            body+='<h3>Configured policy</h3><ul>'+''.join('<li>'+e(line)+'</li>' for line in policy_lines(ev.get('policy',{})))+'</ul>'
        elif row['category']=='exposure':
            body+=evidence_lines(ev)
            body+='<h3>Missing evidence</h3><ul>'+''.join('<li>'+e(v)+'</li>' for v in (row.get('missing_evidence') or ['None recorded for this assessment.']))+'</ul>'
        elif row['category']=='endpoint':
            body+=details_list([('Monitored subnet',ev.get('subnet','Unknown')),('Observed MAC',ev.get('mac') or 'Unknown; no reliable MAC evidence'),('Management state',ev.get('status','unknown').replace('_',' ').title())])
            observations=ev.get('evidence',[])
            if observations:body+='<p>Latest identity evidence: '+e(observations[0].get('observed_at','Unknown'))+' · '+e(observations[0].get('source_file','Unknown source'))+'</p>'
        body+='<h3>Operational context</h3>'+details_list([('Location',' / '.join(v for v in (ctx.get('site'),ctx.get('location')) if v)),('Asset criticality',asset.get('criticality','unknown'))])
        if zone_violation and (ctx.get('owner') or asset.get('processes')):
            body+=details_list([('Owner',ctx.get('owner')),('Supports',', '.join(p['name'] for p in asset['processes']))])
        score=urgency['score']
        body+='<details class="score-details"><summary>Why '+e(priority.lower())+' urgency'+(' · score '+e(score) if score is not None else '')+'</summary><p>Rule '+e(urgency['rule_version'])+'. Severity, applicability and urgency are separate.</p><ul>'
        for factor in urgency['factors']:
            value=factor['value']
            if isinstance(value,bool):value='Yes' if value else 'No'
            else:value=PLAIN_STATUS.get(str(value),str(value))
            body+='<li>'+e(factor['input'])+': '+e(value)+' · +'+e(factor['points'])+'</li>'
        body+='</ul>'+''.join('<p class="muted">'+e(v)+'</p>' for v in urgency.get('uncertainty',[]))+'</details>'
        links=[]
        if asset.get('asset_id'):
            links+=['<a href="/assets/edit?'+e(urlencode({'asset_id':asset['asset_id']}))+'">Review asset</a>',
                    '<a href="/processes?'+e(urlencode({'asset_id':asset['asset_id']}))+'">Operational context</a>']
        if row.get('finding_id'):links.append('<a href="/?'+e(urlencode({'finding_id':row['finding_id']}))+'#finding-'+e(row['finding_id'])+'">Open vulnerability finding</a>')
        if row['category']=='network':
            if not zone_violation:
                links.append('<a href="'+e(evidence_url(ev.get('event_ref',''),return_to))+'">Original event</a>')
            links.append('<a href="/policy">Review network policy</a>')
        if row['category']=='endpoint':links.append('<a href="/approvals?'+e(urlencode({'ip':row['ip']}))+'">Review management approval</a>')
        body+='<div class="record-actions">'+' '.join(links)
        if not row['acknowledged'] and row['state']=='active':
            fields=hidden('category',row['category'])+hidden('alert_id',row['alert_id'])
            if alert_id:
                fields+=hidden('alert',alert_id)
            else:
                fields+=''.join(hidden('filter_category' if k=='category' else k,v) for k,v in filters.items())+hidden('page',query.get('page',['1'])[0])
            body+=form('/triage/ack',fields,'Acknowledge this alert')
        body+='</div>'+raw_record(row)+'</div></details>'
    return body,count
