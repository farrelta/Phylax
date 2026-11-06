"""Decision evidence first; original records remain inspectable separately."""
from urllib.parse import urlencode
from .ui import e,field,select,form,hidden,raw_record,evidence_lines,evidence_url
from .triage import triage
from .theme import PLAIN_STATUS


def details_list(pairs):
    return '<dl class="facts">'+''.join('<div><dt>'+e(label)+'</dt><dd>'+e(value if value not in ('',None) else 'Unknown')+'</dd></div>' for label,value in pairs)+'</dl>'


def policy_lines(policy):
    lines=[]
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
    filters={k:query.get(k,[''])[0] for k in ('category','priority','acknowledged','q')}
    rows,count=triage(store,limit=50,offset=offset,filters=filters)
    body=f'<p>{count} active alert(s)'+(' matching your filters.' if any(filters.values()) else '.')+' Acknowledgement records review; it does not resolve a finding, approve a device or grant scan permission.</p>'
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
        body+='<details class="triage-case" id="alert-'+e(row['alert_id'])+'"'+(' open' if query.get('case',[''])[0]==row['alert_id'] else '')+'><summary>'
        address=' <span class="mono">'+e(row['ip'])+'</span>' if name!=row['ip'] else ''
        body+='<span class="case-title">'+e(name)+address+'</span><span class="case-subject">'+e(title)+'</span>'
        body+='<span class="case-state">'+e(priority)+' urgency · '+e(category)+' · '+e(review)+'</span><span class="case-meta">'+e(row['timestamp'])+' UTC · '+e(cue)+'</span><span class="case-inspect">Inspect alert</span></summary><div class="case-detail triage-record">'
        back_values={k:v for k,v in filters.items() if v}
        back_values.update(page=query.get('page',['1'])[0],case=row['alert_id'])
        return_to='/triage?'+urlencode(back_values)+'#alert-'+row['alert_id']
        body+='<p class="muted">Owner: '+e(ctx.get('owner') or 'Unknown')+' · Supports: '+e(', '.join(p['name'] for p in asset.get('processes',[])) or 'No confirmed process relationships')+'</p>'
        body+='<p>'+e(row['explanation'])+'</p>'
        body+=details_list([('Address',row['ip']),('Event / update time UTC',row['timestamp']),('Severity',row['severity']),('Applicability',applicability),('Evidence confidence',row['evidence_confidence']),('Review state','Acknowledged' if row['acknowledged'] else 'Unacknowledged')])
        body+='<h3>Observed evidence</h3>'
        if row['category']=='network':
            obs=row['observed']
            body+=details_list([('Source',obs['source_ip']),('Destination',obs['destination_ip']),('Destination port',obs['destination_port']),('Protocol',obs['protocol']),('Operation',obs['operation']),('Rule',row['rule_id'].replace('_',' ').title())])
            body+='<h3>Configured policy</h3><ul>'+''.join('<li>'+e(line)+'</li>' for line in policy_lines(ev.get('policy',{})))+'</ul>'
        elif row['category']=='exposure':
            body+=evidence_lines(ev)
            body+='<h3>Missing evidence</h3><ul>'+''.join('<li>'+e(v)+'</li>' for v in (row.get('missing_evidence') or ['None recorded for this assessment.']))+'</ul>'
        else:
            body+=details_list([('Monitored subnet',ev.get('subnet','Unknown')),('Observed MAC',ev.get('mac') or 'Unknown; no reliable MAC evidence'),('Management state',ev.get('status','unknown').replace('_',' ').title())])
            observations=ev.get('evidence',[])
            if observations:body+='<p>Latest identity evidence: '+e(observations[0].get('observed_at','Unknown'))+' · '+e(observations[0].get('source_file','Unknown source'))+'</p>'
        body+='<h3>Operational context</h3>'+details_list([('Location',' / '.join(v for v in (ctx.get('site'),ctx.get('location')) if v)),('Asset criticality',asset.get('criticality','unknown'))])
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
            links+=['<a href="'+e(evidence_url(ev.get('event_ref',''),return_to))+'">Original event</a>','<a href="/policy">Review network policy</a>']
        if row['category']=='endpoint':links.append('<a href="/approvals?'+e(urlencode({'ip':row['ip']}))+'">Review management approval</a>')
        body+='<div class="record-actions">'+' '.join(links)
        if not row['acknowledged']:
            fields=hidden('category',row['category'])+hidden('alert_id',row['alert_id'])
            fields+=''.join(hidden('filter_category' if k=='category' else k,v) for k,v in filters.items())+hidden('page',query.get('page',['1'])[0])
            body+=form('/triage/ack',fields,'Acknowledge this alert')
        body+='</div>'+raw_record(row)+'</div></details>'
    return body,count
