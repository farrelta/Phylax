"""Orient original event records without changing their underlying evidence."""
import json
from .ui import e,raw_record,local_return


def facts(pairs):
    return '<dl class="facts">'+''.join('<div><dt>'+e(k)+'</dt><dd>'+e(v if v not in ('',None) else 'Unknown')+'</dd></div>' for k,v in pairs)+'</dl>'


def event_page(store,query):
    ref=query.get('event_ref',[''])[0]
    back=local_return(query.get('return_to',['/network'])[0])
    label='Return to triage case' if back.startswith('/triage') else 'Return to topology' if back.startswith('/attack-surface') else 'Return to network events'
    body='<p><a href="'+e(back)+'">'+label+'</a></p>'
    events=[dict(r) for r in store.connection.execute('SELECT * FROM network_events WHERE event_ref=?',(ref,))]
    observations=[dict(r) for r in store.connection.execute('SELECT * FROM observations WHERE event_ref=? ORDER BY kind,ip',(ref,))]
    if not events and not observations:
        return body+'<p class="empty">No stored event matches this reference. <a href="/network">Review network events</a>.</p>'
    if events:
        event=events[0]
        body+='<h2>Observed communication</h2>'+facts([
            ('Source',event['source_ip']),('Destination',event['destination_ip']),
            ('Observed UTC',event['timestamp']),('Protocol',event['protocol']),
            ('Source port',event['source_port']),('Destination port',event['destination_port']),
            ('Operation',event['operation']),('Imported source',event['source_file'])])
        alerts=[dict(r) for r in store.connection.execute("SELECT a.rule_id,a.severity,a.explanation,COALESCE(l.state,'active') AS lifecycle,l.policy_id FROM network_alerts a LEFT JOIN network_alert_lifecycle l USING(alert_id) WHERE a.event_id=?",(event['event_id'],))]
        if alerts:
            body+='<h2>Policy conclusions associated with this event</h2><ul>'+''.join('<li><b>'+e(r['rule_id'].replace('_',' ').title())+'</b> · '+e(r['severity'])+' · '+('Active conclusion' if r['lifecycle']=='active' else 'Historical conclusion · '+e(r['lifecycle']))+'<p>'+e(r['explanation'])+'</p><small>Stored policy: '+e(r['policy_id'] or 'Not recorded')+'</small></li>' for r in alerts)+'</ul><p><a href="/policy">Review configured network policy</a></p>'
    else:
        body+='<h2>Observed endpoint evidence</h2>'+facts([('Addresses',', '.join(dict.fromkeys(r['ip'] for r in observations))),('Observed UTC',observations[0]['observed_at']),('Imported source',observations[0]['source_file'])])
    body+='<p class="muted">Event reference: <span class="mono">'+e(ref)+'</span></p><p>'+str(len(events)+len(observations))+' stored record(s). Normalized records and original payloads are available below.</p>'
    for event in events:
        body+=raw_record(event,'Network event · '+event['event_type']+' · '+event['source_ip']+' → '+event['destination_ip'])
        body+=raw_record(json.loads(event['raw_json']),'Original imported network payload · '+event['source_file'])
    for row in observations:
        body+=raw_record(row,'Endpoint observation · '+row['kind'].replace('_',' ')+' · '+row['ip']+' · '+row['observed_at'])
    return body
