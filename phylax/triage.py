"""Shared, deterministic triage projection. Reading does not alter acknowledgements."""
import json
from .prioritization import prioritize,network_priority
from .asset_intelligence import management_status,collectors


def chunks(values,size=400):
    values=list(dict.fromkeys(values))
    for offset in range(0,len(values),size):yield values[offset:offset+size]


def asset_index(store,ips,*,complete=False):
    """Resolve each IP once using the same verified/confidence precedence."""
    assets={}
    for batch in chunks(ips):
        columns='a.*' if complete else 'a.asset_id,a.ip_address,a.hostname,a.criticality,a.identity_confidence,a.identification_source,a.verified'
        rows=store.connection.execute('SELECT '+columns+',c.criticality_rationale AS context_rationale FROM assets a LEFT JOIN asset_context c USING(asset_id) WHERE a.ip_address IN ('+','.join('?' for _ in batch)+') ORDER BY a.verified DESC,a.identity_confidence DESC,a.rowid',batch)
        for row in rows:
            asset=dict(row);ip=asset['ip_address']
            if ip in assets:continue
            rationale=asset.pop('context_rationale')
            if asset['identification_source']=='zeek_passive' and not asset['verified'] and not rationale:
                asset['criticality']='unknown'
                asset['criticality_note']='Automatic inventory default is not verified operational criticality'
            assets[ip]=asset
    if complete:
        by_id={r['asset_id']:r for r in assets.values()}
        for asset in assets.values():asset['processes']=[]
        for batch in chunks(by_id):
            marks=','.join('?' for _ in batch)
            for row in store.connection.execute('SELECT * FROM asset_context WHERE asset_id IN ('+marks+')',batch):
                by_id[row['asset_id']]['operational_context']=dict(row)
            for row in store.connection.execute('SELECT p.*,l.asset_id AS linked_asset_id,l.actor,l.note FROM processes p JOIN process_links l USING(process_id) WHERE l.asset_id IN ('+marks+')',batch):
                value=dict(row);aid=value.pop('linked_asset_id');by_id[aid]['processes'].append(value)
    return assets


def unknown_context():
    return {'criticality':'unknown','identity_confidence':'unknown','processes':[]}


def context(store,ip):
    return asset_index(store,[ip],complete=True).get(ip,unknown_context())


def _hydrate_evidence(store,items):
    """Read and decode large evidence only for the requested page (or export)."""
    for category in ('exposure','network','endpoint'):
        selected={r['alert_id']:r for r in items if r['category']==category}
        for batch in chunks(selected):
            marks=','.join('?' for _ in batch)
            if category=='exposure':
                sql='SELECT a.alert_id,f.evidence,f.missing_evidence FROM alerts a JOIN findings f USING(finding_id) WHERE a.alert_id IN ('+marks+')'
            elif category=='network':sql='SELECT alert_id,policy_evidence FROM network_alerts WHERE alert_id IN ('+marks+')'
            else:sql='SELECT alert_id,evidence_json FROM endpoint_alerts WHERE alert_id IN ('+marks+')'
            for row in store.connection.execute(sql,batch):
                item=selected[row['alert_id']]
                if category=='exposure':
                    item['evidence']=json.loads(row['evidence']);item['missing_evidence']=json.loads(row['missing_evidence'])
                elif category=='network':item['evidence']['policy']=json.loads(row['policy_evidence'])
                else:item['evidence']=json.loads(row['evidence_json'])


def triage(store,*,limit=None,offset=0,history=False,filters=None):
    # A watcher/worker may update evidence concurrently. Keep ranking and the
    # selected page's evidence in one SQLite read snapshot.
    with store.atomic('triage_projection'):
        return _triage(store,limit=limit,offset=offset,history=history,filters=filters)


def _triage(store,*,limit=None,offset=0,history=False,filters=None):
    from .monitoring import active_policy
    filters=filters or {}
    for key,choices in [('category',{'exposure','network','endpoint'}),('priority',{'critical','high','medium','low','not_applicable'}),('acknowledged',{'yes','no'})]:
        if filters.get(key) and filters[key] not in choices:raise ValueError('Invalid triage '+key+' filter')
    policy=active_policy(store) or {};protected=set(policy.get('protected_assets',[]));items=[]
    ack=filters.get('acknowledged');category=filters.get('category')
    where=' WHERE a.acknowledged='+('1' if ack=='yes' else '0') if ack else ''
    if category in (None,'','exposure'):
        sql='SELECT a.alert_id,a.acknowledged,a.explanation,f.finding_id,f.status,a.updated_at,s.ip_address,s.criticality,s.zone,v.severity,v.kev,v.cve_id FROM alerts a JOIN findings f USING(finding_id) JOIN assets s USING(asset_id) JOIN vulnerabilities v USING(cve_id)'+where
        for row in store.connection.execute(sql):
            row=dict(row);urgency=prioritize(row,row,row['status'])
            items.append({'category':'exposure','alert_id':row['alert_id'],'ip':row['ip_address'],'severity':row['severity'] or 'unknown',
                          'applicability':row['status'],'acknowledged':bool(row['acknowledged']),'state':'active','timestamp':row['updated_at'],
                          'explanation':row['explanation'],'urgency':urgency,'finding_id':row['finding_id'],'cve_id':row['cve_id']})
    if category in (None,'','network'):
        sql="SELECT a.alert_id,a.rule_id,a.event_id,a.severity,a.explanation,a.acknowledged,e.source_ip,e.destination_ip,e.source_port,e.destination_port,e.protocol,e.operation,e.timestamp,e.event_ref,e.source_file,COALESCE(l.state,'active') AS lifecycle FROM network_alerts a JOIN network_events e USING(event_id) LEFT JOIN network_alert_lifecycle l USING(alert_id)"+where
        if not history:sql+=(" AND " if where else " WHERE ")+"COALESCE(l.state,'active')='active'"
        for row in store.connection.execute(sql):
            row=dict(row)
            items.append({'category':'network','alert_id':row['alert_id'],'ip':row['destination_ip'],'severity':row['severity'],
                          'applicability':'not_assessed','acknowledged':bool(row['acknowledged']),'state':row['lifecycle'],'timestamp':row['timestamp'],
                          'explanation':row['explanation'],'evidence':{'event_ref':row['event_ref'],'source_file':row['source_file']},
                          'event_id':row['event_id'],'rule_id':row['rule_id'],'observed':{k:row[k] for k in ('source_ip','destination_ip','source_port','destination_port','protocol','operation')}})
    if category in (None,'','endpoint'):
        sql='SELECT a.alert_id,a.ip,a.severity,a.acknowledged,a.state,a.last_seen,a.status FROM endpoint_alerts a'+where
        if not history:sql+=(" AND " if where else " WHERE ")+"a.state='active'"
        labels={'unmanaged':'Unmanaged endpoint—needs review','unauthorized':'Unauthorized endpoint—explicitly blocked','needs_identity_review':'Endpoint identity needs review','approved':'Approved endpoint'}
        for row in store.connection.execute(sql):
            row=dict(row)
            items.append({'category':'endpoint','alert_id':row['alert_id'],'ip':row['ip'],'severity':row['severity'],'applicability':'not_assessed',
                          'acknowledged':bool(row['acknowledged']),'state':row['state'],'timestamp':row['last_seen'],'explanation':labels[row['status']]})
    identities=asset_index(store,(r['ip'] for r in items))
    term=filters.get('q','')[:200].casefold()
    matching=[]
    for item in items:
        asset=identities.get(item['ip'],unknown_context())
        if item['category']!='exposure':
            item['urgency']=network_priority(item['severity'],asset['criticality'],item['category']=='network' and item['ip'] in protected)
        if filters.get('priority') and item['urgency']['priority']!=filters['priority']:continue
        if term and term not in ' '.join(str(v) for v in (item['ip'],asset.get('hostname',''),item['explanation'],item.get('cve_id',''),item.get('observed',{}).get('source_ip',''))).casefold():continue
        matching.append(item)
    order={'critical':0,'high':1,'medium':2,'low':3,'not_applicable':4}
    matching.sort(key=lambda x:(order.get(x['urgency']['priority'],5),x['acknowledged'],x['alert_id']))
    total=len(matching)
    selected=matching[max(0,offset):max(0,offset)+min(100,max(0,limit))] if limit is not None else matching
    contexts=asset_index(store,(r['ip'] for r in selected),complete=True)
    for item in selected:
        item['context']=contexts.get(item['ip'],unknown_context())
        item['evidence_confidence']=({'CONFIRMED_MATCH':'high','POTENTIAL_MATCH':'medium','NEEDS_REVIEW':'low'}.get(item['applicability'],'observed event; asset identity '+item['context'].get('identity_confidence','unknown')))
    _hydrate_evidence(store,selected)
    return selected,total


def acknowledge(store,category,alert_id):
    if category=='endpoint':
        if not store.connection.execute('UPDATE endpoint_alerts SET acknowledged=1 WHERE alert_id=?',(alert_id,)).rowcount:raise ValueError('Alert not found')
        store.audit('endpoint_alert_acknowledged',alert_id,{});store.connection.commit()
    elif category in {'network','exposure'}:
        if not store.acknowledge(alert_id):raise ValueError('Alert not found')
    else:raise ValueError('Invalid alert category')


def release_data(store):
    data={name:[dict(r) for r in store.connection.execute('SELECT * FROM '+name)] for name in
          ('asset_context','processes','process_links','asset_changes','software_components','component_assessments',
           'scan_targets','scan_schedules','scan_runs','monitored_subnets','endpoint_decisions','ingestion_files')}
    data['management']=[management_status(store,r[0]) for r in store.connection.execute(
        'SELECT ip_address FROM assets UNION SELECT ip FROM observations')]
    data['collectors']=collectors(store)
    data['triage']=triage(store,history=True)[0]
    for table in data:
        for row in data[table]:
            for key in list(row):
                if key.endswith('_json'):
                    row[key[:-5]]=json.loads(row.pop(key))
    return data
