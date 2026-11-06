"""Local asset decisions and observations; approval never grants scan permission."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime,timezone,timedelta
from .core import utc_now


def identifier(*values):
    return str(uuid.uuid5(uuid.NAMESPACE_URL,json.dumps(values,sort_keys=True)))


def text(value, limit=4000):
    if not isinstance(value,str) or len(value)>limit:raise ValueError('Expected a bounded text field')
    return value.strip()


def actor_note(actor,note):
    actor,note=text(actor,120),text(note)
    if not actor or not note:raise ValueError('Operator name and note are required')
    return actor,note


def address(value):
    ip=ipaddress.ip_address(text(value,80))
    if ip.is_unspecified or ip.is_multicast or str(ip)=='255.255.255.255':raise ValueError('Expected an endpoint address')
    return str(ip)


def mac_address(value):
    value=text(value,17).lower().replace('-',':')
    if value and (not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',value) or int(value[:2],16)&1 or value=='00:00:00:00:00:00'):
        raise ValueError('Expected a unicast six-octet MAC address')
    return value


def context_revision(store,asset_id):
    row=store.connection.execute('SELECT * FROM asset_context WHERE asset_id=?',(asset_id,)).fetchone()
    return hashlib.sha256(json.dumps(dict(row) if row else None,sort_keys=True).encode()).hexdigest()


def save_context(store,asset_id,*,owner='',site='',location='',lifecycle='unknown',tags=None,criticality_rationale='',expected_revision=None):
    if not store.connection.execute('SELECT 1 FROM assets WHERE asset_id=?',(asset_id,)).fetchone():raise ValueError('Asset not found')
    if lifecycle not in {'unknown','acquisition','deployed','commissioned','maintenance','decommissioned'}:raise ValueError('Invalid lifecycle')
    tags=[] if tags is None else tags
    if not isinstance(tags,list) or len(tags)>30:raise ValueError('Expected at most 30 tags')
    values=[text(v) for v in (owner,site,location,lifecycle)]
    with store.atomic('context_update'):
        if expected_revision is not None and expected_revision!=context_revision(store,asset_id):
            raise ValueError('This context changed after you opened it. Your input is retained below; reload the current record before saving.')
        store.connection.execute('INSERT OR REPLACE INTO asset_context VALUES(?,?,?,?,?,?,?,?)',
            (asset_id,*values,json.dumps([text(v,100) for v in tags]),text(criticality_rationale),utc_now()))
        store.audit('asset_context_changed',asset_id,{'owner':owner,'lifecycle':lifecycle})
    store.connection.commit()


def save_process(store,name,description,asset_id,actor,note):
    actor,note=actor_note(actor,note);name=text(name,200)
    if not name:raise ValueError('Process name is required')
    if not store.connection.execute('SELECT 1 FROM assets WHERE asset_id=?',(asset_id,)).fetchone():raise ValueError('Asset not found')
    pid=identifier('process',name)
    with store.atomic('process_link'):
        store.connection.execute('INSERT INTO processes VALUES(?,?,?) ON CONFLICT(process_id) DO UPDATE SET description=excluded.description',(pid,name,text(description)))
        store.connection.execute('INSERT OR REPLACE INTO process_links VALUES(?,?,?,?)',(asset_id,pid,actor,note))
        store.audit('process_link_confirmed',asset_id,{'process_id':pid,'actor':actor,'note':note})
    store.connection.commit();return pid


def add_subnet(store,name,cidr):
    name=text(name,120)
    if not name:raise ValueError('Subnet name is required')
    net=ipaddress.ip_network(text(cidr,80),strict=True)
    for row in store.connection.execute('SELECT cidr FROM monitored_subnets'):
        old=ipaddress.ip_network(row[0])
        if old.version==net.version and old.overlaps(net):raise ValueError('Overlapping monitored subnets are unsupported')
    sid=identifier('subnet',str(net))
    store.connection.execute('INSERT INTO monitored_subnets VALUES(?,?,?)',(sid,name,str(net)))
    store.audit('subnet_added',sid,{'name':name,'cidr':str(net)})
    reevaluate_endpoints(store);store.connection.commit();return sid


def unlink_process(store,asset_id,process_id,actor,note):
    actor,note=actor_note(actor,note)
    if not store.connection.execute('DELETE FROM process_links WHERE asset_id=? AND process_id=?',(asset_id,process_id)).rowcount:raise ValueError('Process relationship not found')
    store.audit('process_link_removed',asset_id,{'process_id':process_id,'actor':actor,'note':note});store.connection.commit()


def endpoint_decision(store,subnet_id,ip='',mac='',decision='approved',actor='',note=''):
    actor,note=actor_note(actor,note)
    if decision not in {'approved','blocked'}:raise ValueError('Invalid endpoint decision')
    row=store.connection.execute('SELECT cidr FROM monitored_subnets WHERE subnet_id=?',(subnet_id,)).fetchone()
    if not row:raise ValueError('Subnet not found')
    ip=address(ip) if ip else '';mac=mac_address(mac)
    if not ip and not mac:raise ValueError('IP or MAC is required')
    if ip and ipaddress.ip_address(ip) not in ipaddress.ip_network(row[0]):raise ValueError('IP is outside subnet')
    did=identifier('decision',subnet_id,ip,mac)
    store.connection.execute('INSERT INTO endpoint_decisions VALUES(?,?,?,?,?,?,?,1,?) ON CONFLICT(decision_id) DO UPDATE SET decision=excluded.decision,actor=excluded.actor,note=excluded.note,active=1,created_at=excluded.created_at',
        (did,subnet_id,ip,mac,decision,actor,note,utc_now()))
    store.audit('endpoint_decision',did,{'decision':decision,'actor':actor,'note':note})
    reevaluate_endpoints(store);store.connection.commit();return did


def revoke_decision(store,decision_id,actor,note):
    actor,note=actor_note(actor,note)
    if not store.connection.execute('UPDATE endpoint_decisions SET active=0 WHERE decision_id=?',(decision_id,)).rowcount:raise ValueError('Decision not found')
    store.audit('endpoint_decision_revoked',decision_id,{'actor':actor,'note':note})
    reevaluate_endpoints(store);store.connection.commit()


def management_status(store,ip):
    try:ip=address(ip)
    except ValueError:return {'status':'unmonitored','ip':ip,'mac':'','evidence':[],'reason':'Not a unicast endpoint identity'}
    subnet=next((dict(r) for r in store.connection.execute('SELECT * FROM monitored_subnets') if ipaddress.ip_address(ip) in ipaddress.ip_network(r['cidr'])),None)
    if subnet:
        net=ipaddress.ip_network(subnet['cidr'])
        if net.version==4 and net.prefixlen<31 and ipaddress.ip_address(ip) in {net.network_address,net.broadcast_address}:subnet=None
    if not subnet:return {'status':'unmonitored','ip':ip,'mac':'','evidence':[]}
    observed=store.connection.execute("SELECT * FROM observations WHERE ip=? AND mac!='' ORDER BY observed_at DESC LIMIT 1",(ip,)).fetchone()
    mac=observed['mac'] if observed else ''
    evidence=[dict(observed)] if observed else []
    decisions=[dict(r) for r in store.connection.execute('SELECT * FROM endpoint_decisions WHERE subnet_id=? AND active=1',(subnet['subnet_id'],))]
    matched=[r for r in decisions if (not r['ip'] or r['ip']==ip) and (not r['mac'] or r['mac']==mac)]
    status='unauthorized' if any(r['decision']=='blocked' for r in matched) else 'approved' if matched else 'unmanaged'
    if not matched and any(r['mac'] and (not r['ip'] or r['ip']==ip) for r in decisions) and not mac:status='needs_identity_review'
    if status=='unmanaged' and any(r['ip']==ip and r['mac'] and r['mac']!=mac for r in decisions):status='needs_identity_review'
    confirmed=[r['mac_address'].lower().replace('-',':') for r in store.connection.execute("SELECT mac_address FROM assets WHERE ip_address=? AND verified=1 AND mac_address!=''",(ip,))]
    if status!='unauthorized' and mac and confirmed and mac not in confirmed:status='needs_identity_review'
    if observed:
        conflicts=store.connection.execute("SELECT COUNT(DISTINCT mac) FROM observations WHERE ip=? AND observed_at=? AND mac!=''",(ip,observed['observed_at'])).fetchone()[0]
        if conflicts>1 and status!='unauthorized':status='needs_identity_review'
    return {'status':status,'ip':ip,'mac':mac,'subnet_id':subnet['subnet_id'],'subnet':subnet['name'],'evidence':evidence,'decisions':[r for r in decisions if r in matched or r['ip']==ip]}


def change(store,ip,kind,when,evidence):
    key=identifier('change',ip,kind,when,evidence)
    store.connection.execute('INSERT OR IGNORE INTO asset_changes VALUES(?,?,?,?,?,?)',(key,ip,kind,when,utc_now(),json.dumps(evidence,sort_keys=True)))


def observe(store,*,kind,ip,when,source_file,event_ref,raw,mac=''):
    from .validation import utc_timestamp
    when=utc_timestamp(when)
    if not when:raise ValueError('Observed timestamp is required')
    ip=address(ip);mac=mac_address(mac)
    for subnet in store.connection.execute('SELECT cidr FROM monitored_subnets'):
        net=ipaddress.ip_network(subnet[0])
        if net.version==4 and net.prefixlen<31 and ipaddress.ip_address(ip) in {net.network_address,net.broadcast_address}:return False
    oid=identifier('observation',kind,ip,event_ref)
    previous=store.connection.execute('SELECT 1 FROM observations WHERE ip=? LIMIT 1',(ip,)).fetchone()
    cursor=store.connection.execute('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?)',
        (oid,kind,ip,mac,when,utc_now(),source_file,event_ref,json.dumps(raw,sort_keys=True)))
    if not cursor.rowcount:return False
    store.observe_ip(ip,when)
    if not previous:change(store,ip,'first_observed',when,{'observation_id':oid,'source_file':source_file})
    if mac:
        old=store.connection.execute("SELECT mac,observed_at FROM observations WHERE ip=? AND mac!='' AND observation_id!=? ORDER BY observed_at DESC LIMIT 1",(ip,oid)).fetchone()
        if old and old['mac']!=mac and old['observed_at']<=when:
            change(store,ip,'ip_mac_changed',when,{'previous_mac':old['mac'],'observed_mac':mac,'observation_id':oid})
        peer=store.connection.execute('SELECT ip,observed_at FROM observations WHERE mac=? AND ip!=? ORDER BY observed_at DESC LIMIT 1',(mac,ip)).fetchone()
        if peer and peer['observed_at']<=when:change(store,ip,'mac_ip_association_changed',when,{'previous_ip':peer['ip'],'observed_ip':ip,'mac':mac,'observation_id':oid})
    evaluate_endpoint(store,ip)
    return True


def evaluate_endpoint(store,ip):
    state=management_status(store,ip)
    if state['status']=='unmonitored':return
    times=store.connection.execute('SELECT MIN(observed_at),MAX(observed_at) FROM observations WHERE ip=?',(ip,)).fetchone()
    if not times[0]:return
    key=identifier('unmanaged_endpoint_observed',state['subnet_id'],ip)
    if state['status']=='approved' and not store.connection.execute('SELECT 1 FROM endpoint_alerts WHERE alert_id=?',(key,)).fetchone():return
    severity='high' if state['status']=='unauthorized' else 'medium'
    lifecycle='resolved' if state['status']=='approved' else 'active'
    store.connection.execute('INSERT INTO endpoint_alerts VALUES(?,?,?,?,?,?,?,0,?,?) ON CONFLICT(subnet_id,ip) DO UPDATE SET state=excluded.state,status=excluded.status,severity=excluded.severity,evidence_json=excluded.evidence_json,last_seen=excluded.last_seen,acknowledged=CASE WHEN endpoint_alerts.state=\'resolved\' AND excluded.state=\'active\' THEN 0 ELSE endpoint_alerts.acknowledged END',
        (key,state['subnet_id'],ip,lifecycle,state['status'],severity,json.dumps(state),times[0],times[1]))


def reevaluate_endpoints(store):
    for row in store.connection.execute('SELECT DISTINCT ip FROM observations'):evaluate_endpoint(store,row[0])


def heartbeat(store,key,kind,status,message='',success=False):
    store.connection.execute('INSERT INTO collectors VALUES(?,?,?,?,?,?) ON CONFLICT(collector_id) DO UPDATE SET status=excluded.status,heartbeat=excluded.heartbeat,last_success=CASE WHEN ? THEN excluded.last_success ELSE collectors.last_success END,message=excluded.message',
        (key,kind,status,utc_now(),utc_now() if success else '',str(message)[:2000],success))
    store.connection.commit()


def collectors(store):
    now=datetime.now(timezone.utc)
    rows=[dict(r) for r in store.connection.execute('SELECT * FROM collectors')]
    for row in rows:
        if row['status']!='stopped' and now-datetime.fromisoformat(row['heartbeat'].replace('Z','+00:00'))>timedelta(seconds=180):row['status']='stale'
    return rows
