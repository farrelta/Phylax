"""Dedicated DHCP/software models and durable passive evidence ingestion."""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime,timezone
from pathlib import Path
from .asset_intelligence import address,mac_address,text,identifier,observe,change,actor_note
from .core import utc_now
from .validation import utc_timestamp


def rows(stream):
    fields=None
    for number,line in enumerate(stream,1):
        line=line.rstrip('\r\n')
        if not line:continue
        if line.startswith('#fields'):fields=line.split('\t')[1:];continue
        if line.startswith('#'):continue
        try:
            if len(line)>1_000_000:raise ValueError('Record exceeds 1 MB')
            if line.startswith('{'):row=json.loads(line)
            else:
                parts=line.split('\t')
                if not fields or len(parts)!=len(fields):raise ValueError('Invalid TSV fields')
                row=dict(zip(fields,parts))
            if not isinstance(row,dict):raise ValueError('Expected a record object')
            yield row
        except (ValueError,TypeError) as exc:raise ValueError(f'Malformed Zeek row {number}: {exc}') from exc


def scalar(row,key,default=''):
    value=row.get(key,default)
    if value in (None,'-','(empty)','(unset)'):return ''
    if isinstance(value,bool) or not isinstance(value,(str,int,float)):raise ValueError(f'{key} must be scalar')
    return text(str(value))


def timestamp(value):
    try:
        return datetime.fromtimestamp(float(value),timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    except (ValueError,OverflowError,OSError):
        result=utc_timestamp(value)
        if not result:raise ValueError('Observation requires a timestamp')
        return result


@dataclass(frozen=True)
class DHCPObservation:
    ip: str
    mac: str
    observed_at: str
    hostname: str

    @classmethod
    def parse(cls,row):
        # Requested addresses are deliberately not an endpoint association.
        ip=scalar(row,'assigned_addr') or scalar(row,'client_addr')
        return cls(address(ip) if ip else '',mac_address(scalar(row,'mac')),
                   timestamp(scalar(row,'ts')),scalar(row,'host_name'))


@dataclass(frozen=True)
class SoftwareObservation:
    ip: str
    name: str
    version: str
    observed_at: str

    @classmethod
    def parse(cls,row):
        name=scalar(row,'name')
        if not name:raise ValueError('Software name is required')
        parts=[scalar(row,'version.'+key) for key in ('major','minor','minor2','minor3')]
        populated=[i for i,v in enumerate(parts) if v]
        if populated and any(not parts[i].isdigit() for i in range(max(populated)+1)):
            version='' # holes cannot silently become zeroes
        else:version='.'.join(parts[:max(populated)+1]) if populated else ''
        suffix=scalar(row,'version.addl')
        if suffix and version:version+='+'+suffix
        return cls(address(scalar(row,'host')),name,version,timestamp(scalar(row,'ts')))


def asset_for_ip(store,ip):
    assets=store.connection.execute('SELECT * FROM assets WHERE ip_address=?',(ip,)).fetchall()
    return dict(assets[0]) if len(assets)==1 else None


def software_component(store,item,source_file,event_ref,raw):
    asset=asset_for_ip(store,item.ip)
    if not asset:return None
    mapping=store.connection.execute('SELECT * FROM software_mappings WHERE raw_name=?',(item.name,)).fetchone()
    vendor,product=(mapping['vendor'],mapping['product']) if mapping else ('','')
    cid=identifier('software',asset['asset_id'],item.name,item.version)
    previous=store.connection.execute('SELECT * FROM software_components WHERE asset_id=? AND raw_name=? AND active=1 ORDER BY last_seen DESC LIMIT 1',(asset['asset_id'],item.name)).fetchone()
    if previous and previous['version']!=item.version and previous['last_seen']<=item.observed_at:
        store.connection.execute('UPDATE software_components SET verified=0,reviewer=\'\' WHERE asset_id=? AND raw_name=?',(asset['asset_id'],item.name))
        change(store,item.ip,'software_version_changed',item.observed_at,{'previous':previous['version'],'observed':item.version,'name':item.name,'event_ref':event_ref})
    store.connection.execute('INSERT INTO software_components VALUES(?,?,?,?,?,?,0,1,?,?,?,?,?,\'\') ON CONFLICT(asset_id,raw_name,version) DO UPDATE SET last_seen=MAX(software_components.last_seen,excluded.last_seen)',
        (cid,asset['asset_id'],item.name,item.version,vendor,product,item.observed_at,item.observed_at,source_file,event_ref,json.dumps(raw,sort_keys=True)))
    return asset['asset_id']


def review_component(store,component_id,*,verified=False,active=True,actor='',note=''):
    actor,note=actor_note(actor,note)
    row=store.connection.execute('SELECT * FROM software_components WHERE component_id=?',(component_id,)).fetchone()
    if not row:raise ValueError('Software component not found')
    if verified and (not row['vendor'] or not row['product'] or not row['version']):raise ValueError('Map and verify product/version before confirmation')
    store.connection.execute('UPDATE software_components SET verified=?,active=?,reviewer=? WHERE component_id=?',(int(verified),int(active),actor,component_id))
    store.audit('software_review',component_id,{'actor':actor,'note':note,'verified':verified,'active':active})
    store.correlate(asset_ids=[row['asset_id']],commit=False);store.connection.commit()


def map_software(store,raw_name,vendor,product,actor,note):
    actor,note=actor_note(actor,note)
    values=[text(v,200) for v in (raw_name,vendor,product)]
    if not all(values):raise ValueError('Exact software name, vendor and product are required')
    store.connection.execute('INSERT OR REPLACE INTO software_mappings VALUES(?,?,?,?,?)',(*values,actor,note))
    assets=[r[0] for r in store.connection.execute('SELECT DISTINCT asset_id FROM software_components WHERE raw_name=?',(raw_name,))]
    store.connection.execute('UPDATE software_components SET vendor=?,product=?,verified=0,reviewer=\'\' WHERE raw_name=?',(vendor,product,raw_name))
    store.audit('software_mapping',raw_name,{'vendor':vendor,'product':product,'actor':actor,'note':note})
    store.correlate(asset_ids=assets,commit=False);store.connection.commit()


def ingest_observations(store,path,*,kind,source_file=None,commit=True):
    if kind not in {'dhcp','software'}:raise ValueError('Unsupported observation kind')
    path=Path(path)
    if path.stat().st_size>500_000_000:raise ValueError('Log exceeds 500 MB')
    inserted=duplicates=0;diagnostics=[];assets=set()
    with store.atomic('observation_import'),path.open(encoding='utf-8') as stream:
        for row in rows(stream):
            ref=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            item=DHCPObservation.parse(row) if kind=='dhcp' else SoftwareObservation.parse(row)
            if not item.ip:
                diagnostics.append('DHCP record lacks assigned/client address; requested address was not inferred')
                diagnostics=diagnostics[:100];continue
            new=observe(store,kind=kind,ip=item.ip,when=item.observed_at,source_file=source_file or path.name,event_ref=ref,raw=row,mac=item.mac if kind=='dhcp' else '')
            inserted+=int(new);duplicates+=int(not new)
            if kind=='software' and new:
                aid=software_component(store,item,source_file or path.name,ref,row)
                if aid:assets.add(aid)
                else:diagnostics.append('Software host is external or has competing inventory identities; no automatic association')
        if assets:store.correlate(asset_ids=list(assets),commit=False)
        store.audit('observation_import',source_file or path.name,{'kind':kind,'observations':inserted})
    if commit:store.connection.commit()
    return {'events_inserted':inserted,'duplicates_skipped':duplicates,'alerts_created':0,'diagnostics':diagnostics[:100],'diagnostic_count':len(diagnostics)}


def observe_connection(store,event):
    for ip in {event.source_ip,event.destination_ip}- {''}:
        try:
            observe(store,kind=event.event_type,ip=ip,when=event.timestamp,source_file=event.source_file,event_ref=event.event_ref,raw=event.as_dict())
        except ValueError:
            continue # unspecified/multicast/broadcast are not endpoint identities
    if event.event_type=='connection' and event.destination_ip and event.destination_port:
        key=identifier('service',event.destination_ip,event.destination_port,event.protocol)
        prior=store.connection.execute('SELECT 1 FROM asset_changes WHERE change_id=?',(key,)).fetchone()
        if not prior:
            store.connection.execute('INSERT INTO asset_changes VALUES(?,?,?,?,?,?)',(key,event.destination_ip,'service_first_observed',event.timestamp,utc_now(),json.dumps({'port':event.destination_port,'protocol':event.protocol,'event_ref':event.event_ref,'source_file':event.source_file})))
