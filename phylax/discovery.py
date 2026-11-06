"""Explicit, bounded IT discovery. No discovery result grants further permission."""
from __future__ import annotations
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime,timezone
from .core import Store,utc_now
from .asset_intelligence import address,actor_note,identifier,observe,change,heartbeat

ELIGIBLE={'server','network device','gateway'}
IDENTIFICATION={22:'ssh',80:'http',8080:'http',443:'https',8443:'https'}


def eligible(store,asset_id,ip):
    row=store.connection.execute('SELECT * FROM assets WHERE asset_id=?',(asset_id,)).fetchone()
    return eligible_asset(row,ip)


def eligible_asset(row,ip):
    """Shared row validation, including read-only permission previews."""
    if not row or row['ip_address']!=ip:raise ValueError('Target inventory address changed or asset is missing')
    if ipaddress.ip_address(address(ip)).version!=4:raise ValueError('Active discovery supports literal IPv4 only')
    if row['asset_type'] not in ELIGIBLE or row['identification_source']=='zeek_passive':raise ValueError('Unknown and control-related endpoints are passive-only')
    if row['asset_type']=='server' and row['zone'] not in {'IT','DMZ'}:raise ValueError('Only supporting IT/DMZ servers can be scanned')
    return dict(row)


def eligible_inventory(store,search='',*,limit=50,offset=0):
    """Bound the selector in SQL; execution revalidates the actual permission."""
    where="asset_type IN ('server','network device','gateway') AND identification_source!='zeek_passive' AND (asset_type!='server' OR zone IN ('IT','DMZ')) AND instr(ip_address,':')=0"
    params=[]
    if search:
        term=search[:200].replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        where+=" AND (hostname LIKE ? ESCAPE '\\' OR ip_address LIKE ? ESCAPE '\\' OR asset_id LIKE ? ESCAPE '\\')"
        params=[f'%{term}%']*3
    total=store.connection.execute('SELECT COUNT(*) FROM assets WHERE '+where,params).fetchone()[0]
    rows=store.connection.execute('SELECT * FROM assets WHERE '+where+' ORDER BY ip_address,asset_id LIMIT ? OFFSET ?',params+[min(100,max(1,limit)),max(0,offset)])
    result=[]
    for row in rows:
        try:result.append(eligible_asset(row,row['ip_address']))
        except ValueError:continue
    return result,total


def save_target(store,asset_id,ports,*,identify=None,permission=False,actor='',note='',expected_revision=None):
    actor,note=actor_note(actor,note)
    asset=store.connection.execute('SELECT ip_address FROM assets WHERE asset_id=?',(asset_id,)).fetchone()
    if not asset:raise ValueError('Asset not found')
    ip=asset[0]
    tid=identifier('scan-target',asset_id)
    if permission or not store.connection.execute('SELECT 1 FROM scan_targets WHERE target_id=?',(tid,)).fetchone():eligible(store,asset_id,ip)
    if not isinstance(ports,list) or not 1<=len(ports)<=32 or any(type(p) is not int or not 1<=p<=65535 for p in ports):raise ValueError('Select 1–32 explicit TCP ports')
    ports=sorted(set(ports));identify={} if identify is None else identify
    if not isinstance(identify,dict):raise ValueError('Identification must be an object keyed by selected port')
    for port,protocol in identify.items():
        if not str(port).isdigit() or int(port) not in ports or IDENTIFICATION.get(int(port))!=protocol:raise ValueError('Identification supports SSH 22, HTTP 80/8080 and HTTPS 443/8443 only')
    if type(permission) is not bool:raise ValueError('Explicit boolean permission is required')
    tid=identifier('scan-target',asset_id)
    with store.atomic('target_permission'):
        current=store.connection.execute('SELECT revision FROM scan_targets WHERE target_id=?',(tid,)).fetchone()
        if expected_revision is not None and expected_revision!=(current[0] if current else 0):
            raise ValueError('Target permission changed after this form was opened. Reload it before saving.')
        store.connection.execute('INSERT INTO scan_targets VALUES(?,?,?,?,?,?,1,?,?,?) ON CONFLICT(target_id) DO UPDATE SET ip=excluded.ip,ports_json=excluded.ports_json,identification_json=excluded.identification_json,permission=excluded.permission,revision=scan_targets.revision+1,actor=excluded.actor,note=excluded.note,updated_at=excluded.updated_at',
            (tid,asset_id,ip,json.dumps(ports),json.dumps(identify,sort_keys=True),int(permission),actor,note,utc_now()))
        store.connection.execute("UPDATE scan_runs SET status='cancelled',finished_at=?,error='Target permission/configuration changed' WHERE target_id=? AND status='queued'",(utc_now(),tid))
        store.connection.execute("UPDATE scan_runs SET cancel_requested=1 WHERE target_id=? AND status='running'",(tid,))
        store.audit('scan_permission_changed',tid,{'permission':permission,'actor':actor,'note':note,'ports':ports,'identification':identify})
    store.connection.commit();return tid


def target(store,target_id):
    row=store.connection.execute('SELECT * FROM scan_targets WHERE target_id=?',(target_id,)).fetchone()
    if not row:raise ValueError('Target not found')
    row=dict(row);eligible(store,row['asset_id'],row['ip'])
    if not row['permission']:raise ValueError('Target lacks scan permission')
    return row


def enqueue(store,target_id):
    row=target(store,target_id)
    existing=store.connection.execute("SELECT run_id FROM scan_runs WHERE target_id=? AND status IN ('queued','running')",(target_id,)).fetchone()
    if existing:return existing[0]
    rid=uuid.uuid4().hex
    if store.connection.execute("SELECT COUNT(*) FROM scan_runs WHERE status='queued'").fetchone()[0]>=256:raise ValueError('Discovery queue is full')
    inserted=store.connection.execute('INSERT OR IGNORE INTO scan_runs(run_id,target_id,revision,status,requested_at) VALUES(?,?,?,\'queued\',?)',(rid,target_id,row['revision'],utc_now())).rowcount
    if not inserted:
        store.connection.commit()
        return store.connection.execute("SELECT run_id FROM scan_runs WHERE target_id=? AND status IN ('queued','running')",(target_id,)).fetchone()[0]
    store.audit('scan_queued',rid,{'target_id':target_id,'revision':row['revision']});store.connection.commit();return rid


def schedule(store,target_id,interval_minutes=60,enabled=True):
    if type(enabled) is not bool:raise ValueError('Explicit schedule enabled state is required')
    if enabled:target(store,target_id)
    elif not store.connection.execute('SELECT 1 FROM scan_targets WHERE target_id=?',(target_id,)).fetchone():
        raise ValueError('Target not found')
    if type(interval_minutes) is not int or not 15<=interval_minutes<=10080:raise ValueError('Schedule interval must be 15 minutes–7 days')
    store.connection.execute('INSERT INTO scan_schedules VALUES(?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET interval_seconds=excluded.interval_seconds,next_due=excluded.next_due,enabled=excluded.enabled',
        (target_id,interval_minutes*60,time.time()+interval_minutes*60,int(enabled)))
    store.audit('scan_schedule_changed',target_id,{'interval_minutes':interval_minutes,'enabled':enabled});store.connection.commit()


def cancel(store,run_id):
    row=store.connection.execute('SELECT status FROM scan_runs WHERE run_id=?',(run_id,)).fetchone()
    if not row:raise ValueError('Run not found')
    store.connection.execute("UPDATE scan_runs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,finished_at=CASE WHEN status='queued' THEN ? ELSE finished_at END WHERE run_id=?",(utc_now(),run_id))
    store.audit('scan_cancel_requested',run_id,{});store.connection.commit()


class Cancelled(RuntimeError):pass


def bounded_run(command,*,timeout,cancelled):
    # File-backed diagnostics avoid an unbounded PIPE buffer and contain no secrets.
    with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
        process=subprocess.Popen(command,stdout=output,stderr=errors,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},start_new_session=True)
        start=time.monotonic()
        try:
            while process.poll() is None:
                if cancelled():raise Cancelled('Run cancelled or permission changed')
                if time.monotonic()-start>timeout:raise TimeoutError('Discovery process timed out')
                if output.tell()>2_000_000 or errors.tell()>64_000:raise ValueError('Discovery output exceeded bounds')
                time.sleep(.1)
            output.seek(0);errors.seek(0)
            body=output.read(2_000_001);error=errors.read(4096).decode('utf-8','replace')
            if len(body)>2_000_000:raise ValueError('Discovery XML exceeds 2 MB')
            if process.returncode:raise RuntimeError('Nmap failed: '+error)
            return body
        finally:
            if process.poll() is None:
                import signal
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=5)


def parse_result(body,ip,ports):
    if len(body)>2_000_000 or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():
        # Nmap emits a harmless root DOCTYPE; allow only its exact bare form.
        body=body.replace(b'<!DOCTYPE nmaprun>',b'')
        if len(body)>2_000_000 or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():raise ValueError('Unsafe or oversized discovery XML')
    try:root=ET.fromstring(body)
    except ET.ParseError as exc:raise ValueError('Malformed Nmap XML') from exc
    hosts=root.findall('host')
    if len(hosts)!=1:raise ValueError('Expected exactly one target result')
    addresses=[a.get('addr') for a in hosts[0].findall('address') if a.get('addrtype')=='ipv4']
    if addresses!=[ip]:raise ValueError('Nmap returned a different target')
    result=[]
    for p in hosts[0].findall('./ports/port'):
        port=int(p.get('portid','0'));state=p.find('state')
        if p.get('protocol')!='tcp' or port not in ports or state is None:raise ValueError('Unexpected port result')
        result.append({'port':port,'state':state.get('state','unknown'),'reason':state.get('reason','')})
    missing=set(ports)-{p['port'] for p in result}
    extra=hosts[0].findall('./ports/extraports')
    collapsed=extra[0] if len(extra)==1 and extra[0].get('count')==str(len(missing)) else None
    for port in sorted(missing):
        reasons=collapsed.find('extrareasons') if collapsed is not None else None
        result.append({'port':port,'state':collapsed.get('state','unknown') if collapsed is not None else 'unknown',
                       'reason':reasons.get('reason','') if reasons is not None else 'not individually reported'})
    # -Pn's host "up" status is an assumption, never reachability evidence.
    return {'ports':result,'reachability':'responded' if any(p['state'] in {'open','closed'} for p in result) else 'unknown',
            'xml_sha256':__import__('hashlib').sha256(body).hexdigest()}


def identify_service(ip,port,protocol):
    deadline=time.monotonic()+3
    def remaining():
        value=deadline-time.monotonic()
        if value<=0:raise TimeoutError('Identification exceeded 3 seconds')
        return value
    conn=socket.create_connection((ip,port),timeout=remaining())
    try:
        if protocol=='https':
            conn.settimeout(remaining());conn=ssl.create_default_context().wrap_socket(conn,server_hostname=ip)
        if protocol!='ssh':
            conn.settimeout(remaining())
            conn.sendall(f'HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Phylax/0.2\r\nConnection: close\r\n\r\n'.encode('ascii'))
        data=b''
        while len(data)<=4096:
            conn.settimeout(remaining());chunk=conn.recv(min(1024,4097-len(data)))
            if not chunk:break
            data+=chunk
            if (protocol=='ssh' and b'\n' in data) or b'\r\n\r\n' in data:break
        if len(data)>4096:raise ValueError('Identification response exceeds 4 KB')
        value=data.decode('utf-8','replace')
        if protocol=='ssh':return {'protocol':'ssh','banner':value}
        lines=value.split('\r\n')
        if not re.fullmatch(r'HTTP/1\.[01] [1-5][0-9]{2}(?: .*)?',lines[0]):raise ValueError('Unrecognized HTTP response')
        headers=[line.split(':',1)[1].strip() for line in lines[1:] if line.lower().startswith('server:')]
        return {'protocol':protocol,'status':int(lines[0].split()[1]),'server':'; '.join(headers),'redirect_followed':False}
    finally:conn.close()


def execute(store,run,*,runner=bounded_run,identifier_fn=identify_service):
    initial=target(store,run['target_id'])
    if initial['revision']!=run['revision']:raise Cancelled('Permission revision changed')
    start=time.monotonic()
    def cancelled():
        status=store.connection.execute('SELECT cancel_requested FROM scan_runs WHERE run_id=?',(run['run_id'],)).fetchone()
        try:current=target(store,run['target_id'])
        except ValueError:return True
        return not status or bool(status[0]) or current['revision']!=run['revision']
    binary=shutil.which('nmap',path='/usr/bin:/usr/local/bin')
    if not binary:raise RuntimeError('Nmap is not installed; passive workflows remain available')
    version=runner([binary,'--version'],timeout=5,cancelled=cancelled).decode('utf-8','replace')[:500]
    ports=json.loads(initial['ports_json'])
    command=[binary,'--unprivileged','-sT','-Pn','-n','--max-retries','1','--max-parallelism','1','--max-rate','5','--scan-delay','200ms','--host-timeout','30s','-p',','.join(map(str,ports)),'-oX','-',initial['ip']]
    result=parse_result(runner(command,timeout=30,cancelled=cancelled),initial['ip'],ports)
    result.update(tool_version=version,permission_revision=run['revision'],ip=initial['ip'],identification={})
    for port,protocol in json.loads(initial['identification_json']).items():
        if cancelled():raise Cancelled('Run cancelled or target no longer eligible')
        if time.monotonic()-start>175:raise TimeoutError('Overall discovery execution limit reached')
        if any(p['port']==int(port) and p['state']=='open' for p in result['ports']):
            try:result['identification'][port]=identifier_fn(initial['ip'],int(port),protocol)
            except (OSError,ValueError,http.client.HTTPException) as exc:result['identification'][port]={'error':type(exc).__name__+': '+str(exc)[:500]}
    if cancelled():raise Cancelled('Permission changed before persistence')
    when=utc_now();rid=run['run_id']
    with store.atomic('scan_evidence'):
        previous=store.connection.execute("SELECT result_json FROM scan_runs WHERE target_id=? AND status='success' ORDER BY finished_at DESC LIMIT 1",(initial['target_id'],)).fetchone()
        old={p['port']:p['state'] for p in json.loads(previous[0]).get('ports',[])} if previous else {}
        for port in result['ports']:
            if port['state'] in {'open','closed'} and old.get(port['port'])!=port['state']:
                change(store,initial['ip'],'active_port_changed',when,{'port':port['port'],'previous':old.get(port['port'],'unknown'),'observed':port['state'],'run_id':rid})
        observe(store,kind='active_probe',ip=initial['ip'],when=when,source_file='scan-run:'+rid,event_ref=rid,raw=result)
        from .observations import SoftwareObservation,software_component
        for port,details in result['identification'].items():
            server=details.get('server','');banner=details.get('banner','')
            apache=re.fullmatch(r'Apache/([0-9]+(?:\.[0-9]+)+)(?:\s.*)?',server)
            ssh=re.search(r'^SSH-2\.0-OpenSSH_([^\s]+)',banner)
            if apache or ssh:
                item=SoftwareObservation(initial['ip'],'Apache' if apache else 'OpenSSH',(apache or ssh).group(1),when)
                software_component(store,item,'scan-run:'+rid,rid+':'+port,details)
        store.correlate(asset_ids=[initial['asset_id']],commit=False)
    result['elapsed_seconds']=round(time.monotonic()-start,6)
    store.connection.commit();return result


def worker_once(store,*,runner=bounded_run,identifier_fn=identify_service,now=None):
    now=time.time() if now is None else now;owner=uuid.uuid4().hex;db=store.connection
    db.execute('BEGIN IMMEDIATE')
    try:
        lease=db.execute("SELECT * FROM worker_lease WHERE name='scanner'").fetchone()
        if lease and lease['expires']>now:db.rollback();return {'busy':True}
        db.execute("UPDATE scan_runs SET status='interrupted',finished_at=?,error='Worker lease expired; run was not replayed' WHERE status='running'",(utc_now(),))
        db.execute("INSERT OR REPLACE INTO worker_lease VALUES('scanner',?,?)",(owner,now+210))
        db.commit()
        for schedule_row in db.execute('SELECT * FROM scan_schedules WHERE enabled=1 AND next_due<=?',(now,)).fetchall():
            try:enqueue(store,schedule_row['target_id'])
            except ValueError as exc:store.audit('scheduled_scan_skipped',schedule_row['target_id'],{'reason':str(exc)})
            db.execute('UPDATE scan_schedules SET next_due=? WHERE target_id=?',(now+schedule_row['interval_seconds'],schedule_row['target_id']));db.commit()
        row=db.execute("SELECT * FROM scan_runs WHERE status='queued' ORDER BY requested_at,run_id LIMIT 1").fetchone()
        if not row:return {'idle':True}
        run=dict(row);rid=run['run_id']
        db.execute("UPDATE scan_runs SET status='running',started_at=? WHERE run_id=?",(utc_now(),rid));db.commit()
        heartbeat(store,'scanner','worker','running',rid)
        try:
            result=execute(store,run,runner=runner,identifier_fn=identifier_fn)
            status,error='success',''
        except Cancelled as exc:result={};status,error='cancelled',str(exc)
        except Exception as exc:result={};status,error='failed',f'{type(exc).__name__}: {exc}'[:2000]
        db.execute('UPDATE scan_runs SET status=?,finished_at=?,result_json=?,error=? WHERE run_id=?',(status,utc_now(),json.dumps(result),error,rid))
        store.audit('scan_finished',rid,{'status':status,'error':error});db.commit()
        heartbeat(store,'scanner','worker','running',f'{rid}: {status}',success=status=='success')
        return {'run_id':rid,'status':status,'result':result,'error':error}
    finally:
        if db.in_transaction:db.rollback()
        db.execute("DELETE FROM worker_lease WHERE name='scanner' AND owner=?",(owner,));db.commit()


def worker(database,once=False):
    store=Store(database)
    try:
        while True:
            heartbeat(store,'scanner','worker','running')
            result=worker_once(store)
            if once:return result
            time.sleep(5)
    except KeyboardInterrupt:return {'stopped':True}
    finally:heartbeat(store,'scanner','worker','stopped');store.close()
