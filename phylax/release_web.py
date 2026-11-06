"""Protected operator routing; presentation lives in focused view modules."""
import json
from urllib.parse import urlencode
from .theme import layout
from .ui import e,table,pager,raw_record,error_summary
from .asset_intelligence import save_context,save_process,unlink_process,add_subnet,endpoint_decision,revoke_decision
from .observations import map_software,review_component
from .discovery import save_target,enqueue,cancel,schedule,IDENTIFICATION
from .triage import acknowledge
from .csaf import configure
from .configuration_pages import context_page,discovery_page
from .review_pages import approvals_page,software_page
from .triage_views import triage_page
from .evidence_views import event_page

PAGES={'/discovery','/approvals','/changes','/software','/processes','/triage','/evidence'}
ACTIONS={'/discovery/save','/discovery/revoke','/discovery/run','/discovery/cancel','/discovery/schedule','/approvals/subnet','/approvals/decide','/approvals/revoke','/software/map','/software/review','/processes/context','/processes/link','/processes/unlink','/triage/ack','/sources/csaf'}
TITLES={'/discovery':'Approved IT discovery','/approvals':'Device management approvals','/changes':'Asset change timeline','/software':'Software evidence and verification','/processes':'Operational context and processes','/triage':'Unified security triage','/evidence':'Original event evidence'}


def page(store,path,query,submitted=None,error=''):
    try:page_number=max(1,int(query.get('page',['1'])[0]))
    except ValueError:page_number=1
    offset=(page_number-1)*50;total=0
    views={'/processes':context_page,'/discovery':discovery_page,'/approvals':approvals_page,'/software':software_page}
    if path in views:body,total=views[path](store,query,offset,submitted)
    elif path=='/triage':body,total=triage_page(store,query,offset)
    elif path=='/changes':
        ip=query.get('ip',[''])[0];where=' WHERE ip=?' if ip else '';params=[ip] if ip else []
        rows=[dict(r) for r in store.connection.execute('SELECT * FROM asset_changes'+where+' ORDER BY observed_at DESC LIMIT 50 OFFSET ?',params+[offset])]
        for row in rows:row['kind']=row['kind'].replace('_',' ').capitalize()
        total=store.connection.execute('SELECT COUNT(*) FROM asset_changes'+where,params).fetchone()[0]
        body='<p>Observed and ingestion times are distinct. Collector silence does not prove device removal.</p>'
        body+=table(rows,[('ip','Address'),('kind','Change'),('observed_at','Observed UTC'),('ingested_at','Imported UTC')],actions=lambda r:raw_record(json.loads(r['evidence_json']),'Change evidence'))
    else:
        body=event_page(store,query)
    notice=query.get('notice',[''])[0]
    prefix=('<p class="notice success" role="status">'+e(notice)+'</p>') if notice else ''
    if error:prefix=error_summary(error)+prefix
    return layout(TITLES[path],prefix+body+pager(path,query,page_number,total),path,asset_id=query.get('asset_id',[''])[0])


def error_page(store,path,values,error):
    base='/'+path.split('/')[1]
    if base not in PAGES:return layout('Input needs attention','<p class="notice error" role="alert">'+e(error)+'</p><p><a href="/settings">Return to settings</a></p>','/settings')
    query={k:[v[0]] for k,v in values.items() if v and k in {'asset_id','component_id','ip','category','priority','acknowledged','q','page'}}
    try:return page(store,base,query,{k:v[0] for k,v in values.items()},str(error))
    except ValueError:return layout('Input needs attention','<p class="notice error" role="alert">'+e(error)+'</p><p><a href="'+base+'">Reload the current records</a></p>',base)


def post(store,path,form_values):
    f={k:v[0] for k,v in form_values.items()};actor=f.get('actor','');note=f.get('note','');query={}
    messages={
        '/discovery/save':'Target permission saved. Pending requests were invalidated.',
        '/discovery/revoke':'Scan permission revoked. Pending requests were invalidated.',
        '/discovery/run':'Discovery queued. The separate worker executes approved requests.',
        '/discovery/cancel':'Execution cancellation requested.',
        '/discovery/schedule':'Discovery schedule saved.',
        '/approvals/subnet':'Monitored subnet added.',
        '/approvals/decide':'Management decision recorded. Stored endpoint evidence was reevaluated.',
        '/approvals/revoke':'Management decision revoked. Stored endpoint evidence was reevaluated.',
        '/software/map':'Exact mapping saved. Relevant findings were reassessed.',
        '/software/review':'Software review saved. Relevant findings were reassessed.',
        '/processes/context':'Asset context saved. Inventory identity and criticality were not changed.',
        '/processes/link':'Process support relationship recorded.',
        '/processes/unlink':'Process support relationship removed.',
        '/triage/ack':'Alert acknowledged. Its finding, permission and remediation state are unchanged.',
        '/sources/csaf':'CSAF source configuration saved.'}
    if path=='/discovery/save':
        try:ports=[int(p.strip()) for p in f.get('ports','').split(',')]
        except ValueError:raise ValueError('Ports must be comma-separated integers')
        identify={str(p):IDENTIFICATION[p] for p in ports if p in IDENTIFICATION} if f.get('identify')=='true' else {}
        save_target(store,f.get('asset_id',''),ports,identify=identify,permission=f.get('permission')=='true',actor=actor,note=note,
                    expected_revision=int(f['target_revision']) if 'target_revision' in f else None)
        query['asset_id']=f.get('asset_id','')
    elif path=='/discovery/revoke':
        row=store.connection.execute('SELECT * FROM scan_targets WHERE target_id=?',(f.get('target_id',''),)).fetchone()
        if not row:raise ValueError('Target not found')
        save_target(store,row['asset_id'],json.loads(row['ports_json']),identify=json.loads(row['identification_json']),permission=False,actor=actor,note=note)
    elif path=='/discovery/run':enqueue(store,f.get('target_id',''))
    elif path=='/discovery/cancel':cancel(store,f.get('run_id',''))
    elif path=='/discovery/schedule':schedule(store,f.get('target_id',''),int(f.get('interval_minutes','60')),f.get('enabled')=='true')
    elif path=='/approvals/subnet':add_subnet(store,f.get('name',''),f.get('cidr',''))
    elif path=='/approvals/decide':endpoint_decision(store,f.get('subnet_id',''),f.get('ip',''),f.get('mac',''),f.get('decision',''),actor,note)
    elif path=='/approvals/revoke':revoke_decision(store,f.get('decision_id',''),actor,note)
    elif path=='/software/map':map_software(store,f.get('raw_name',''),f.get('vendor',''),f.get('product',''),actor,note)
    elif path=='/software/review':
        review_component(store,f.get('component_id',''),verified=f.get('verified')=='true',active=f.get('active')=='true',actor=actor,note=note)
        query['component_id']=f.get('component_id','')
    elif path=='/processes/context':
        aid=f.get('asset_id','')
        if not f.get('context_revision'):raise ValueError('Reload the selected asset context before saving. No values were changed.')
        row=store.connection.execute('SELECT * FROM asset_context WHERE asset_id=?',(aid,)).fetchone()
        current=dict(row) if row else {}
        values={k:f.get(k,current.get(k,'unknown' if k=='lifecycle' else '')) for k in ('owner','site','location','lifecycle','criticality_rationale')}
        tags=[t.strip() for t in f['tags'].split(',') if t.strip()] if 'tags' in f else json.loads(current.get('tags_json','[]'))
        save_context(store,aid,**values,tags=tags,expected_revision=f['context_revision']);query['asset_id']=aid
    elif path=='/processes/link':
        save_process(store,f.get('name',''),f.get('description',''),f.get('asset_id',''),actor,note);query['asset_id']=f.get('asset_id','')
    elif path=='/processes/unlink':
        unlink_process(store,f.get('asset_id',''),f.get('process_id',''),actor,note);query['asset_id']=f.get('asset_id','')
    elif path=='/triage/ack':
        acknowledge(store,f.get('category',''),f.get('alert_id',''))
        query={k:f[k] for k in ('priority','acknowledged','q','page') if f.get(k)}
        if f.get('filter_category'):query['category']=f['filter_category']
    elif path=='/sources/csaf':configure(store,f.get('url',''),f.get('enabled')=='true')
    destination='/settings' if path=='/sources/csaf' else '/'+path.split('/')[1]
    return destination+'?'+urlencode({**query,'notice':messages[path]})
