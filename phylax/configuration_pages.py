"""Record-bound context editors and explicit IT discovery affordances."""
import json
from datetime import datetime,timezone
from urllib.parse import urlencode
from .ui import e,field,select,hidden,form,actor_fields,table,raw_record
from .asset_intelligence import context_revision,collectors
from .discovery import eligible,eligible_inventory,target


def asset_label(asset):
    return f"{asset['hostname'] or asset['ip_address']} · {asset['ip_address']}"


def context_page(store,query,offset,submitted=None):
    inventory=store.assets()
    if not inventory:
        return '<p class="empty">Add an inventory asset before recording its owner, location or supported processes. <a href="/assets/edit">Add asset</a>.</p>',0
    choices=[(a['asset_id'],asset_label(a)) for a in inventory[:1000]]
    aid=(submitted or {}).get('asset_id',query.get('asset_id',[inventory[0]['asset_id']])[0])
    asset=next((a for a in inventory if a['asset_id']==aid),None)
    if not asset:raise ValueError('Asset not found. Choose an existing inventory asset.')
    if aid not in {value for value,label in choices}:choices.insert(0,(aid,asset_label(asset)))
    current=store.connection.execute('SELECT * FROM asset_context WHERE asset_id=?',(aid,)).fetchone()
    current=dict(current) if current else {}
    values={**current,'tags':', '.join(json.loads(current.get('tags_json','[]')))}
    if submitted:values.update(submitted)
    body='<p>Record ownership and confirmed process support. These relationships do not automatically change criticality or establish disruption.</p>'
    body+='<form method="get" class="controls">'+select('asset_id','Asset to review',choices,aid)+'<button>Load asset context</button></form>'
    body+='<section class="editor"><h2>Context for '+e(asset_label(asset))+'</h2>'
    body+='<p class="muted">'+('Last saved '+e(current['updated_at']) if current else 'No operational context saved for this asset.')+'</p>'
    body+='<p>Existing values are loaded below. An empty value clears that field. Inventory identity and criticality are edited separately.</p>'
    revision=(submitted or {}).get('context_revision',context_revision(store,aid))
    fields=hidden('asset_id',aid)+hidden('context_revision',revision)
    fields+='<div class="form-grid">'+''.join(field(k,label,values.get(k,'')) for k,label in (
        ('owner','Owner'),('site','Facility / site'),('location','Physical location')))
    fields+=select('lifecycle','Lifecycle',[(v,v.title()) for v in ('unknown','acquisition','deployed','commissioned','maintenance','decommissioned')],values.get('lifecycle','unknown'))
    fields+=field('tags','Tags (comma separated)',values.get('tags',''))+field('criticality_rationale','Criticality rationale',values.get('criticality_rationale',''))+'</div>'
    body+=form('/processes/context',fields,'Save context for '+(asset['hostname'] or asset['ip_address']))
    body+='<p><a href="/processes?'+e(urlencode({'asset_id':aid}))+'">Reload current context</a> · <a href="/assets/edit?'+e(urlencode({'asset_id':aid}))+'">Edit inventory identity / criticality</a></p></section>'
    rows=[dict(r) for r in store.connection.execute('SELECT c.*,a.hostname,a.ip_address FROM asset_context c JOIN assets a USING(asset_id) ORDER BY a.ip_address LIMIT 50 OFFSET ?',(offset,))]
    for row in rows:row['asset']=asset_label(row)
    body+='<h2>Saved asset context</h2>'+table(rows,[('asset','Asset'),('owner','Owner'),('site','Site'),('location','Location'),('lifecycle','Lifecycle')],
        actions=lambda r:'<a href="/processes?'+e(urlencode({'asset_id':r['asset_id']}))+'">Edit context</a>',empty='No context saved yet. Complete the selected asset above.')
    body+='<details class="workflow"><summary>Confirm a process relationship</summary>'+form('/processes/link',
        select('asset_id','Supporting asset',choices,aid)+field('name','Supported process name',required=True)+field('description','Process description')+actor_fields(),'Confirm process relationship')+'</details>'
    links=[dict(r) for r in store.connection.execute('SELECT l.*,p.name,p.description,a.hostname,a.ip_address FROM process_links l JOIN processes p USING(process_id) JOIN assets a USING(asset_id) ORDER BY a.ip_address,p.name LIMIT 50 OFFSET ?',(offset,))]
    for row in links:row['asset']=asset_label(row)
    def remove(row):
        return '<details><summary>Remove relationship</summary><p>'+e(row['asset'])+' supports '+e(row['name'])+'</p>'+form('/processes/unlink',
            hidden('asset_id',row['asset_id'])+hidden('process_id',row['process_id'])+actor_fields(),'Remove this relationship')+'</details>'
    body+='<h2>Confirmed process support</h2>'+table(links,[('asset','Asset'),('name','Process'),('actor','Confirmed by'),('note','Evidence')],actions=remove)
    total=max(store.connection.execute('SELECT COUNT(*) FROM asset_context').fetchone()[0],store.connection.execute('SELECT COUNT(*) FROM process_links').fetchone()[0])
    return body,total


def discovery_page(store,query,offset,submitted=None):
    search=query.get('asset_q',[''])[0][:200]
    try:asset_page=max(1,int(query.get('asset_page',['1'])[0]))
    except ValueError:asset_page=1
    available,eligible_count=eligible_inventory(store,search,offset=(asset_page-1)*50)
    selected=submitted.get('asset_id','') if submitted is not None else query.get('asset_id',[''])[0]
    if selected and not any(a['asset_id']==selected for a in available):
        row=store.connection.execute('SELECT ip_address FROM assets WHERE asset_id=?',(selected,)).fetchone()
        try:asset=eligible(store,selected,row['ip_address'] if row else '')
        except ValueError:pass
        else:available.insert(0,asset)
    targets=[dict(r) for r in store.connection.execute('SELECT t.*,t.ip AS ip_address,a.hostname FROM scan_targets t JOIN assets a USING(asset_id) ORDER BY t.ip LIMIT 1000')]
    by_asset={r['asset_id']:r for r in targets};by_id={r['target_id']:r for r in targets}
    body='<p>Only individually approved supporting IT hosts and network management interfaces are eligible. OT control endpoints and unknown identities remain passive-only.</p>'
    body+='<h2>Target permissions</h2>'
    body+='<form method="get" class="filter-bar">'+field('asset_q','Find eligible asset by hostname, IP or ID',search)+'<button>Find eligible assets</button></form>'
    body+='<p class="muted">'+str(eligible_count)+' eligible asset'+('' if eligible_count==1 else 's')+' match. Choices are shown in pages of 50.</p>'
    links=[]
    for number,label in ((asset_page-1,'Previous assets'),(asset_page+1,'Next assets')):
        if (number<asset_page and asset_page>1) or (number>asset_page and asset_page*50<eligible_count):
            links.append('<a href="/discovery?'+e(urlencode({'asset_q':search,'asset_page':number}))+'">'+label+'</a>')
    if links:body+='<nav class="pagination" aria-label="Eligible asset pages">'+' '.join(links)+'</nav>'
    invalid_selection=(submitted is not None or 'asset_id' in query) and not any(a['asset_id']==selected for a in available)
    if invalid_selection:
        body+='<p class="notice">'+('Selected asset '+e(selected)+' is missing or is not eligible for active discovery. ' if selected else 'No eligible target is loaded. ')+'Choose and load an eligible supporting IT asset before editing permissions. Existing permissions can still be revoked below.</p>'
    if submitted is not None and (invalid_selection or not selected):
        draft={name:submitted.get(name,'') for name in ('asset_id','ports','permission','identify','actor','note','target_revision')}
        body+=raw_record(draft,'Unapplied permission draft for the selected target')
    if available:
        choices=[(a['asset_id'],asset_label(a)) for a in available[:1000]]
        aid=selected if submitted is not None or 'asset_id' in query else available[0]['asset_id']
        asset=next((a for a in available if a['asset_id']==aid),None)
        if not asset:
            choices.insert(0,('','Choose an eligible supporting IT asset'))
            aid=''
        body+='<form method="get" class="controls">'+hidden('asset_q',search)+hidden('asset_page',asset_page)+select('asset_id','Eligible supporting IT asset',choices,aid)+'<button>Load target permission</button></form>'
        if asset:
            current=by_asset.get(aid,{})
            values={'ports':','.join(str(p) for p in json.loads(current.get('ports_json','[]'))) or '80,443',
                    'permission':'true' if current.get('permission') else 'false','identify':'true' if json.loads(current.get('identification_json','{}')) else 'false',
                    'actor':'','note':''}
            if submitted:values.update(submitted)
            body+='<section class="editor"><h3>'+e(asset_label(asset))+'</h3><p>Device management approval and inventory verification do not grant scan permission. Saving changes invalidates pending requests for this target.</p>'
            fields=hidden('asset_id',aid)+hidden('target_revision',(submitted or {}).get('target_revision',current.get('revision',0)))
            fields+='<div class="form-grid">'+field('ports','Selected TCP ports (comma separated, maximum 32)',values['ports'],True)
            fields+=select('permission','Scan permission',[('false','Disabled'),('true','Explicitly permitted')],values['permission'])
            fields+=select('identify','Standard-port HTTP(S) headers / SSH banner',[('false','Disabled'),('true','Enabled for selected supported ports')],values['identify'])+'</div>'
            fields+=actor_fields(values)
            body+=form('/discovery/save',fields,'Save permission for '+(asset['hostname'] or asset['ip_address']))+'</section>'
    else:
        body+=('<p class="empty">No eligible assets on this result page. <a href="/discovery">Clear the search and return to the first page</a>.</p>' if search or asset_page>1 else '<p class="empty">No eligible supporting IT assets. <a href="/assets">Review inventory</a>. PLCs, RTUs, HMIs, engineering workstations and unknown endpoints cannot be granted scan permission.</p>')
    permitted=[]
    for row in targets:
        try:target(store,row['target_id'])
        except ValueError as exc:row['permission_state']='Disabled' if not row['permission'] else 'Needs review: '+str(exc)
        else:row['permission_state']='Permitted';permitted.append(row)
        row['asset']=asset_label(row);row['ports']=', '.join(str(p) for p in json.loads(row['ports_json']))
    def actions(row):
        markup='<a href="/discovery?'+e(urlencode({'asset_id':row['asset_id']}))+'">Edit permission</a>'
        if row['permission']:
            markup+='<details><summary>Revoke scan permission</summary><p>'+e(row['asset'])+'</p>'+form('/discovery/revoke',hidden('target_id',row['target_id'])+actor_fields(),'Revoke this permission')+'</details>'
        return markup+raw_record(row,'Permission evidence and identifiers')
    body+=table(targets,[('asset','Target'),('ports','TCP ports'),('permission_state','Scan permission'),('actor','Last changed by')],actions=actions,empty='No targets configured. Save an eligible target permission above.')
    body+='<h2>Run approved discovery</h2><p>Requests enter the local queue. Start the separate discovery worker to execute them; no scan starts merely by viewing this page.</p>'
    collector_rows=collectors(store)
    workers=[row for row in collector_rows if row['kind']=='worker']
    if workers:
        worker=max(workers,key=lambda row:row['heartbeat'])
        state=worker['status'].replace('_',' ').capitalize()
        body+='<p class="notice"><strong>Worker status: '+e(state)+'</strong> · last heartbeat '+e(worker['heartbeat'])+'. '
        if worker['status']=='running':body+='A recent running heartbeat is recorded; execution still depends on the separate worker process.'
        elif worker['status']=='stale':body+='No heartbeat within the last 3 minutes; check the separate worker before expecting queued requests to run.'
        elif worker['status']=='stopped':body+='The worker reported that it stopped. Start it separately to execute queued requests.'
        else:body+='Review the stored worker details before expecting queued requests to run.'
        body+=' <a href="#discovery-worker-status">Worker details and startup command</a>.</p>'
    else:
        body+='<p class="notice"><strong>Worker status: no heartbeat recorded.</strong> Start the separate worker to execute queued requests. <a href="#discovery-worker-status">Worker details and startup command</a>.</p>'
    choices=[(r['target_id'],asset_label(r)+' · TCP '+r['ports']+' · Permitted') for r in permitted]
    if choices:
        body+=form('/discovery/run',select('target_id','Currently permitted target',choices),'Queue approved discovery')
    else:body+='<p class="empty">No currently permitted targets. Grant an eligible target explicit scan permission above before queueing.</p>'
    body+='<details class="workflow"><summary>Opt-in schedules</summary><p>Minimum interval: 15 minutes. Missed intervals are skipped. Disabling a schedule does not revoke scan permission.</p>'
    if choices:
        body+=form('/discovery/schedule',select('target_id','Permitted target schedule',choices)+field('interval_minutes','Interval in minutes (minimum 15)','60',True,'number')+select('enabled','Schedule',[('false','Disabled'),('true','Enabled')]),'Save schedule')
    schedules=[dict(r) for r in store.connection.execute('SELECT * FROM scan_schedules')]
    for row in schedules:
        row['asset']=asset_label(by_id[row['target_id']]) if row['target_id'] in by_id else row['target_id']
        row['state']='Enabled' if row['enabled'] else 'Disabled';row['interval']=str(row['interval_seconds']//60)+' minutes'
        row['due']=datetime.fromtimestamp(row['next_due'],timezone.utc).isoformat(timespec='seconds')
    def disable(row):
        return form('/discovery/schedule',hidden('target_id',row['target_id'])+hidden('interval_minutes',row['interval_seconds']//60)+hidden('enabled','false'),'Disable schedule') if row['enabled'] else ''
    body+=table(schedules,[('asset','Target'),('state','Schedule'),('interval','Interval'),('due','Next due UTC')],actions=disable)+'</details>'
    body+='<h2>Execution history</h2>'
    runs=[dict(r) for r in store.connection.execute('SELECT * FROM scan_runs ORDER BY requested_at DESC LIMIT 50 OFFSET ?',(offset,))]
    if not runs:body+='<p class="empty">No executions yet. Queue a permitted target, then run the discovery worker.</p>'
    for row in runs:
        name=asset_label(by_id[row['target_id']]) if row['target_id'] in by_id else row['target_id']
        body+='<article class="record"><h3>'+e(name)+' · '+e(row['status'].replace('_',' ').title())+'</h3><p>'+e(row['requested_at'])+'</p>'
        body+=raw_record({**row,'result':json.loads(row['result_json'])},'Execution results and evidence')
        if row['status'] in {'queued','running'}:body+=form('/discovery/cancel',hidden('run_id',row['run_id']),'Cancel this execution')
        body+='</article>'
    body+='<details class="workflow" id="discovery-worker-status"><summary>Worker and collector status</summary>'+table(collector_rows,[(k,k.replace('_',' ').title()) for k in ('kind','status','heartbeat','last_success','message')])
    body+='<p>Run <code>python3 -m phylax --db /path/to/your.db worker</code> in a separate terminal using the same database.</p></details>'
    return body,store.connection.execute('SELECT COUNT(*) FROM scan_runs').fetchone()[0]
