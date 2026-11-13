"""Record-bound asset and process context editors."""
import json
from urllib.parse import urlencode
from .ui import verbatim, e,field,select,hidden,form,actor_fields,table
from .asset_intelligence import context_revision


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
    body+='<section class="editor"><h2>Context for '+verbatim(asset_label(asset))+'</h2>'
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
        return '<details><summary>Remove relationship</summary><p>'+verbatim(row['asset'])+' supports '+verbatim(row['name'])+'</p>'+form('/processes/unlink',
            hidden('asset_id',row['asset_id'])+hidden('process_id',row['process_id'])+actor_fields(),'Remove this relationship')+'</details>'
    body+='<h2>Confirmed process support</h2>'+table(links,[('asset','Asset'),('name','Process'),('actor','Confirmed by'),('note','Evidence')],actions=remove)
    total=max(store.connection.execute('SELECT COUNT(*) FROM asset_context').fetchone()[0],store.connection.execute('SELECT COUNT(*) FROM process_links').fetchone()[0])
    return body,total
