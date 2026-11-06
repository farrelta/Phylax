"""Contextual management and software review actions bound to their records."""
import json
from urllib.parse import urlencode
from .ui import e,field,select,hidden,form,actor_fields,table,raw_record
from .configuration_pages import asset_label


def approvals_page(store,query,offset,submitted=None):
    values=submitted or {};subnets=[dict(r) for r in store.connection.execute('SELECT * FROM monitored_subnets')]
    body='<p>Unmanaged endpoints need review. Only an explicit block establishes unauthorized status. Approval does not grant scan permission.</p>'
    if subnets:
        body+='<h2>Record a management decision</h2>'+form('/approvals/decide',
            select('subnet_id','Monitored network',[(r['subnet_id'],r['name']+' · '+r['cidr']) for r in subnets],values.get('subnet_id'))
            +'<div class="form-grid">'+field('ip','IP address (optional with MAC)',values.get('ip',query.get('ip',[''])[0]))
            +field('mac','MAC address (optional with IP)',values.get('mac',''))+'</div>'
            +select('decision','Decision',[('approved','Approve management'),('blocked','Explicitly block identity')],values.get('decision','approved'))
            +actor_fields(values),'Record management decision')
    else:body+='<p class="notice">Configure a monitored subnet below before recording management decisions or generating unmanaged-endpoint alerts.</p>'
    rows=[dict(r) for r in store.connection.execute('SELECT d.*,s.name AS network FROM endpoint_decisions d JOIN monitored_subnets s USING(subnet_id) ORDER BY d.created_at DESC LIMIT 50 OFFSET ?',(offset,))]
    for row in rows:
        row['identity']=row['ip'] or 'Any IP matching MAC';row['mac_label']=row['mac'] or 'IP-only decision'
        row['decision_label']='Approved management' if row['decision']=='approved' else 'Explicitly blocked'
        row['state']='Active' if row['active'] else 'Revoked'
    def actions(row):
        result=raw_record(row,'Decision history and identifiers')
        if row['active']:
            edit=values if values.get('decision_id')==row['decision_id'] else {}
            result+='<details><summary>Revoke this decision</summary><p>'+e(row['identity'])+' · '+e(row['mac_label'])+' · '+e(row['decision_label'])+'</p>'+form('/approvals/revoke',hidden('decision_id',row['decision_id'])+actor_fields(edit),'Revoke this decision')+'</details>'
        return result
    body+='<h2>Management decision history</h2>'+table(rows,[('identity','Address'),('mac_label','MAC scope'),('network','Network'),('decision_label','Decision'),('state','State'),('actor','Recorded by')],actions=actions)
    body+='<details class="workflow"'+(' open' if not subnets else '')+'><summary>Configure monitored subnets</summary>'+table(subnets,[('name','Network'),('cidr','Subnet')])
    body+=form('/approvals/subnet',field('name','Network name',values.get('name',''),True)+field('cidr','Monitored subnet (CIDR)',values.get('cidr',''),True),'Add monitored subnet')+'</details><p><a href="/triage?category=endpoint">Review unmanaged endpoints in triage</a></p>'
    return body,store.connection.execute('SELECT COUNT(*) FROM endpoint_decisions').fetchone()[0]


def software_page(store,query,offset,submitted=None):
    values=submitted or {}
    rows=[dict(r) for r in store.connection.execute('SELECT s.*,a.hostname,a.ip_address FROM software_components s JOIN assets a USING(asset_id) ORDER BY s.last_seen DESC LIMIT 50 OFFSET ?',(offset,))]
    for row in rows:
        row['asset']=asset_label(row);row['identity']=(row['vendor']+' / '+row['product']) if row['vendor'] and row['product'] else 'Unmapped identity'
        row['verification']='Verified' if row['verified'] else 'Unverified';row['state']='Active evidence' if row['active'] else 'Retired evidence'
    body='<p>Observed versions remain unverified until reviewed. Multiple active versions require review; retire obsolete evidence only after checking installation scope.</p>'
    body+=table(rows,[('asset','Asset'),('raw_name','Software'),('version','Version'),('identity','Exact mapping'),('verification','Verification'),('state','Evidence state')],
        actions=lambda r:'<a href="/software?'+e(urlencode({'component_id':r['component_id']}))+'#review-component">Review evidence</a>',empty='No software evidence imported. Import a Zeek software log or review an approved IT identification result.')
    cid=values.get('component_id',query.get('component_id',[''])[0])
    if cid:
        row=store.connection.execute('SELECT s.*,a.hostname,a.ip_address FROM software_components s JOIN assets a USING(asset_id) WHERE component_id=?',(cid,)).fetchone()
        if not row:raise ValueError('Software component not found. Choose an existing evidence row.')
        row=dict(row)
        body+='<section class="editor" id="review-component"><h2>Review '+e(row['raw_name'])+' '+e(row['version'] or 'unknown version')+'</h2><p>'+e(asset_label(row))+'</p>'
        body+='<p>First observed '+e(row['first_seen'])+' · last observed '+e(row['last_seen'])+'</p>'
        fields=hidden('component_id',cid)+select('verified','Identity and version verified',[('false','Unverified'),('true','Verified')],values.get('verified','true' if row['verified'] else 'false'))
        fields+=select('active','Evidence state',[('true','Active evidence'),('false','Retired evidence')],values.get('active','true' if row['active'] else 'false'))+actor_fields(values)
        body+=form('/software/review',fields,'Save review for this component')+raw_record(row,'Original software evidence and identifiers')+'</section>'
    body+='<details class="workflow"><summary>Manage an exact product mapping</summary><p>Use a source product identifier supported by verified mapping evidence. Similar names alone do not establish a match.</p>'+form('/software/map',
        field('raw_name','Exact observed software name',values.get('raw_name',''),True)+field('vendor','Source product vendor identifier',values.get('vendor',''),True)+field('product','Source product identifier',values.get('product',''),True)+actor_fields(values),'Save exact mapping')+'</details>'
    return body,store.connection.execute('SELECT COUNT(*) FROM software_components').fetchone()[0]
