"""One labeled review form for overview and remediation workflows."""
from .ui import verbatim, e,field,hidden,error_summary
from .remediation_lifecycle import ADVANCES, TRANSITIONS, plan_review_block


def alert_plan_fields(item):
    alert = item['alert']
    return (hidden('category', alert['category']) + hidden('alert_id', alert['alert_id'])
            + hidden('alert_revision', alert['revision']) + hidden('plan_id', item.get('plan_id', ''))
            + hidden('plan_version', item.get('version', '')))


def lifecycle_form(item,submitted=None,error=''):
    values=submitted or {}
    alert_case = 'alert' in item
    prefix='plan-'+(item['alert_id'] if alert_case else item['finding_id'])
    options=TRANSITIONS.get(item['status'],())
    if 'finding_status' in item and plan_review_block(item):
        options=tuple(status for status in options if status not in ADVANCES)
    selected=values.get('status',options[0] if options else '')
    choices=([(selected,selected+' (unavailable; choose a valid next status)')] if selected and selected not in options else [])+[(s,s) for s in options]
    problem='reviewer' if 'Reviewer is required' in error else 'verification_evidence' if 'Verification evidence is required' in error else 'change_notes' if 'in the approval notes' in error else 'status'
    body=error_summary(error,[(prefix+'-'+problem,'Review '+problem.replace('_',' '))]) if error else ''
    subject = verbatim(item['alert'].get('ip') or item['alert'].get('destination_ip')) if alert_case else (
        e(item.get('cve_id',''))+' · '+verbatim(item.get('hostname') or item.get('ip_address','')))
    body+='<form method="post" action="/remediation/update" class="lifecycle-form"><fieldset><legend>Review plan for '+subject+'</legend>'
    if alert_case:
        body+=alert_plan_fields(item)
    else:
        body+=hidden('finding_id',item['finding_id'])+hidden('plan_id',item['plan_id'])+hidden('plan_version',len(item['history']))
    body+='<p class="muted">Current status: '+e(item['status'])+'. Only valid next statuses are offered. Typed reviewer names record attribution; they are not authenticated identities.</p><div class="form-grid">'
    body+='<label><span id="'+e(prefix+'-status-label')+'">Next plan status</span><select name="status" id="'+e(prefix+'-status')+'" aria-labelledby="'+e(prefix+'-status-label')+'"'+(' aria-invalid="true" aria-describedby="'+e(prefix+'-status-error')+'"' if error and problem=='status' else '')+'>'
    body+=''.join('<option value="'+e(value)+'"'+(' selected' if value==selected else '')
                  +(' disabled' if value not in options else '')+'>'+e(text)+'</option>'
                  for value,text in choices)+'</select>'
    if error and problem=='status':body+='<small class="field-error" id="'+e(prefix+'-status-error')+'">'+e(error)+'</small>'
    body+='</label>'
    notes_hint = 'When approving without stored mitigation, record the specific action here.' if 'Approved' in options and not item.get('current_mitigation') else 'Leave blank to retain recorded notes.'
    for name,label,maximum,hint in (
        ('reviewer','Reviewer',120,'Required when approving. Leave blank to retain the recorded reviewer.'),
        ('change_notes','Review / change notes',2000,notes_hint),
        ('verification_evidence','Verification evidence',4000,'Required when marking Verified. Returning to Under Review clears prior verification evidence.')):
        body+=field(name,label,values.get(name,''),maxlength=maximum,control_id=prefix+'-'+name,help_text=hint,error=error if error and problem==name else '')
    return body+'</div><button class="primary">Update plan status</button></fieldset></form>'
