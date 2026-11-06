"""One labeled review form for overview and remediation workflows."""
from .ui import e,field,hidden,error_summary
from .remediation_lifecycle import TRANSITIONS


def lifecycle_form(item,submitted=None,error=''):
    values=submitted or {}
    prefix='plan-'+item['finding_id']
    options=TRANSITIONS.get(item['status'],())
    selected=values.get('status',options[0] if options else '')
    choices=([(selected,selected+' (unavailable; choose a valid next status)')] if selected and selected not in options else [])+[(s,s) for s in options]
    problem='reviewer' if 'Reviewer is required' in error else 'verification_evidence' if 'Verification evidence is required' in error else 'status'
    body=error_summary(error,[(prefix+'-'+problem,'Review '+problem.replace('_',' '))]) if error else ''
    body+='<form method="post" action="/remediation/update" class="lifecycle-form"><fieldset><legend>Review plan for '+e(item.get('cve_id',''))+' · '+e(item.get('hostname') or item.get('ip_address',''))+'</legend>'
    body+=hidden('finding_id',item['finding_id'])
    body+='<p class="muted">Current status: '+e(item['status'])+'. Only valid next statuses are offered. Typed reviewer names record attribution; they are not authenticated identities.</p><div class="form-grid">'
    body+='<label><span id="'+e(prefix+'-status-label')+'">Next plan status</span><select name="status" id="'+e(prefix+'-status')+'" aria-labelledby="'+e(prefix+'-status-label')+'"'+(' aria-invalid="true" aria-describedby="'+e(prefix+'-status-error')+'"' if error and problem=='status' else '')+'>'
    body+=''.join('<option value="'+e(value)+'"'+(' selected' if value==selected else '')+'>'+e(text)+'</option>' for value,text in choices)+'</select>'
    if error and problem=='status':body+='<small class="field-error" id="'+e(prefix+'-status-error')+'">'+e(error)+'</small>'
    body+='</label>'
    for name,label,maximum,hint in (
        ('reviewer','Reviewer',120,'Required when approving. Leave blank to retain the recorded reviewer.'),
        ('change_notes','Review / change notes',2000,'Leave blank to retain recorded notes.'),
        ('verification_evidence','Verification evidence',4000,'Required when marking Verified. Returning to Under Review clears prior verification evidence.')):
        body+=field(name,label,values.get(name,''),maxlength=maximum,control_id=prefix+'-'+name,help_text=hint,error=error if error and problem==name else '')
    return body+'</div><button class="primary">Update plan status</button></fieldset></form>'
