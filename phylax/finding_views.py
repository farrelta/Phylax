"""Focused assessment view shared by narrow and wide browser layouts."""
import json
from urllib.parse import urlencode
from .ui import verbatim, e,evidence_lines,reference_links,evidence_url,assist_link
from .theme import layout,status_marker
from .prioritization import prioritize


def finding_case(store,finding,kev_label,notice=''):
    f=finding;fid=f['finding_id'];score=prioritize(f,f,f['status'])
    plan=store.get_remediation_plan(fid)
    body=('<p class="notice" role="status">'+e(notice)+'</p>') if notice else ''
    body+='<p><a href="/">Return to overview</a> · <a href="/triage?'+e(urlencode({'q':f['cve_id']}))+'">Related alerts in triage</a></p>'
    body+='<article class="finding-case" id="finding-'+e(fid)+'"><h2>'+e(f['cve_id'])+' · '+verbatim(f['hostname'] or f['ip_address'])+'</h2>'
    body+='<p>'+status_marker(f['status'])+' · '+e(f['severity'] or 'Unknown')+' severity · '+e(score['priority'].replace('_',' '))+' urgency</p>'
    if f['synthetic']:body+='<p class="notice">Synthetic demonstration fixture; not a public CVE or real incident.</p>'
    body+='<p>'+verbatim(f['summary'])+'</p><div class="record-actions">'
    if plan:
        body+='<span>Plan status: '+e(plan['status'])+'</span><a class="btn primary" href="/remediation?'+e(urlencode({'finding_id':fid}))+'">Review plan</a>'
    else:body+=assist_link('remediation', 'Draft remediation guidance', fid)
    body+='</div><h3>Affected asset</h3><dl class="facts">'
    for label,value in [('Address',f['ip_address']),('Product / version',' '.join(v for v in (f['vendor'],f['product'],f['version']) if v) or 'Unknown'),('Identity confidence',f['identity_confidence']),('Criticality',f['criticality']),('Zone',f['zone'])]:
        body+='<div><dt>'+e(label)+'</dt><dd>'+e(value)+'</dd></div>'
    body+='</dl><p><a href="/assets/edit?'+e(urlencode({'asset_id':f['asset_id']}))+'">Review asset identity</a> · <a href="/processes?'+e(urlencode({'asset_id':f['asset_id']}))+'">Operational context</a></p>'
    body+='<h3>Applicability evidence</h3>'+evidence_lines(json.loads(f['evidence']))
    components = store.connection.execute('''SELECT s.component_id,s.source_file,s.event_ref,
        EXISTS(SELECT 1 FROM observations o WHERE o.event_ref=s.event_ref) AS has_observation
        FROM component_assessments c JOIN software_components s USING(component_id)
        WHERE c.finding_id=?''', (fid,))
    for component in components:
        review = '/software?'+urlencode({'component_id':component['component_id']})+'#review-component'
        original = evidence_url(component['event_ref'], '/?'+urlencode({'finding_id':fid}))
        body+='<p>'+verbatim(component['source_file'])
        if component['has_observation']:
            body+=' · <a href="'+e(original)+'">Original event</a>'
        body+=' · <a href="'+e(review)+'">Review evidence</a></p>'
    missing=json.loads(f['missing_evidence'])
    body+='<h3>Missing evidence</h3><ul>'+''.join('<li>'+e(v)+'</li>' for v in (missing or ['None recorded for this assessment.']))+'</ul>'
    body+='<details class="score-details"><summary>Why this urgency'+(' · '+str(score['score'])+' of 12' if score['score'] is not None else '')+'</summary><ul>'
    body+=''.join('<li>'+e(v['input'])+': '+e(v['value'])+' · +'+e(v['points'])+'</li>' for v in score['factors'])
    body+='</ul>'+''.join('<p>'+e(v)+'</p>' for v in score.get('uncertainty',[]))+'</details><p>'+e(kev_label)+'</p>'
    body+='<h3>Stored mitigation guidance</h3><p>'+(verbatim(f['mitigation']) if f['mitigation'] else e('No verified vendor guidance supplied.'))+'</p>'
    refs=json.loads(f['references_json'])
    body+='<details><summary>Source provenance and references</summary><p>'+e(f['source'])+' · published '+e(f['published'] or 'Unknown')+' · modified '+e(f['modified'] or 'Unknown')+'</p><p>'+(reference_links(refs) or 'No references supplied.')+'</p></details>'
    body+='</article><footer>Applicability and urgency are deterministic assessments. A vulnerability match does not establish compromise. No infrastructure changes are performed here.</footer>'
    return layout('Vulnerability finding',body,'/',heading='Vulnerability finding')
