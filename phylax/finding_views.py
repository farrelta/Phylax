"""Focused assessment view shared by narrow and wide browser layouts."""
import json
from urllib.parse import urlencode
from .ui import verbatim, e,evidence_lines,reference_links,evidence_url,form,hidden
from .theme import layout,status_marker,icon
from .prioritization import prioritize
from .remediation import CONFIRMED, EXCLUDED, next_step, plan_finding_context, stored_mitigation
from .remediation_lifecycle import plan_review_block


AXES = (('KEV membership', 'Known exploitation', 3), ('Source severity', 'Flaw severity', 3),
        ('Asset criticality', 'Device importance', 3), ('Confirmed applicability', 'Confirmed match', 2),
        ('Network zone', 'Network zone', 1))


def radar(factors):
    import math
    points = {f['input']: f['points'] for f in factors}
    cx, cy, radius = 210, 128, 86
    def spot(index, share):
        angle = -math.pi / 2 + index * 2 * math.pi / len(AXES)
        return cx + radius * share * math.cos(angle), cy + radius * share * math.sin(angle)
    def polygon(shares):
        return ' '.join(f'{x:.1f},{y:.1f}' for x, y in (spot(i, s) for i, s in enumerate(shares)))
    out = ''.join(f'<polygon class="grid" points="{polygon([level] * len(AXES))}"/>' for level in (1 / 3, 2 / 3, 1))
    out += ''.join(f'<line class="axis" x1="{cx}" y1="{cy}" x2="{spot(i, 1)[0]:.1f}" y2="{spot(i, 1)[1]:.1f}"/>' for i in range(len(AXES)))
    out += f'<polygon class="max" points="{polygon([1] * len(AXES))}"/>'
    shares = [min(1, points.get(key, 0) / top) for key, _, top in AXES]
    out += f'<polygon class="val" points="{polygon([max(s, .04) for s in shares])}"/>'
    out += ''.join(f'<circle class="pt" cx="{spot(i, max(s, .04))[0]:.1f}" cy="{spot(i, max(s, .04))[1]:.1f}" r="3"/>' for i, s in enumerate(shares))
    for i, (key, label, top) in enumerate(AXES):
        x, y = spot(i, 1.2)
        anchor = 'middle' if abs(x - cx) < 10 else ('start' if x > cx else 'end')
        out += f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="{anchor}">{e(label)} {points.get(key, 0)}/{top}</text>'
    return f'<svg class="radar" viewBox="0 0 420 262" role="img" aria-label="Urgency score by factor">{out}</svg>'


def finding_case(store,finding,kev_label,notice=''):
    f=finding;fid=f['finding_id'];score=prioritize(f,f,f['status'])
    plan=store.get_remediation_plan(fid)
    name=f['hostname'] or f['ip_address']
    body=('<p class="notice" role="status">'+e(notice)+'</p>') if notice else ''
    body+='<article class="finding-case" id="finding-'+e(fid)+'">'
    urgency=score['priority']
    body+=('<section class="case-head"><div class="case-top"><div><h2>'+e(f['cve_id'])+' · '+verbatim(name)+'</h2></div>'
           '<div class="case-pills"><span>'+status_marker(f['status'])+'</span><span><i class="u-dot u-'+e(urgency)+'"></i>'
           +e(urgency.replace('_',' ').capitalize())+' urgency</span></div></div><dl class="case-facts">')
    for label,value in [('Device',name),('Severity',(f['severity'] or 'Unknown').capitalize()),
                        ('Urgency',(str(score['score'])+' / 12') if score['score'] is not None else 'Not scored'),
                        ('Published',f['published'] or 'Unknown'),('Last update',f['modified'] or 'Unknown')]:
        body+='<div><dt>'+e(label)+'</dt><dd>'+(verbatim(value) if label=='Device' else e(value))+'</dd></div>'
    body+='</dl><p><a href="/triage?'+e(urlencode({'q':f['cve_id']}))+'">Related alerts</a></p></section>'
    if f['synthetic']:body+='<p class="notice">Synthetic demonstration fixture; not a public CVE or real incident.</p>'
    body+='<div class="case-grid" id="case-overview"><section class="cardx"><h3>Information</h3><p>'+verbatim(f['summary'])+'</p><dl class="kv">'
    for label,value in [('Address',f['ip_address']),('Product / version',' '.join(v for v in (f['vendor'],f['product'],f['version']) if v) or 'Unknown'),('Identity confidence',f['identity_confidence']),('Criticality',f['criticality']),('Zone',f['zone'])]:
        body+='<div><dt>'+e(label)+'</dt><dd>'+e(value)+'</dd></div>'
    body+='</dl><p><a href="/assets/edit?'+e(urlencode({'asset_id':f['asset_id']}))+'">Review asset identity</a> · <a href="/processes?'+e(urlencode({'asset_id':f['asset_id']}))+'">Operational context</a></p></section>'
    body+=('<section class="cardx"><header><h3>Why this urgency'+(' · '+str(score['score'])+' of 12' if score['score'] is not None else '')+'</h3>'
           '<span class="legend-row"><span><i class="lg-val"></i>This finding</span><span><i class="lg-max"></i>Highest possible</span></span></header>'
           +radar(score['factors']))
    body+='<details class="score-details"><summary>How the score is counted</summary><ul>'
    body+=''.join('<li>'+e(v['input'])+': '+e(v['value'])+' · +'+e(v['points'])+'</li>' for v in score['factors'])
    body+='</ul>'+''.join('<p>'+e(v)+'</p>' for v in score.get('uncertainty',[]))+'</details><p class="muted">'+e(kev_label)+'</p></section></div>'
    body+='<div class="case-grid"><section class="cardx" id="case-evidence"><h3>Applicability evidence</h3>'+evidence_lines(json.loads(f['evidence']))
    components = store.connection.execute("""SELECT s.component_id,s.source_file,s.event_ref,
        EXISTS(SELECT 1 FROM observations o WHERE o.event_ref=s.event_ref) AS has_observation
        FROM component_assessments c JOIN software_components s USING(component_id)
        WHERE c.finding_id=?""", (fid,))
    for component in components:
        review = '/software?'+urlencode({'component_id':component['component_id']})+'#review-component'
        original = evidence_url(component['event_ref'], '/?'+urlencode({'finding_id':fid}))
        body+='<p>'+verbatim(component['source_file'])
        if component['has_observation']:
            body+=' · <a href="'+e(original)+'">Original event</a>'
        body+=' · <a href="'+e(review)+'">Review evidence</a></p>'
    missing=json.loads(f['missing_evidence'])
    body+='<h3>Missing evidence</h3><ul>'+''.join('<li>'+e(v)+'</li>' for v in (missing or ['None recorded for this assessment.']))+'</ul></section>'
    mitigation = stored_mitigation(f)
    body+='<section class="cardx" id="case-fix"><h3>Next step</h3><p>'+e(next_step(f['status'], mitigation))+'</p>'
    if mitigation:
        body+='<details><summary>Advisory guidance for reference</summary><p>'+verbatim(mitigation)+'</p></details>'
    if plan and f['status'] == CONFIRMED and (reason := plan_review_block(plan | plan_finding_context(f))):
        body+='<p>'+e(reason)+'</p>'
    body+='<div class="record-actions">'
    if plan:
        body+='<span>Plan status: '+e(plan['status'])+'</span><a class="btn primary" href="/remediation?'+e(urlencode({'finding_id':fid}))+'">Review plan</a>'
    elif f['status'] != EXCLUDED:
        label = 'Create remediation plan' if f['status'] == CONFIRMED else 'Create review draft'
        body+=form('/remediation/create', hidden('finding_id', fid), label)
    body+='</div></section></div>'
    refs=json.loads(f['references_json'])
    body+='<section class="cardx" id="case-sources"><details><summary>Source provenance and references</summary><p>'+e(f['source'])+' · published '+e(f['published'] or 'Unknown')+' · modified '+e(f['modified'] or 'Unknown')+'</p><p>'+(reference_links(refs) or 'No references supplied.')+'</p></details></section>'
    body+='</article><footer>Applicability and urgency are deterministic assessments. A vulnerability match does not establish compromise. No infrastructure changes are performed here.</footer>'
    return layout('Vulnerability finding',body,'/',heading='Vulnerability finding',
                  crumbs=[('/#findings','Exposure findings'),(None,'<span translate="no">'+e(f['cve_id'])+'</span>')])
