"""Small local-only operator dashboard built on Python's standard library."""

from __future__ import annotations

import html
import json
import re
import secrets
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from .core import Store, read_json_limited, ASSET_FIELDS
from .web_security import CSP, valid_host, valid_origin, valid_token, form_token, protect_forms
from .prioritization import prioritize
from .jobs import Jobs
from .remediation_service import generate_plan
from .remediation_presenter import plan_card
from .finding_views import finding_case
from .advisory_views import advisory_summary
from .operator_pages import inventory_form,policy_page,settings_page,reports_page
from .theme import layout, ring, status_marker, term, glossary_page
from .feeds import sync_store
from .monitoring import ingest_file, validate_policy, reevaluate_events
from . import release_web
from .ui import field, select, table, pager, reference_links, evidence_lines, evidence_url
from .topology import render_topology, url as surface_url, values as surface_query


MAX_UPLOAD = 5_000_000


def kev_status(finding,source_health):
    """Describe stored membership without claiming absence of exploitation."""
    if finding.get('synthetic'):
        return 'Synthetic KEV association: '+('yes' if finding.get('kev') else 'no')
    if finding.get('kev'):return 'KEV-associated in stored intelligence'
    catalog=next((r for r in source_health if r['source']=='CISA KEV'),None)
    if not catalog or not catalog.get('last_success_at'):
        return 'KEV status unknown; no successful catalog synchronization'
    health=catalog['health']
    coverage='cached catalog' if health=='healthy' else 'stale cached catalog' if health=='stale' else 'cached catalog; latest synchronization unavailable'
    return 'Not listed in CISA KEV '+coverage+' · last success '+catalog['last_success_at']


def evidence_html(items) -> str:
    return evidence_lines(items)


def page(store: Store, notice: str = "", page_number: int = 1, finding_id: str = '') -> str:
    page_number = max(1,page_number)
    data = store.dashboard(limit=50,offset=(page_number-1)*50)
    if finding_id:
        finding=store.finding(finding_id)
        if not finding:raise ValueError('Finding not found')
        return finding_case(store,finding,kev_status(finding,data['source_health']),notice)
    cards = [("Devices in inventory", data["assets"], ""), ("Devices to identify", data["assets_needing_identity_review"], "Identity review"), ("Confirmed affected", data["confirmed_assets"], "Confirmed affected"), ("Possibly affected", data["potential_assets"], "Possibly affected"), ("Known-exploited flaws", data["kev_findings"], "KEV"), ("Critical devices at risk", data["critical_exposed_assets"], ""), ("Network connections seen", data["communication_relationships"], ""), ("New alerts", data["unacknowledged_alerts"], ""), ("Out-of-date data feeds", data["stale_sources"], "")]
    rows = []
    for f in data["findings"]:
        evidence = evidence_html(json.loads(f["evidence"]))
        missing = "<br>".join(html.escape(x) for x in json.loads(f["missing_evidence"])) or "None recorded"
        references = reference_links(json.loads(f["references_json"])) or "No references supplied"
        urgency = prioritize(f,f,f["status"])
        priority_detail = "; ".join(f"{x['input']}: {x['value']} (+{x['points']})" for x in urgency["factors"])
        assessment_confidence = {"CONFIRMED_MATCH": "high", "NO_MATCH_TO_THIS_ADVISORY": "high", "POTENTIAL_MATCH": "medium", "NEEDS_REVIEW": "low"}.get(f["status"], "unknown")
        plan_data = store.get_remediation_plan(f["finding_id"])
        if plan_data:
            plan_action = (f'<p>Plan status: {html.escape(plan_data["status"])} · updated {html.escape(plan_data["updated_at"])}</p>'
                           f'<a class="btn" href="/remediation?{urlencode({"finding_id":f["finding_id"]})}">Review plan</a>')
        else:
            plan_action = f'<form method="post" action="/remediation/create"><input type="hidden" name="finding_id" value="{html.escape(f["finding_id"], quote=True)}"><button>Generate remediation plan</button></form>'
        rows.append(f"""<tr id="finding-{html.escape(f['finding_id'],quote=True)}"><td><b class="mono"><a href="/?{urlencode({'finding_id':f['finding_id']})}#finding-{html.escape(f['finding_id'],quote=True)}">{html.escape(f['cve_id'])}</a></b><br>{'DEMO FIXTURE' if f['synthetic'] else html.escape(f['source'])}<br><small>Published {html.escape(f['published'] or 'Unknown')} · modified {html.escape(f['modified'] or 'Unknown')}<br>{references}</small></td>
          <td><span class="mono">{html.escape(f['ip_address'])}</span> {html.escape(f['hostname'])}<br>{html.escape(f['vendor'])} {html.escape(f['product'])} {html.escape(f['version'])}<br><small>{html.escape(f['criticality'])} criticality · identity {html.escape(f['identity_confidence'])} · {html.escape(f['zone'])} zone</small></td>
          <td>{status_marker(f['status'])}<br><b>Urgency {urgency['score'] if urgency['score'] is not None else 'n/a'} of 12</b> · {html.escape(f['priority'])}<br>{html.escape(f['severity'] or 'Unknown')} severity · {html.escape(kev_status(f,data['source_health']))}<details><summary>Why this score</summary><small>{html.escape(priority_detail)}<br>Match confidence: {assessment_confidence}</small></details></td>
          <td>{evidence}<br><small>Missing: {missing}</small></td>
          <td>{html.escape(f['summary'])}<br><small>{html.escape(f['mitigation'] or 'No verified vendor guidance supplied.')}</small><br>{plan_action}</td></tr>""")
    finding_table = "".join(rows) or '<tr><td colspan="5" class="empty">No findings yet. Import assets and load a local fixture to begin.</td></tr>'
    alert_summary = (f'<p>{data["unacknowledged_alerts"]} unacknowledged alerts across vulnerability, network and device-management evidence.</p>'
                     '<p><a href="/triage?acknowledged=no">Review new alerts in Triage</a></p>')
    health_html = "".join(f'<div class="alert"><div><b>{html.escape(source["source"])} · {html.escape(source["health"])}</b><br><small>Last success: {html.escape(source["last_success_at"] or "Never")} · {html.escape(source["message"])}</small></div></div>' for source in data["source_health"]) or '<p class="empty">No synchronization yet. Stored offline data remains available.</p>'
    updates_html = "".join(f'<div class="alert"><div><b>{html.escape(item["change_type"])} · {html.escape(item["cve_id"])}</b><br><small>{html.escape(item["source"])} · {html.escape(item["changed_at"])}<br>{html.escape(item["summary"])}</small></div></div>' for item in data["recent_intelligence"]) or '<p class="empty">No intelligence records stored yet.</p>'
    identity_review_html = f'<p class="notice">{data["assets_needing_identity_review"]} assets need identity review. Unknown product or version information limits vulnerability assessment. <a href="/assets?identity_review=yes">Review these assets</a>.</p>' if data["assets_needing_identity_review"] else ""
    largest = data['findings_count']
    pager = (f'<a class="link" href="/?page={page_number-1}">Previous</a>' if page_number>1 else '')
    if page_number>1 or page_number*50 < largest:
        pager += f' <span class="muted">Page {page_number}</span> '
    if page_number*50 < largest:pager += f'<a class="link" href="/?page={page_number+1}">Next</a>'
    pager = f'<div class="controls">{pager}</div>' if pager.strip() else ''
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    hot = {"Confirmed affected", "Known-exploited flaws", "Critical devices at risk", "New alerts"}
    def stat_items(items):
        return "".join(f'<div class="{"hot" if label in hot and value else ""}"><dt>{term(tip, label) if tip else html.escape(label)}</dt><dd>{value}</dd></div>' for label,value,tip in items)
    primary_metrics={'Devices in inventory','Confirmed affected','Possibly affected','New alerts'}
    stats_html=stat_items(c for c in cards if c[0] in primary_metrics)
    more_stats='<details class="workflow"><summary>More inventory and source metrics</summary><dl class="stats">'+stat_items(c for c in cards if c[0] not in primary_metrics)+'</dl></details>'
    scored = []
    for f in data["findings"]:
        u = prioritize(f, f, f["status"])
        if u["score"] is not None:
            scored.append((u["score"], u["priority"], f))
    scored.sort(key=lambda t: -t[0])
    tone = {"critical": "crit", "high": "high", "medium": "info"}
    focus_cards = "".join(
        f'<a class="card" href="/?{urlencode({"finding_id":f["finding_id"]})}#finding-{html.escape(f["finding_id"],quote=True)}">{ring(score, 12, str(score), tone.get(priority, "none"))}<div><b>{html.escape(f["cve_id"])}</b>'
        f'<small>{html.escape(f["hostname"] or f["ip_address"])} · {html.escape(priority)} priority</small><div class="t">{status_marker(f["status"])}</div></div></a>'
        for score, priority, f in scored[:3])
    surface = store.attack_surface()
    inventory_nodes = [n for n in surface["nodes"] if n["asset_id"]]
    seen = sum(1 for n in inventory_nodes if n["observed"])
    focus_cards += (f'<div class="card">{ring(seen, len(inventory_nodes), f"{seen}/{len(inventory_nodes)}", "ok")}<div><b>Network visibility</b>'
                    f'<small>{seen} of {len(inventory_nodes)} inventory assets appear in imported logs</small></div></div>')
    total_assets, confirmed, possible = data["assets"], data["confirmed_assets"], data["potential_assets"]
    if not total_assets:
        headline = "No devices loaded yet.<small>Start with step 1 below: import your list of devices.</small>"
    elif scored:
        top_score, top_priority, top = scored[0]
        headline = (f"{confirmed} of {total_assets} devices are confirmed affected by a known flaw, and {possible} more are possibly affected."
                    f'<small>Start with <b>{html.escape(top["cve_id"])}</b> on <b>{html.escape(top["hostname"] or top["ip_address"])}</b> '
                    f'(urgency {top_score} of 12, {html.escape(top_priority)}). <a href="#findings">See the findings</a>.</small>')
    else:
        headline = f"None of your {total_assets} devices match a known flaw yet.<small>Sync public intelligence or load an offline advisory below. Imports reassess findings automatically.</small>"
    focus_html = f'<p class="headline">{headline}</p><h2>Top priorities</h2><div class="focus">{focus_cards}</div>'
    content = f"""{notice_html}{pager}{identity_review_html}
<dl class="stats">{stats_html}</dl>{more_stats}
{focus_html}
<p><a class="btn" href="/triage">Open unified security triage</a></p>
<details class="workflow"><summary>Import data</summary><ol class="steps">
<li><b>1 · Inventory</b><form method="post" action="/assets/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".csv,text/csv" aria-label="Asset CSV"><button>Import asset CSV</button></form><a class="link" href="/assets/edit">Add asset manually</a><a class="link" href="/assets">View inventory</a></li>
<li><b>2 · Public intelligence</b><form method="post" action="/sync"><button>Sync public sources</button></form><form method="post" action="/intelligence/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".json,application/json" aria-label="Offline fixture"><button>Load offline fixture</button></form></li>
<li><b>3 · Passive network</b><form method="post" action="/network/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".log,.json,.tsv,text/plain" aria-label="Zeek log"><input name="policy" type="file" accept=".json,application/json" aria-label="Optional policy JSON"><button>Analyze Zeek log</button></form></li>
</ol></details>
<div class="split"><div><h2 id="findings">Exposure findings</h2><section class="panel"><table class="findings"><thead><tr><th>Vulnerability</th><th>Device</th><th>Risk</th><th>Why we think so</th><th>What it is and what to do</th></tr></thead><tbody>{finding_table}</tbody></table></section></div>
<div><h2>Security alerts · {data["network_events"]} network events</h2><section class="panel text-panel">{alert_summary}</section><h2>Intelligence sources</h2><section class="panel">{health_html}</section><h2>Recent intelligence updates</h2><section class="panel">{updates_html}</section></div></div>
<footer>Urgency is a transparent rule-based priority; severity and applicability remain separate. KEV indicates catalog-listed exploitation, not an attack on this asset. Absence of a finding does not mean an asset is safe. Timestamps are stored in UTC. Exports are on the <a href="/reports">Reports</a> page.</footer>"""
    if not total_assets:
        content=notice_html+'''<section class="setup-start"><h2>Start with your asset inventory</h2><p>No devices loaded yet. Add an asset or import a CSV with an IP address for each device. Unknown product and firmware information can stay blank.</p>
<p><a class="btn primary" href="/assets/edit">Add your first asset</a></p><form method="post" action="/assets/import" enctype="multipart/form-data"><label>Inventory CSV<input required name="file" type="file" accept=".csv,text/csv"></label><button>Import asset CSV</button></form>
<h3>Then build the evidence</h3><ol><li>Load public intelligence or an offline advisory fixture.</li><li>Import Zeek logs or analyze an offline capture.</li><li>Review applicability, missing evidence and policy alerts.</li></ol><p>Control endpoints remain passive-only. Active IT discovery requires separate target permission.</p>
<p><a href="/settings">Check data sources and collector setup</a> · <a href="/intelligence">View stored intelligence</a></p></section>'''
    return layout("Overview", content, "/", lead="Local inventory and stored intelligence. Active IT discovery requires target permission; control endpoints remain passive-only.", heading="Security overview")


def assets_page(store: Store, search: str = "", page_number: int = 1, *, identity_review: bool = False) -> str:
    page_number = max(1, page_number)
    limit = 50
    rows, total = store.search_assets(search, limit=limit, offset=(page_number - 1) * limit, identity_review=identity_review)
    body = "".join(f"""<tr><td class="nw mono">{html.escape(row['ip_address'])}<br><small>ID {html.escape(row['asset_id'])} · {html.escape(row['mac_address'] or 'MAC unknown')}</small><br><a href="/assets/edit?{urlencode({'asset_id':row['asset_id']})}">Edit</a></td><td>{html.escape(row['hostname'] or 'Unknown')}</td>
      <td>{html.escape(row['asset_type'])}<br><small>{html.escape(row['vendor'])} {html.escape(row['product'])} {html.escape(row['version'])}<br>{html.escape(row['operating_system'])}</small></td>
      <td>{html.escape(row['zone'])}<br>{html.escape(row['criticality'])}</td><td>{html.escape(row['identification_source'])}<br><small>{html.escape(row['identity_confidence'])} confidence · {'verified' if row['verified'] else 'unverified'}</small></td><td>{html.escape(row['last_seen'] or 'Unknown')}<br><small>{html.escape(row['notes'])}</small></td></tr>""" for row in rows) or '<tr><td colspan="6" class="empty">No assets found. Import a CSV from the overview.</td></tr>'
    query = urlencode({"q": search, **({"identity_review":"yes"} if identity_review else {})})
    previous = f'<a class="link" href="/assets?{query}&page={page_number - 1}">Previous</a>' if page_number > 1 else ""
    next_link = f'<a class="link" href="/assets?{query}&page={page_number + 1}">Next</a>' if page_number * limit < total else ""
    review_control = '<label class="inline-check"><input type="checkbox" name="identity_review" value="yes"'+(' checked' if identity_review else '')+'> Needs identity review</label>'
    content = f"""<div class="controls"><form method="get" action="/assets"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search IP, hostname, vendor, product" aria-label="Search assets">{review_control} <button>Search</button><a href="/assets">Clear filters</a></form><a class="btn primary" href="/assets/edit">Add asset</a><a class="btn" href="/assets.csv">Export CSV</a><span class="muted">{total} assets · page {page_number}</span>{previous}{next_link}</div>
<section class="panel"><table><thead><tr><th>Address</th><th>Hostname</th><th>Type and identity</th><th>Zone / criticality</th><th>Source / confidence</th><th>Last seen / notes</th></tr></thead><tbody>{body}</tbody></table></section>"""
    return layout("Inventory", content, "/assets", lead="Observed metadata remains separate from operator verification. Unknown identity is not inferred from an IP address.", heading="Asset inventory")


def _pager(path: str, search: str, page_number: int, total: int, limit: int = 50) -> str:
    query = urlencode({"q": search})
    previous = f'<a class="link" href="{path}?{query}&page={page_number - 1}">Previous</a>' if page_number > 1 else ""
    following = f'<a class="link" href="{path}?{query}&page={page_number + 1}">Next</a>' if page_number * limit < total else ""
    return f'<span class="muted">{total} records · page {page_number}</span>{previous}{following}'


def intelligence_page(store: Store, search: str = "", page_number: int = 1) -> str:
    page_number = max(1, page_number)
    limit = 50
    records, total, _ = store.search_intelligence(search, limit=limit, offset=(page_number - 1) * limit, include_advisories=False)
    rows = []
    for item in records:
        affected = json.loads(item["affected_products"])
        product_text = "; ".join(f"{p['vendor']} {p['product']} [{', '.join(p.get('versions', [])) or 'versions unspecified'}]" for p in affected) or "Affected product data not provided"
        refs = json.loads(item.get("references_json", "[]"))
        rows.append(f"""<tr><td><b class="mono">{html.escape(item['cve_id'])}</b><br><small>{html.escape(item['source'])}</small></td>
        <td>{html.escape(item['severity'] or 'Unknown')} {('· CVSS ' + html.escape(str(item['cvss']))) if item['cvss'] is not None else ''}<br>KEV {'Yes' if item['kev'] else 'No'}<br><small>Published {html.escape(item['published'] or 'Unknown')}<br>Modified {html.escape(item['modified'] or 'Unknown')}<br>Retrieved {html.escape(item['retrieved_at'])}</small></td>
        <td>{html.escape(item['summary'])}<br><small>{html.escape(product_text)}</small></td><td>{html.escape(item['mitigation'] or 'No mitigation guidance supplied.')}<br><small>{reference_links(refs or ([item['source_url']] if item['source_url'] else [])) or 'No reference supplied'}</small></td></tr>""")
    pager = _pager("/intelligence", search, page_number, total, limit)
    content = f"""<div class="controls"><form method="get" action="/intelligence"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search CVE, summary, source" aria-label="Search intelligence"> <button>Search</button></form><form method="post" action="/sync"><button>Sync public sources</button></form>{pager}</div>
<section class="panel"><table><thead><tr><th>Identifier / source</th><th>Severity / status / dates</th><th>Summary / affected product data</th><th>Mitigation / references</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="4" class="empty">No intelligence records found. Sync sources or load the offline fixture.</td></tr>'}</tbody></table></section>"""
    return layout("CVE intelligence", content, "/intelligence", lead="Normalized CVE records are cached locally. Product/version applicability remains subject to source evidence and the documented matcher limits.")


def ics_advisories_page(store: Store, search: str = '', page_number: int = 1) -> str:
    page_number=max(1,page_number);limit=50
    records,total=store.search_ics_advisories(search,limit=limit,offset=(page_number-1)*limit)
    rows=''.join(f"<tr><td>{html.escape(row['title'])}</td><td>{html.escape(row['published'] or 'Unknown')}</td><td>{reference_links([row['link']])}</td><td>{advisory_summary(row['summary'])}</td></tr>" for row in records)
    empty='No advisories match this search. Clear the search to see stored advisories.' if search else 'No CISA ICS advisories stored. Sync public sources to load the advisory feed.'
    controls=f'''<div class="controls"><form method="get" action="/intelligence/ics"><input name="q" value="{html.escape(search,quote=True)}" placeholder="Search advisory, product or summary" aria-label="Search CISA ICS advisories"> <button>Search</button> <a href="/intelligence/ics">Clear search</a></form><form method="post" action="/sync"><button>Sync public sources</button></form>{_pager('/intelligence/ics',search,page_number,total,limit)}</div>'''
    content=controls+'<section class="panel"><table><thead><tr><th>Advisory</th><th>Published</th><th>Reference</th><th>Summary</th></tr></thead><tbody>'+(rows or '<tr><td colspan="4" class="empty">'+html.escape(empty)+'</td></tr>')+'</tbody></table></section>'
    return layout('CISA ICS advisories',content,'/intelligence/ics',lead='Cached advisory feed entries for operator review. Affected versions are not inferred from advisory text.')


def network_page(store: Store, page_number: int = 1) -> str:
    page_number = max(1, page_number)
    limit = 50
    events, total = store.recent_network_events(limit=limit, offset=(page_number - 1) * limit)
    rows = "".join(f"""<tr><td class="mono">{html.escape(row['timestamp'])}<br><small><a href="{html.escape(evidence_url(row['event_ref'],'/network?page='+str(page_number)),quote=True)}">{html.escape(row['event_ref'])}</a></small></td><td class="mono">{html.escape(row['source_ip'])}:{html.escape(str(row['source_port'] or ''))}<br>↓ {html.escape(row['destination_ip'])}:{html.escape(str(row['destination_port'] or ''))}</td><td>{html.escape(row['protocol'])} · {html.escape(row['event_type'])}<br>{html.escape(row['operation'])}</td><td>{html.escape(row['rule_ids'] or 'No active rule alert')}<br><small>{html.escape('; '.join(json.loads(row['diagnostics_json'] or '[]')))}<br>{html.escape(row['source_file'])}</small></td></tr>""" for row in events) or '<tr><td colspan="4" class="empty">No network events imported yet. Add Zeek conn.log or Modbus logs from the overview.</td></tr>'
    pager = _pager("/network", "", page_number, total, limit)
    content = f"""<div class="controls"><a class="btn" href="/">Import logs from overview</a>{pager}</div><section class="panel"><table><thead><tr><th>Timestamp / event reference</th><th>Source / destination</th><th>Protocol / operation</th><th>Detection / source file</th></tr></thead><tbody>{rows}</tbody></table></section>"""
    return layout("Network events", content, "/network", lead="Stored Zeek observations. This view does not capture live traffic or send packets to devices.", heading="Passive network monitoring")


def attack_surface_page(store: Store, query=None) -> str:
    query=query or {}
    params=surface_query(query)
    filter_keys={'subnet','zone','criticality','management_status','since','until','node'}
    filters={k:v for k,v in params.items() if k in filter_keys}
    active_filters={k:v for k,v in filters.items() if v}
    data=store.attack_surface(filters)
    try: surface_page_number=max(1,int(params.get('page','1')))
    except ValueError: surface_page_number=1
    total_nodes=len(data['nodes'])
    surface_page_number=min(surface_page_number,max(1,(total_nodes+99)//100))
    params['page']=str(surface_page_number)
    visible_nodes=data['nodes'][(surface_page_number-1)*100:surface_page_number*100]
    esc=lambda value:html.escape(str(value),quote=True)

    def timestamp(value):
        if not value:return 'Not available in this view'
        text=str(value)
        if 'T' not in text:return esc(text)
        return '<time datetime="'+esc(text)+'" title="'+esc(text)+'">'+esc(text[:10]+' '+text[11:19]+' UTC')+'</time>'

    def asset_link(node,label=None):
        return '<a href="'+esc(surface_url(params,selected=node['ip_address']))+'">'+esc(label or node['ip_address'])+'</a>'

    nodes=''.join('<tr><td class="nw mono">'+asset_link(n)+'</td><td>'+esc(n['identity'])
                  +'<br><small>'+esc(n['asset_type'])+' · '+esc(' '.join(str(n[k]) for k in ('vendor','product','version')))
                  +'</small></td><td>'+esc(n['zone'])+' zone · '+esc(n['criticality'])+' criticality<br>'
                  +esc(n['identity_confidence'])+' confidence · '+('verified' if n['verified'] else 'unverified')
                  +'<br><small>'+esc(n['visibility'])+'</small></td><td>'+timestamp(n['last_seen'])+'</td></tr>'
                  for n in visible_nodes)
    assets_table=('<section class="panel"><table><thead><tr><th scope="col">Address</th><th scope="col">Identity and product</th>'
                  '<th scope="col">Zone / criticality / confidence / visibility</th><th scope="col">Inventory last seen</th>'
                  '</tr></thead><tbody>'+nodes+'</tbody></table></section>') if nodes else (
                  '<p class="empty">'+('No endpoints match these surface filters. Widen or clear the filters.' if active_filters
                                        else 'No inventory assets or imported network observations yet. Import inventory or Zeek logs to begin.')+'</p>')
    edges=[]
    for row in data['edges']:
        return_to=surface_url(params)
        source=esc(row['source_identity'])+' ('+esc(row['source_ip'])+')'
        destination=esc(row['destination_identity'])+' ('+esc(row['destination_ip'])+')'
        metadata=esc(row['protocol'] or 'unknown')+' · '+esc(row['event_type'])
        if row['operation']:
            names={'1':'Read coils','2':'Read discrete inputs','3':'Read holding registers','4':'Read input registers','5':'Write single coil','6':'Write single register','15':'Write multiple coils','16':'Write multiple registers'}
            operation=str(row['operation'])
            metadata+=' · '+esc(names.get(operation,'Modbus function')+' ('+operation+')' if row['event_type']=='modbus' else operation)
        source_name=str(row['source_file'] or 'Source unavailable').replace('\\','/').rsplit('/',1)[-1]
        source_label=source_name if len(source_name)<=60 else source_name[:57]+'…'
        evidence='<small>'+esc(source_label)+'</small><br><a href="'+esc(evidence_url(row['sample_event_ref'],return_to))+'">Inspect evidence</a>'
        evidence+='<details class="raw-record"><summary>Event reference and source</summary><p class="mono">'+esc(row['sample_event_ref'])+'</p><p>'+esc(row['source_file'] or 'Source unavailable')+'</p></details>'
        edges.append('<tr><td>'+source+' → '+destination+'</td><td>'+esc(row['source_port'] if row['source_port'] is not None else 'unknown')
                     +' → '+esc(row['destination_port'] if row['destination_port'] is not None else 'unknown')+'</td><td>'+metadata
                     +'</td><td>'+timestamp(row['first_seen'])+'<br>to '+timestamp(row['last_seen'])+'<br><small>'
                     +esc(row['event_count'])+' event(s)</small><br>'+evidence+'</td></tr>')
    communication=('<section class="panel"><table><thead><tr><th scope="col">Relationship</th><th scope="col">Observed ports</th>'
                   '<th scope="col">Protocol / operation</th><th scope="col">Time / evidence</th></tr></thead><tbody>'
                   +''.join(edges)+'</tbody></table></section>') if edges else (
                   '<p class="empty">'+('No communication relationships match these filters. Widen or clear the filters; missing traffic does not establish absence.'
                                         if active_filters else 'No communication relationships have been observed in imported logs. Import Zeek logs to add communication evidence.')+'</p>')
    inventory_only=[n for n in visible_nodes if not n.get('ever_observed',n['observed'])]
    inventory_count=sum(not n.get('ever_observed',n['observed']) for n in data['nodes'])
    inventory_table=table(inventory_only,[('ip_address','Address'),('identity','Identity'),('zone','Zone'),('visibility','Visibility')],
                          actions=lambda n:asset_link(n,'Inspect asset')) if inventory_only else (
                          '<p class="empty">'+('No inventory-only assets on this page.' if inventory_count else 'No inventory assets without imported traffic in this view.')+'</p>')

    keep=''.join('<input type="hidden" name="'+esc(k)+'" value="'+esc(v)+'">' for k,v in params.items()
                 if k in {'q','selected','zoom','processes'})
    controls='<details class="workflow"><summary>Filter observed surface'+(' · '+str(len(active_filters))+' active' if active_filters else '')+'</summary><form method="get" action="/attack-surface#topology">'+keep
    controls+='<fieldset><legend>Asset scope</legend><div class="form-grid">'+field('subnet','Subnet CIDR (optional)',filters.get('subnet',''))
    controls+=select('zone','Network zone',[(v,v or 'All zones') for v in ('','IT','OT','DMZ','unknown')],filters.get('zone',''))
    controls+=select('criticality','Asset criticality',[(v,v.title() if v else 'All criticalities') for v in ('','low','medium','high','critical','unknown')],filters.get('criticality',''))
    controls+=select('management_status','Management state',[(v,label) for v,label in (('','All management states'),('approved','Approved'),('unmanaged','Unmanaged — needs review'),('unauthorized','Unauthorized — explicitly blocked'),('needs_identity_review','Identity needs review'),('unmonitored','Not monitored'))],filters.get('management_status',''))+'</div></fieldset>'
    controls+='<fieldset><legend>Observation time</legend><div class="form-grid">'+field('since','Observed since UTC (ISO 8601)',filters.get('since',''))+field('until','Observed until UTC (ISO 8601)',filters.get('until',''))+'</div><p class="muted">UTC example: 2026-11-04T06:00:00Z. Time filters apply to observations, not inventory or confirmed process support.</p></fieldset>'
    controls+='<fieldset><legend>Communication focus</legend>'+field('node','Focus endpoint IP',filters.get('node',''))+'<p class="muted">Show communication involving this endpoint.</p></fieldset><button>Apply surface filters</button></form></details>'
    if active_filters:
        clear_params={k:v for k,v in params.items() if k not in filter_keys|{'page'}}
        controls+='<div class="active-filters">'+''.join('<span>'+esc(k.replace('_',' ').title())+': '+esc(v)+'</span>' for k,v in active_filters.items())+'<a href="'+esc(surface_url(clear_params))+'">Clear filters</a></div>'
    relationship_count=data.get('relationship_count',len(data['edges']))
    counts=str(data['event_count'])+' stored events in the selected time window, before asset and endpoint filters. Showing '+str(len(data['edges']))+' of '+str(relationship_count)+' eligible grouped communication relationships'
    if data.get('relationships_truncated'):counts+='; limited to the '+str(data['edge_limit'])+' most recent groups'
    content=controls+'<p class="muted">'+esc(counts)+'. Visibility is limited to imported logs. Unknown peers and missing metadata remain unknown. Unseen traffic is not evidence of absence. A recorded connection does not prove a firewall permits other traffic between these networks.</p>'
    content+=render_topology(store,data,query)
    content+='<details class="workflow"><summary>Inventory without observed traffic · '+str(inventory_count)+' assets</summary>'+inventory_table+'<p class="muted">This list follows the asset table page below. These assets have no imported traffic across all stored times; this does not mean a device is offline or removed.</p></details>'
    content+='<details class="workflow"><summary>Assets and peers · '+str(total_nodes)+' endpoints</summary>'+assets_table+'<p class="muted">Find asset or peer locates endpoints across this eligible inventory and peer list; it does not narrow the list.</p></details>'
    content+=pager('/attack-surface',{k:[v] for k,v in params.items()},surface_page_number,total_nodes,100)
    content+='<h2>Observed communication</h2>'+communication
    process_rows=[{**r,'relationship_type':'Operator-confirmed support'} for r in data['process_links']]
    content+='<h2>Operator-confirmed process support</h2>'+(table(process_rows,[('ip_address','Asset address'),('name','Supported process'),('relationship_type','Relationship'),('actor','Confirmed by'),('note','Evidence')]) if process_rows else '<p class="empty">No operator-confirmed process support in this view.</p>')
    content+='<p class="muted">Time filters apply to observations, not inventory or confirmed process support.</p>'
    return layout("Attack surface", content, "/attack-surface", lead="Inventory identity joined with relationships from imported Zeek logs. No discovery scans or live capture are performed here.", heading="Passive attack surface")


def remediation_page(store: Store, page_number: int = 1, *, finding_id='',submitted=None,error='',notice='') -> str:
    page_number=max(1,page_number)
    data=store.dashboard(limit=50,offset=(page_number-1)*50)
    plans = data["remediation_plans"]
    finding_id = submitted.get("finding_id", "") if submitted else finding_id
    if finding_id:
        selected=store.get_remediation_plan(finding_id)
        finding=store.finding(finding_id)
        if not selected or not finding:raise ValueError('Remediation plan not found')
        plans=[{**selected,**{k:finding[k] for k in ("cve_id","hostname","ip_address")},"finding_status":finding["status"],"priority":finding["priority"],"current_identity_confidence":finding['identity_confidence'],"current_missing_evidence":json.loads(finding['missing_evidence'])}]
    blocks = [plan_card(item, submitted if submitted and submitted.get('finding_id')==item['finding_id'] else None, error) for item in plans]
    pager=(f'<a href="/remediation?page={page_number-1}">Previous</a> ' if page_number>1 else '')
    if page_number*50 < data["plans_count"]:pager+=f'<a href="/remediation?page={page_number+1}">Next</a>'
    if finding_id:
        pager = '<p><a href="/remediation">All remediation plans</a> · <a href="/?'+urlencode({'finding_id':finding_id})+'#finding-'+html.escape(finding_id,quote=True)+'">Back to finding</a></p>'
    body = pager + "".join(blocks) or '<section class="panel empty">No remediation plans yet. <a href="/#findings">Open an exposure finding on the overview</a> to request a plan.</section>'
    if notice:body='<p class="notice success" role="status">'+html.escape(notice)+'</p>'+body
    return layout("Remediation plans", body, "/remediation", lead="Recommendations are separate from approvals, implementation, and verified outcomes. No infrastructure changes are performed by Phylax.")


class Handler(BaseHTTPRequestHandler):
    server_version = "Phylax/0.1"
    store: Store
    csrf_token = secrets.token_urlsafe(32)

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def _send(self, body: bytes, content_type: str = "text/html; charset=utf-8", status: int = 200, download: str | None = None) -> None:
        if content_type.startswith('text/html'):
            label=self.store.connection.execute("SELECT value FROM schema_meta WHERE key='dataset_label'").fetchone()
            if label:
                banner='<div class="notice">'+html.escape(label[0])+'</div>'
                body=re.sub(r'<main\b[^>]*>',lambda match:match[0]+banner,body.decode('utf-8'),count=1).encode('utf-8')
            body = protect_forms(body.decode('utf-8'),self.csrf_token).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",CSP)
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Cache-Control","no-store")
        # no-referrer makes Chromium navigation POSTs send Origin: null.
        # Keep local form origins intact while withholding external referrers.
        self.send_header("Referrer-Policy", "same-origin")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Browsers may navigate away or close a tab while a response is
            # being written. This is a normal client disconnect, not an app
            # failure, so avoid a noisy server traceback.
            return

    def _valid_request_host(self) -> bool:
        server = getattr(self,'server',None)
        port = server.server_address[1] if server else 8765
        return valid_host(self.headers.get('Host',''),port)

    def do_GET(self) -> None:
        if not self._valid_request_host():
            self._send(b'Invalid Host', 'text/plain; charset=utf-8',403)
            return
        path = urlparse(self.path).path
        if path in release_web.PAGES:
            try:self._send(release_web.page(self.store,path,parse_qs(urlparse(self.path).query)).encode())
            except ValueError as exc:self._send(str(exc).encode(),'text/plain; charset=utf-8',400)
            return
        if path == "/":
            notice = parse_qs(urlparse(self.path).query).get("notice", [""])[0]
            try: page_number=int(parse_qs(urlparse(self.path).query).get("page",["1"])[0])
            except ValueError: page_number=1
            try:self._send(page(self.store,notice,page_number,parse_qs(urlparse(self.path).query).get('finding_id',[''])[0]).encode())
            except ValueError as exc:self._send(layout('Finding unavailable','<p>'+html.escape(str(exc))+'</p><a href="/">Return to overview</a>','/').encode(),status=404)
        elif path.startswith('/jobs/'):
            job = self.server.jobs.get(path.rsplit('/',1)[-1])
            if not job:
                self._send(b'Job not found','text/plain; charset=utf-8',404)
                return
            refresh = '<meta http-equiv="refresh" content="2">' if job['status'] in {'queued','running'} else ''
            running = job['status'] in {'queued', 'running'}
            body = layout(job["label"], f'<p class="lead">{html.escape(job["message"])}</p><dl class="stats"><div><dt>Status</dt><dd>{html.escape(job["status"])}</dd></div><div><dt>Updated</dt><dd>{html.escape(str(job["updated_at"]))}</dd></div></dl>' + ('<p class="muted">This page refreshes every 2 seconds while the task is running.</p>' if running else '<p><a class="btn" href="/">Return to overview</a></p>'), "").replace("<title>", refresh + "<title>", 1)
            self._send(body.encode())
        elif path == '/assets/edit':
            try:
                asset_id=parse_qs(urlparse(self.path).query).get('asset_id',[''])[0]
                self._send(inventory_form(self.store,asset_id).encode())
            except ValueError as exc:self._send(str(exc).encode(),'text/plain; charset=utf-8',400)
        elif path == '/glossary':
            self._send(glossary_page().encode())
        elif path == '/policy':
            self._send(policy_page(self.store).encode())
        elif path == '/settings':
            self._send(settings_page(self.store).encode())
        elif path == '/reports':
            self._send(reports_page(self.store).encode())
        elif path == "/assets":
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            self._send(assets_page(self.store, query.get("q", [""])[0], page_number, identity_review=query.get("identity_review",[""])[0]=="yes").encode())
        elif path in {"/intelligence", "/intelligence/ics"}:
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            render=ics_advisories_page if path=='/intelligence/ics' else intelligence_page
            self._send(render(self.store, query.get("q", [""])[0], page_number).encode())
        elif path == "/network":
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            self._send(network_page(self.store, page_number).encode())
        elif path == "/attack-surface":
            try:self._send(attack_surface_page(self.store,parse_qs(urlparse(self.path).query)).encode())
            except ValueError as exc:self._send(str(exc).encode(),'text/plain; charset=utf-8',400)
        elif path == "/remediation":
            query=parse_qs(urlparse(self.path).query)
            try: page_number=int(query.get("page",["1"])[0])
            except ValueError: page_number=1
            try:self._send(remediation_page(self.store,page_number,finding_id=query.get("finding_id",[""])[0],notice=query.get("notice",[""])[0]).encode())
            except ValueError as exc:self._send(str(exc).encode(),'text/plain; charset=utf-8',404)
        elif path == "/assets.csv":
            from io import StringIO
            out = StringIO()
            self.store.export_assets_csv(out)
            self._send(out.getvalue().encode(), "text/csv; charset=utf-8", download="phylax-assets.csv")
        elif path == "/report.json":
            self._send(self.store.report("json").encode(), "application/json; charset=utf-8", download="phylax-report.json")
        elif path == "/report.md":
            self._send(self.store.report("markdown").encode(), "text/markdown; charset=utf-8", download="phylax-report.md")
        elif path == "/report.csv":
            self._send(self.store.report("csv").encode(), "text/csv; charset=utf-8", download="phylax-report.csv")
        else:
            self._send(b"Not found", "text/plain; charset=utf-8", 404)

    def do_POST(self) -> None:
        try:
            if not self._valid_request_host():
                self._send(b'Invalid Host', 'text/plain; charset=utf-8',403)
                return
            origin = self.headers.get('Origin')
            if origin and not valid_origin(origin,self.headers['Host'],self.server.server_address[1]):
                message=('Cross-origin request denied. Open http://'+self.headers['Host']
                         +'/ directly in a regular browser tab, reload the dashboard, and retry. '
                         'The request Origin must match the dashboard host and port; embedded pages and opaque origins are not accepted.')
                self._send(message.encode(),'text/plain; charset=utf-8',403)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_UPLOAD + 64_000:
                raise ValueError("Request is too large")
            raw = self.rfile.read(length)
            if not valid_token(form_token(raw,self.headers.get('Content-Type','')),self.csrf_token):
                self._send(b'Invalid or expired form token. Reload the dashboard and retry.','text/plain; charset=utf-8',403)
                return
            path = urlparse(self.path).path
            if path in release_web.ACTIONS:
                values=parse_qs(raw.decode('utf-8','strict'),keep_blank_values=True)
                try:destination=release_web.post(self.store,path,values)
                except (ValueError,RuntimeError) as exc:
                    self._send(release_web.error_page(self.store,path,values,str(exc)).encode(),status=400)
                    return
                self.send_response(303);self.send_header('Location',destination);self.end_headers();return
            if path == "/correlate":
                result = self.store.correlate()
                notice = f"Correlation complete: {result or 'no matching records'}"
            elif path == "/sync":
                def sync_work(store, update):
                    result = sync_store(store,progress=lambda source,stage,message:update(f'{source} · {stage}: {message}'))
                    return 'Source sync results: ' + '; '.join(f"{name}: {'ok' if item['ok'] else item['error']}" for name,item in result.items())
                job_id = self.server.jobs.submit('Sync public sources',sync_work)
                self.send_response(303);self.send_header('Location','/jobs/'+job_id);self.end_headers()
                return
            elif path == "/remediation/create":
                form = parse_qs(raw.decode("utf-8", "replace"))
                finding_id = form.get("finding_id", [""])[0]
                if self.store.finding(finding_id) is None:
                    raise ValueError('Finding not found')
                job_id = self.server.jobs.submit('Generate remediation '+finding_id,lambda store,update:generate_plan(store,finding_id))
                self.send_response(303);self.send_header('Location','/jobs/'+job_id);self.end_headers()
                return
            elif path == '/assets/save':
                import csv
                from io import StringIO
                form=parse_qs(raw.decode('utf-8','strict'),keep_blank_values=True)
                buffer=StringIO();writer=csv.DictWriter(buffer,fieldnames=ASSET_FIELDS);writer.writeheader()
                writer.writerow({name:form.get(name,[''])[0] for name in ASSET_FIELDS})
                buffer.seek(0);result=self.store.import_csv(buffer)
                if result['errors']:raise ValueError(result['errors'][0]['error'])
                notice='Inventory saved; affected findings reassessed.'
            elif path == '/policy/apply':
                form=parse_qs(raw.decode('utf-8','strict'))
                policy=validate_policy(read_json_limited(form.get('policy_json',[''])[0].encode(),max_bytes=100000))
                job_id=self.server.jobs.submit('Reevaluate passive network policy',lambda store,update:str(reevaluate_events(store,policy)))
                self.send_response(303);self.send_header('Location','/jobs/'+job_id);self.end_headers()
                return
            elif path == "/remediation/update":
                form = parse_qs(raw.decode("utf-8", "replace"))
                finding_id = form.get("finding_id", [""])[0]
                self.store.update_remediation_plan(finding_id, form.get("status", [""])[0], reviewer=form.get("reviewer", [""])[0][:120], change_notes=form.get("change_notes", [""])[0][:2000], verification_evidence=form.get("verification_evidence", [""])[0][:4000])
                notice = "Remediation lifecycle updated and recorded. Finding applicability and risk are unchanged."
            elif path in {"/assets/import", "/intelligence/import", "/network/import"}:
                boundary = self.headers.get("Content-Type", "").split("boundary=", 1)[-1].strip('"')
                if not boundary or not raw.startswith(("--" + boundary).encode()):
                    raise ValueError("Expected a multipart file upload")
                parts = raw.split(("--" + boundary).encode())
                upload_parts = [p for p in parts if b"Content-Disposition" in p and b"\r\n\r\n" in p]
                part = next((p for p in upload_parts if b'name="file"' in p), b"")
                if not part:
                    raise ValueError("Uploaded file is missing")
                body = part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]
                if len(body) > MAX_UPLOAD:
                    raise ValueError("File is too large")
                if path == "/assets/import":
                    import io
                    result = self.store.import_csv(io.StringIO(body.decode("utf-8-sig")))
                    notice = f"Imported {result['imported']} asset rows; {len(result['errors'])} row errors. " + "; ".join(f"row {e['row']}: {e['error']}" for e in result["errors"][:5])
                elif path == "/intelligence/import":
                    result = self.store.ingest_fixture(read_json_limited(body))
                    notice = f"Loaded {len(result['ingested'])} locally stored vulnerability record(s)."
                else:
                    import tempfile
                    policy_part = next((p for p in upload_parts if b'name="policy"' in p), b"")
                    policy = None
                    if policy_part:
                        policy_body = policy_part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]
                        policy = validate_policy(read_json_limited(policy_body, max_bytes=100_000))
                    disposition = part.split(b"\r\n", 1)[0].decode("utf-8", "replace")
                    match = re.search(r'filename="([^"]{1,255})"', disposition)
                    original_name = match.group(1).replace("\\", "/").split("/")[-1] if match else "conn.log"
                    suffix = ".json" if original_name.casefold().endswith(".json") else ".log"
                    with tempfile.NamedTemporaryFile(prefix="phylax-zeek-", suffix=suffix) as tmp:
                        tmp.write(body)
                        tmp.flush()
                        kind=next((k for k in ('modbus','dhcp','software') if k in original_name.casefold()),'conn')
                        result = ingest_file(self.store, tmp.name, kind=kind, policy=policy, source_file=original_name)
                    notice = f"Network analysis: {result['events_inserted']} events, {result['alerts_created']} alerts, {result['duplicates_skipped']} duplicates. " + "; ".join(result["diagnostics"][:3])
            else:
                self._send(b"Not found", "text/plain; charset=utf-8", 404)
                return
            self.send_response(303)
            destination = "/remediation?"+urlencode({'finding_id':finding_id,'notice':notice}) if path == '/remediation/update' else "/?"+urlencode({'notice':notice})
            self.send_header("Location", destination)
            self.end_headers()
        except (ValueError, UnicodeDecodeError, RuntimeError, TimeoutError, RecursionError) as exc:
            path=urlparse(self.path).path
            values=parse_qs(raw.decode('utf-8','replace'),keep_blank_values=True) if 'raw' in locals() else {}
            submitted={k:v[0] for k,v in values.items() if v and k!='csrf_token'}
            if path=='/assets/save':
                body=inventory_form(self.store,submitted.get('asset_id',''),submitted=submitted,error=str(exc))
            elif path=='/policy/apply':body=policy_page(self.store,submitted=submitted,error=str(exc))
            elif path=='/remediation/update' and self.store.get_remediation_plan(submitted.get('finding_id','')):
                body=remediation_page(self.store,submitted=submitted,error=str(exc))
            else:body=page(self.store,f"Input error: {exc}")
            self._send(body.encode(),status=400)

    def log_message(self, fmt: str, *args: object) -> None:
        # Keep the local console useful without logging request payloads or uploaded filenames.
        super().log_message(fmt, *args)


def serve(database: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Dashboard binds to loopback only")
    store = Store(database)
    Handler.store = store
    # SQLite connection is intentionally confined to this single request thread.
    class LocalHTTPServer(HTTPServer):
        address_family=socket.AF_INET6 if host=="::1" else socket.AF_INET
    server = LocalHTTPServer(("127.0.0.1" if host=="localhost" else host, port), Handler)
    server.jobs = Jobs(database)
    Handler.csrf_token = secrets.token_urlsafe(32)
    print(f"Phylax dashboard: http://{host}:{port} (local-only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping Phylax dashboard")
    finally:
        server.server_close()
        server.jobs.close()
        store.close()
