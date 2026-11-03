"""Small local-only operator dashboard built on Python's standard library."""

from __future__ import annotations

import html
import json
import re
import secrets
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from .ai import AIConfig
from .core import Store, read_json_limited, ASSET_FIELDS
from .web_security import CSP, valid_host, valid_origin, valid_token, form_token, protect_forms
from .prioritization import prioritize
from .jobs import Jobs
from .remediation_service import generate_plan
from .operator_pages import inventory_form,policy_page,settings_page,reports_page
from .theme import layout, ring, status_marker, term, glossary_page
from .feeds import sync_store
from .monitoring import ingest_file, validate_policy, reevaluate_events
from .remediation import HostedModelProvider, TemplateFallbackProvider, compose_plan


MAX_UPLOAD = 5_000_000


def evidence_html(items) -> str:
    """Short evidence lines inline; long machine-readable ones collapsed."""
    out = []
    for item in items:
        if len(item) > 120 or item.startswith("Matched source condition:"):
            label, _, rest = item.partition(": ")
            out.append(f'<details><summary>{html.escape(label)}</summary><code class="block">{html.escape(rest)}</code></details>')
        else:
            out.append(f"<div>{html.escape(item)}</div>")
    return "".join(out)


def page(store: Store, notice: str = "", page_number: int = 1) -> str:
    page_number = max(1,page_number)
    data = store.dashboard(limit=50,offset=(page_number-1)*50)
    cards = [("Devices in inventory", data["assets"], ""), ("Devices to identify", data["assets_needing_identity_review"], "Identity review"), ("Confirmed affected", data["confirmed_assets"], "Confirmed affected"), ("Possibly affected", data["potential_assets"], "Possibly affected"), ("Known-exploited flaws", data["kev_findings"], "KEV"), ("Critical devices at risk", data["critical_exposed_assets"], ""), ("Network connections seen", data["communication_relationships"], ""), ("New alerts", data["unacknowledged_alerts"], ""), ("Out-of-date data feeds", data["stale_sources"], "")]
    rows = []
    for f in data["findings"]:
        evidence = evidence_html(json.loads(f["evidence"]))
        missing = "<br>".join(html.escape(x) for x in json.loads(f["missing_evidence"])) or "None recorded"
        references = ", ".join(json.loads(f["references_json"])) or "No references supplied"
        urgency = prioritize(f,f,f["status"])
        priority_detail = "; ".join(f"{x['input']}: {x['value']} (+{x['points']})" for x in urgency["factors"])
        assessment_confidence = {"CONFIRMED_MATCH": "high", "NO_MATCH_TO_THIS_ADVISORY": "high", "POTENTIAL_MATCH": "medium", "NEEDS_REVIEW": "low"}.get(f["status"], "unknown")
        plan_data = store.get_remediation_plan(f["finding_id"])
        plan_html = ""
        if plan_data:
            p = plan_data["plan"]
            sections = ["finding_summary", "priority_explanation", "preferred_remediation", "operational_impact", "vendor_guidance_status"]
            if p.get("cisa_required_action"):sections.append("cisa_required_action")
            detail_html = "".join(f"<p><b>{html.escape(label.replace('_', ' ').title())}:</b> {html.escape(str(p[key]))}</p>" for key, label in ((key, key) for key in sections))
            detail_html += f"<p><b>Confidence and unresolved questions:</b> {html.escape(json.dumps(p['confidence_and_questions'], ensure_ascii=False))}</p><p><b>Human approval required:</b> {'Yes' if p['human_approval_required'] else 'No'}</p><p><b>Plan source:</b> {html.escape(p.get('provider_note', plan_data['provider']))}</p>"
            list_sections = ("preconditions", "alternative_controls", "validation_steps", "rollback_considerations", "post_remediation_verification", "source_references")
            for key in list_sections:
                detail_html += f"<b>{html.escape(key.replace('_', ' ').title())}</b><ul>" + "".join(f"<li>{html.escape(str(value))}</li>" for value in p.get(key, [])) + "</ul>"
            if p.get("ai_summary"):
                detail_html += f"<div class=notice>AI-generated, unverified public-advisory supplement ({html.escape(plan_data['model'])}): {html.escape(p['ai_summary'])}<br>" + "<br>".join(html.escape(x) for x in p.get("ai_steps", [])) + f"<br>{html.escape(p.get('ai_validation', ''))}<br>Cited URLs: {html.escape('; '.join(p.get('ai_source_references',[])))}</div>"
            statuses = ["Recommended", "Under Review", "Approved", "Implemented", "Verified", "Rejected", "Deferred", "Needs More Evidence"]
            options = "".join(f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in statuses if s != plan_data["status"])
            detail_html += f'<b>Lifecycle: {html.escape(plan_data["status"])}</b> · Updated {html.escape(plan_data["updated_at"])}<form method="post" action="/remediation/update"><input type="hidden" name="finding_id" value="{html.escape(f["finding_id"], quote=True)}"><select name="status">{options}</select><input name="reviewer" maxlength="120" placeholder="Reviewer (required for approval)"><input name="change_notes" maxlength="2000" placeholder="Change or review notes"><input name="verification_evidence" maxlength="4000" placeholder="Verification evidence (required for Verified)"><button>Update plan</button></form>'
            plan_html = f'<details><summary>Remediation plan · {html.escape(plan_data["status"])}</summary>{detail_html}</details>'
        plan_action = f'<form method="post" action="/remediation/create"><input type="hidden" name="finding_id" value="{html.escape(f["finding_id"], quote=True)}"><button>Generate remediation plan</button></form>'
        rows.append(f"""<tr><td><b class="mono">{html.escape(f['cve_id'])}</b><br>{'DEMO FIXTURE' if f['synthetic'] else html.escape(f['source'])}<br><small>Published {html.escape(f['published'] or 'Unknown')} · modified {html.escape(f['modified'] or 'Unknown')}<br>{html.escape(references)}</small></td>
          <td><span class="mono">{html.escape(f['ip_address'])}</span> {html.escape(f['hostname'])}<br>{html.escape(f['vendor'])} {html.escape(f['product'])} {html.escape(f['version'])}<br><small>{html.escape(f['criticality'])} criticality · identity {html.escape(f['identity_confidence'])} · {html.escape(f['zone'])} zone</small></td>
          <td>{status_marker(f['status'])}<br><b>Urgency {urgency['score'] if urgency['score'] is not None else 'n/a'} of 12</b> · {html.escape(f['priority'])}<br>{html.escape(f['severity'] or 'Unknown')} severity · {'known to be exploited' if f['kev'] else 'no known exploitation'}<details><summary>Why this score</summary><small>{html.escape(priority_detail)}<br>Match confidence: {assessment_confidence}</small></details></td>
          <td>{evidence}<br><small>Missing: {missing}</small></td>
          <td>{html.escape(f['summary'])}<br><small>{html.escape(f['mitigation'] or 'No verified vendor guidance supplied.')}</small><br>{plan_action}{plan_html}</td></tr>""")
    finding_table = "".join(rows) or '<tr><td colspan="5" class="empty">No findings yet. Import assets and load a local fixture to begin.</td></tr>'
    alerts = []
    for a in data["alerts"]:
        button = "Acknowledged" if a["acknowledged"] else f'<form method="post" action="/ack"><input type="hidden" name="alert_id" value="{html.escape(a["alert_id"])}"><button>Acknowledge</button></form>'
        simulation_label = "SYNTHETIC TEST EVENT · " if "synthetic" in a.get("source_file", "").casefold() else ""
        observed_asset = f" · asset {html.escape(a['destination_hostname'] or a['destination_asset_id'])}" if a.get("destination_asset_id") else ""
        evidence = f"<br><small>Rule: {html.escape(a['rule_id'])} · Event: {html.escape(a['event_ref'])} · {html.escape(a['source_ip'])} → {html.escape(a['destination_ip'])}{observed_asset} · {html.escape(a['event_timestamp'])}<br>Policy evidence: {html.escape(a['policy_evidence'])}</small>" if a.get("rule_id") else ""
        alerts.append(f'<div class="alert"><div><b>{simulation_label}{html.escape(a["severity"])} · {html.escape(a["alert_id"][:8])}</b><p>{html.escape(a["explanation"])}</p>{evidence}<small>{html.escape(a["created_at"])}</small></div>{button}</div>')
    alert_html = "".join(alerts) or '<p class="empty">No evidence-backed exposure alerts.</p>'
    health_html = "".join(f'<div class="alert"><div><b>{html.escape(source["source"])} · {html.escape(source["health"])}</b><br><small>Last success: {html.escape(source["last_success_at"] or "Never")} · {html.escape(source["message"])}</small></div></div>' for source in data["source_health"]) or '<p class="empty">No synchronization yet. Stored offline data remains available.</p>'
    updates_html = "".join(f'<div class="alert"><div><b>{html.escape(item["change_type"])} · {html.escape(item["cve_id"])}</b><br><small>{html.escape(item["source"])} · {html.escape(item["changed_at"])}<br>{html.escape(item["summary"])}</small></div></div>' for item in data["recent_intelligence"]) or '<p class="empty">No intelligence records stored yet.</p>'
    identity_names = ", ".join(html.escape(asset["hostname"] or asset["asset_id"]) for asset in data["identity_review_assets"][:8])
    identity_review_html = f'<p class="notice">{data["assets_needing_identity_review"]} device(s) cannot be checked for known flaws yet because their make, model or version is not confirmed ({identity_names}). Phylax does not guess these from an IP address. <a href="/assets">Open inventory to fill them in</a>.</p>' if data["identity_review_assets"] else ""
    largest = max(data['findings_count'],data['exposure_alerts_count'],data['network_alerts_count'],data['assets_needing_identity_review'])
    pager = (f'<a class="link" href="/?page={page_number-1}">Previous</a>' if page_number>1 else '')
    if page_number>1 or page_number*50 < largest:
        pager += f' <span class="muted">Page {page_number}</span> '
    if page_number*50 < largest:pager += f'<a class="link" href="/?page={page_number+1}">Next</a>'
    pager = f'<div class="controls">{pager}</div>' if pager.strip() else ''
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    hot = {"Confirmed affected", "Known-exploited flaws", "Critical devices at risk", "New alerts"}
    stats_html = "".join(f'<div class="{"hot" if label in hot and value else ""}"><dt>{term(tip, label) if tip else html.escape(label)}</dt><dd>{value}</dd></div>' for label, value, tip in cards)
    scored = []
    for f in data["findings"]:
        u = prioritize(f, f, f["status"])
        if u["score"] is not None:
            scored.append((u["score"], u["priority"], f))
    scored.sort(key=lambda t: -t[0])
    tone = {"critical": "crit", "high": "high", "medium": "info"}
    focus_cards = "".join(
        f'<a class="card" href="#findings">{ring(score, 12, str(score), tone.get(priority, "none"))}<div><b>{html.escape(f["cve_id"])}</b>'
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
        headline = f"None of your {total_assets} devices match a known flaw yet.<small>Run steps 2 and 4 below to check against the latest information.</small>"
    focus_html = f'<p class="headline">{headline}</p><h2>Top priorities</h2><div class="focus">{focus_cards}</div>'
    content = f"""{notice_html}{pager}{identity_review_html}
<dl class="stats">{stats_html}</dl>
{focus_html}
<ol class="steps">
<li><b>1 · Inventory</b><form method="post" action="/assets/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".csv,text/csv" aria-label="Asset CSV"><button>Import asset CSV</button></form><a class="link" href="/assets/edit">Add asset manually</a><a class="link" href="/assets">View inventory</a></li>
<li><b>2 · Public intelligence</b><form method="post" action="/sync"><button>Sync public sources</button></form><form method="post" action="/intelligence/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".json,application/json" aria-label="Offline fixture"><button>Load offline fixture</button></form></li>
<li><b>3 · Passive network</b><form method="post" action="/network/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".log,.json,.tsv,text/plain" aria-label="Zeek log"><input name="policy" type="file" accept=".json,application/json" aria-label="Optional policy JSON"><button>Analyze Zeek log</button></form></li>
<li><b>4 · Assess</b><form method="post" action="/correlate"><button class="primary">Run correlation</button></form><span class="muted">Re-run after any change to steps 1-3.</span></li>
</ol>
<div class="split"><div><h2 id="findings">Exposure findings</h2><section class="panel"><table class="findings"><thead><tr><th>Vulnerability</th><th>Device</th><th>Risk</th><th>Why we think so</th><th>What it is and what to do</th></tr></thead><tbody>{finding_table}</tbody></table></section></div>
<div><h2>Security alerts · {data["network_events"]} network events</h2><section class="panel">{alert_html}</section><h2>Intelligence sources</h2><section class="panel">{health_html}</section><h2>Recent intelligence updates</h2><section class="panel">{updates_html}</section></div></div>
<footer>Urgency is a transparent rule-based priority; severity and applicability remain separate. KEV indicates catalog-listed exploitation, not an attack on this asset. Absence of a finding does not mean an asset is safe. Timestamps are stored in UTC. Exports are on the <a href="/reports">Reports</a> page.</footer>"""
    return layout("Overview", content, "/", lead="Local inventory and stored intelligence. No active scanning or device control.", heading="Security overview")


def assets_page(store: Store, search: str = "", page_number: int = 1) -> str:
    page_number = max(1, page_number)
    limit = 50
    rows, total = store.search_assets(search, limit=limit, offset=(page_number - 1) * limit)
    body = "".join(f"""<tr><td class="nw mono">{html.escape(row['ip_address'])}<br><small>ID {html.escape(row['asset_id'])} · {html.escape(row['mac_address'] or 'MAC unknown')}</small><br><a href="/assets/edit?{urlencode({'asset_id':row['asset_id']})}">Edit</a></td><td>{html.escape(row['hostname'] or 'Unknown')}</td>
      <td>{html.escape(row['asset_type'])}<br><small>{html.escape(row['vendor'])} {html.escape(row['product'])} {html.escape(row['version'])}<br>{html.escape(row['operating_system'])}</small></td>
      <td>{html.escape(row['zone'])}<br>{html.escape(row['criticality'])}</td><td>{html.escape(row['identification_source'])}<br><small>{html.escape(row['identity_confidence'])} confidence · {'verified' if row['verified'] else 'unverified'}</small></td><td>{html.escape(row['last_seen'] or 'Unknown')}<br><small>{html.escape(row['notes'])}</small></td></tr>""" for row in rows) or '<tr><td colspan="6" class="empty">No assets found. Import a CSV from the overview.</td></tr>'
    query = urlencode({"q": search})
    previous = f'<a class="link" href="/assets?{query}&page={page_number - 1}">Previous</a>' if page_number > 1 else ""
    next_link = f'<a class="link" href="/assets?{query}&page={page_number + 1}">Next</a>' if page_number * limit < total else ""
    content = f"""<div class="controls"><form method="get" action="/assets"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search IP, hostname, vendor, product" aria-label="Search assets"> <button>Search</button></form><a class="btn primary" href="/assets/edit">Add asset</a><a class="btn" href="/assets.csv">Export CSV</a><span class="muted">{total} assets · page {page_number}</span>{previous}{next_link}</div>
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
    records, total, advisories = store.search_intelligence(search, limit=limit, offset=(page_number - 1) * limit)
    rows = []
    for item in records:
        affected = json.loads(item["affected_products"])
        product_text = "; ".join(f"{p['vendor']} {p['product']} [{', '.join(p.get('versions', [])) or 'versions unspecified'}]" for p in affected) or "Affected product data not provided"
        refs = json.loads(item.get("references_json", "[]"))
        rows.append(f"""<tr><td><b class="mono">{html.escape(item['cve_id'])}</b><br><small>{html.escape(item['source'])}</small></td>
        <td>{html.escape(item['severity'] or 'Unknown')} {('· CVSS ' + html.escape(str(item['cvss']))) if item['cvss'] is not None else ''}<br>KEV {'Yes' if item['kev'] else 'No'}<br><small>Published {html.escape(item['published'] or 'Unknown')}<br>Modified {html.escape(item['modified'] or 'Unknown')}<br>Retrieved {html.escape(item['retrieved_at'])}</small></td>
        <td>{html.escape(item['summary'])}<br><small>{html.escape(product_text)}</small></td><td>{html.escape(item['mitigation'] or 'No mitigation guidance supplied.')}<br><small>{html.escape('; '.join(refs) or item['source_url'] or 'No reference supplied')}</small></td></tr>""")
    advisory_rows = "".join(f"<tr><td>{html.escape(row['title'])}</td><td>{html.escape(row['published'] or 'Unknown')}</td><td>{html.escape(row['link'])}</td><td>{html.escape(row['summary'])}</td></tr>" for row in advisories) or '<tr><td colspan="4" class="empty">No CISA ICS advisories stored.</td></tr>'
    pager = _pager("/intelligence", search, page_number, total, limit)
    content = f"""<div class="controls"><form method="get" action="/intelligence"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search CVE, summary, source" aria-label="Search intelligence"> <button>Search</button></form><form method="post" action="/sync"><button>Sync public sources</button></form>{pager}</div>
<section class="panel"><table><thead><tr><th>Identifier / source</th><th>Severity / status / dates</th><th>Summary / affected product data</th><th>Mitigation / references</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="4" class="empty">No intelligence records found. Sync sources or load the offline fixture.</td></tr>'}</tbody></table></section>
<h2>CISA ICS advisories</h2><p class="muted">Feed entries and references are retained for operator review; affected versions are not inferred from advisory text.</p><section class="panel"><table><thead><tr><th>Advisory</th><th>Published</th><th>Reference</th><th>Summary</th></tr></thead><tbody>{advisory_rows}</tbody></table></section>"""
    return layout("Intelligence", content, "/intelligence", lead="Normalized records are cached locally. Product/version applicability remains subject to source evidence and the documented matcher limits.", heading="Threat intelligence")


def network_page(store: Store, page_number: int = 1) -> str:
    page_number = max(1, page_number)
    limit = 50
    events, total = store.recent_network_events(limit=limit, offset=(page_number - 1) * limit)
    rows = "".join(f"""<tr><td class="mono">{html.escape(row['timestamp'])}<br><small>{html.escape(row['event_ref'])}</small></td><td class="mono">{html.escape(row['source_ip'])}:{html.escape(str(row['source_port'] or ''))}<br>↓ {html.escape(row['destination_ip'])}:{html.escape(str(row['destination_port'] or ''))}</td><td>{html.escape(row['protocol'])} · {html.escape(row['event_type'])}<br>{html.escape(row['operation'])}</td><td>{html.escape(row['rule_ids'] or 'No active rule alert')}<br><small>{html.escape('; '.join(json.loads(row['diagnostics_json'] or '[]')))}<br>{html.escape(row['source_file'])}</small></td></tr>""" for row in events) or '<tr><td colspan="4" class="empty">No network events imported yet. Add Zeek conn.log or Modbus logs from the overview.</td></tr>'
    pager = _pager("/network", "", page_number, total, limit)
    content = f"""<div class="controls"><a class="btn" href="/">Import logs from overview</a>{pager}</div><section class="panel"><table><thead><tr><th>Timestamp / event reference</th><th>Source / destination</th><th>Protocol / operation</th><th>Detection / source file</th></tr></thead><tbody>{rows}</tbody></table></section>"""
    return layout("Network events", content, "/network", lead="Stored Zeek observations. This view does not capture live traffic or send packets to devices.", heading="Passive network monitoring")


def attack_surface_page(store: Store) -> str:
    data = store.attack_surface()
    nodes = "".join(f"<tr><td class='nw mono'>{html.escape(n['ip_address'])}</td><td>{html.escape(n['identity'])}<br><small>{html.escape(n['asset_type'])} · {html.escape(n['vendor'])} {html.escape(n['product'])} {html.escape(n['version'])}</small></td><td>{html.escape(n['zone'])} zone · {html.escape(n['criticality'])} criticality<br>{html.escape(n['identity_confidence'])} confidence · {'verified' if n['verified'] else 'unverified'}<br><small>{html.escape(n['visibility'])}</small></td><td>{html.escape(n['last_seen'] or 'Not available')}</td></tr>" for n in data['nodes']) or '<tr><td colspan="4" class="empty">No inventory assets or imported network observations yet.</td></tr>'
    edges = "".join(f"<tr><td>{html.escape(e['source_identity'])} ({html.escape(e['source_ip'])}) → {html.escape(e['destination_identity'])} ({html.escape(e['destination_ip'])})</td><td>{html.escape(str(e['source_port'] or 'unknown'))} → {html.escape(str(e['destination_port'] or 'unknown'))}</td><td>{html.escape(e['protocol'] or 'unknown')} · {html.escape(e['event_type'])}{(' · ' + html.escape(e['operation'])) if e['operation'] else ''}</td><td>{html.escape(e['first_seen'])} → {html.escape(e['last_seen'])}<br><small>{e['event_count']} event(s) · event {html.escape(e['sample_event_ref'])} · {html.escape(e['source_file'] or 'source unavailable')}</small></td></tr>" for e in data['edges']) or '<tr><td colspan="4" class="empty">No communication relationships have been observed in imported logs.</td></tr>'
    graph_nodes = data["nodes"][:24]
    position = {node["ip_address"]: (100 + (index % 4) * 220, 70 + (index // 4) * 100) for index, node in enumerate(graph_nodes)}
    graph_edges = []
    for edge in data["edges"]:
        if edge["source_ip"] in position and edge["destination_ip"] in position:
            x1, y1 = position[edge["source_ip"]]
            x2, y2 = position[edge["destination_ip"]]
            graph_edges.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#5b626b" stroke-width="2"><title>Observed {html.escape(edge["protocol"] or "unknown")} flow · {html.escape(edge["first_seen"])} · event {html.escape(edge["sample_event_ref"])}</title></line>')
    graph_items = []
    zone_colors = {"IT": "#58a272", "OT": "#d98a2b", "DMZ": "#7ba3d9", "unknown": "#868d96"}
    for node in graph_nodes:
        x, y = position[node["ip_address"]]
        color = zone_colors.get(node["zone"], zone_colors["unknown"])
        identity = html.escape((node["identity"] or "Unknown")[:24])
        graph_items.append(f'<g><circle cx="{x}" cy="{y}" r="25" fill="#1a1c1f" stroke="{color}" stroke-width="3"><title>{html.escape(node["identity"])} · {html.escape(node["zone"])} zone · {html.escape(node["criticality"])} criticality · {html.escape(node["identity_confidence"])} confidence</title></circle><text x="{x}" y="{y + 44}" text-anchor="middle" fill="#d8dbe0" font-size="12">{identity}</text><text x="{x}" y="{y + 59}" text-anchor="middle" fill="#868d96" font-size="10">{html.escape(node["ip_address"])}</text></g>')
    graph = f'<svg viewBox="0 0 900 {max(180, 100 + ((len(graph_nodes) + 3) // 4) * 100)}" role="img" aria-label="Observed communication graph">{"".join(graph_edges)}{"".join(graph_items)}</svg>' if graph_nodes else '<p class="empty">No inventory assets or observed peers to map.</p>'
    content = f"""<div class="notice">Observed surface is limited to imported logs ({data['event_count']} stored events; at most {data['edge_limit']} grouped relationships shown). Unknown peers and missing metadata remain unknown. Unseen traffic is not evidence of absence. A recorded connection does not prove a firewall permits other traffic between these networks.</div><h2>Topology overview</h2><section class="panel">{graph}<p class="legend">Circle colors: IT green · OT amber · DMZ blue · unknown gray. Lines represent observed events only. Showing at most 24 nodes and {data['edge_limit']} grouped relationships. Zone membership comes from inventory; no trust boundaries are inferred.</p></section><h2>Assets and peers</h2><section class="panel"><table><thead><tr><th>Address</th><th>Identity and product</th><th>Zone / criticality / confidence / visibility</th><th>Inventory last seen</th></tr></thead><tbody>{nodes}</tbody></table></section><h2>Observed communication</h2><section class="panel"><table><thead><tr><th>Relationship</th><th>Observed ports</th><th>Protocol / operation</th><th>Time / evidence</th></tr></thead><tbody>{edges}</tbody></table></section>"""
    return layout("Attack surface", content, "/attack-surface", lead="Inventory identity joined with relationships from imported Zeek logs. No discovery scans or live capture are performed here.", heading="Passive attack surface")


def remediation_page(store: Store, page_number: int = 1) -> str:
    page_number=max(1,page_number)
    data=store.dashboard(limit=50,offset=(page_number-1)*50)
    plans = data["remediation_plans"]
    blocks = []
    statuses = ["Recommended", "Under Review", "Approved", "Implemented", "Verified", "Rejected", "Deferred", "Needs More Evidence"]
    for item in plans:
        plan = item["plan"]
        details = "".join(f"<p><b>{html.escape(key.replace('_', ' ').title())}:</b> {html.escape(str(plan.get(key, '')))}</p>" for key in ("finding_summary", "priority_explanation", "preferred_remediation", "vendor_guidance_status", "operational_impact", "confidence_and_questions"))
        for key in ("alternative_controls", "preconditions", "validation_steps", "rollback_considerations", "post_remediation_verification", "source_references"):
            values = plan.get(key, [])
            details += f"<b>{html.escape(key.replace('_', ' ').title())}</b><ul>" + "".join(f"<li>{html.escape(str(value))}</li>" for value in values) + "</ul>"
        if plan.get("ai_summary"):
            cited = html.escape('; '.join(plan.get('ai_source_references', [])))
            details += f'<div class="notice">AI-generated, unverified supplement · {html.escape(item["model"])}<p>{html.escape(plan["ai_summary"])}</p>' + "<br>".join(html.escape(s) for s in plan.get("ai_steps", [])) + f'<p>{html.escape(plan.get("ai_validation", ""))}</p>Cited URLs: {cited}<br>Local asset and network evidence was not sent to the model.</div>'
        options = "".join(f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in statuses if s != item["status"])
        history = "".join(f'<li>{html.escape(h["old_status"])} → {html.escape(h["new_status"])} · {html.escape(h["actor"] or "system")} · {html.escape(h["created_at"])} · {html.escape(h["notes"])}</li>' for h in item["history"])
        blocks.append(f'<article class="panel plan"><h2>{html.escape(item["cve_id"])} · {html.escape(item["hostname"] or item["ip_address"])} · {html.escape(item["status"])}</h2><p class="muted">Finding {html.escape(item["finding_status"])} · {html.escape(item["priority"])} priority · {html.escape(item["provider"])} {html.escape(item["model"])} · created {html.escape(item["created_at"])}</p>{details}<p>Reviewer: {html.escape(item["reviewer"] or "Not recorded")} · Change notes: {html.escape(item["change_notes"] or "None")}</p><p>Verification evidence: {html.escape(item["verification_evidence"] or "Not recorded")}</p><details><summary>Lifecycle history</summary><ol>{history}</ol></details><form method="post" action="/remediation/update"><input type="hidden" name="finding_id" value="{html.escape(item["finding_id"], quote=True)}"><select name="status">{options}</select><input name="reviewer" maxlength="120" placeholder="Reviewer (required for approval)"><input name="change_notes" maxlength="2000" placeholder="Change or review notes"><input name="verification_evidence" maxlength="4000" placeholder="Evidence (required to mark Verified)"><button>Update plan</button></form></article>')
    pager=(f'<a href="/remediation?page={page_number-1}">Previous</a> ' if page_number>1 else '')
    if page_number*50 < data["plans_count"]:pager+=f'<a href="/remediation?page={page_number+1}">Next</a>'
    body = pager + "".join(blocks) or '<section class="panel empty">No remediation plans yet. Generate one from an exposure finding on the overview.</section>'
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
            body = protect_forms(body.decode('utf-8'),self.csrf_token).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",CSP)
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Cache-Control","no-store")
        self.send_header("Referrer-Policy", "no-referrer")
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
        if path == "/":
            notice = parse_qs(urlparse(self.path).query).get("notice", [""])[0]
            try: page_number=int(parse_qs(urlparse(self.path).query).get("page",["1"])[0])
            except ValueError: page_number=1
            self._send(page(self.store, notice,page_number).encode())
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
            self._send(assets_page(self.store, query.get("q", [""])[0], page_number).encode())
        elif path == "/intelligence":
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            self._send(intelligence_page(self.store, query.get("q", [""])[0], page_number).encode())
        elif path == "/network":
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            self._send(network_page(self.store, page_number).encode())
        elif path == "/attack-surface":
            self._send(attack_surface_page(self.store).encode())
        elif path == "/remediation":
            try: page_number=int(parse_qs(urlparse(self.path).query).get("page",["1"])[0])
            except ValueError: page_number=1
            self._send(remediation_page(self.store,page_number).encode())
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
                self._send(b'Cross-origin request denied','text/plain; charset=utf-8',403)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_UPLOAD + 64_000:
                raise ValueError("Request is too large")
            raw = self.rfile.read(length)
            if not valid_token(form_token(raw,self.headers.get('Content-Type','')),self.csrf_token):
                self._send(b'Invalid or expired form token. Reload the dashboard and retry.','text/plain; charset=utf-8',403)
                return
            path = urlparse(self.path).path
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
            elif path == "/ack":
                form = parse_qs(raw.decode("utf-8", "replace"))
                if not self.store.acknowledge(form.get("alert_id", [""])[0]):
                    raise ValueError("Alert not found")
                notice = "Alert acknowledged."
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
                        result = ingest_file(self.store, tmp.name, kind="modbus" if "modbus" in original_name.casefold() else "conn", policy=policy, source_file=original_name)
                    notice = f"Network analysis: {result['events_inserted']} events, {result['alerts_created']} alerts, {result['duplicates_skipped']} duplicates. " + "; ".join(result["diagnostics"][:3])
            else:
                self._send(b"Not found", "text/plain; charset=utf-8", 404)
                return
            self.send_response(303)
            self.send_header("Location", "/?notice=" + __import__("urllib.parse", fromlist=["quote"]).quote(notice))
            self.end_headers()
        except (ValueError, UnicodeDecodeError, RuntimeError, TimeoutError, RecursionError) as exc:
            self._send(page(self.store, f"Input error: {exc}").encode(), status=400)

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
