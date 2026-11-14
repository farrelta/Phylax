"""Small local-only operator dashboard built on Python's standard library."""

from __future__ import annotations

import html
import json
import re
import secrets
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from .core import Store, read_json_limited, ASSET_FIELDS
from .web_security import CSP, valid_host, valid_origin, valid_token, multipart_fields, protect_forms
from .prioritization import prioritize
from .jobs import Jobs
from .remediation_service import generate_plan
from .remediation_presenter import plan_card
from .finding_views import finding_case
from .advisory_views import advisory_summary
from .operator_pages import inventory_form,policy_page,settings_page,reports_page
from .theme import layout, ring, status_marker, term, glossary_page, icon, kpi, spark, gauge
from .feeds import sync_store
from .monitoring import ingest_file, infer_zeek_kind, validate_policy, reevaluate_events
from .sensor_imports import import_wazuh
from .fingerprints import latest_fingerprint
from . import assistant_web, release_web
from .ui import verbatim, field, select, table, pager, reference_links, evidence_lines, evidence_url, assist_link
from .topology import VIEWPORT_SCRIPT, alert_topology_url, render_alert_topology, render_topology, url as surface_url, values as surface_query
from .triage import zone_alert, zone_pair, triage as triage_rows, alert_url
from .i18n import (COOKIE_NAME, LANGUAGES, language_control, local_destination,
                   request_language, translate_html, translate_text)


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


JOB_RETURN = {
    'Sync public sources': ('/intelligence', 'Return to intelligence'),
    'Reevaluate passive network policy': ('/policy', 'Return to network policy'),
    'Create investigation report': ('/reports', 'Return to reports'),
}


def action_notice(notice):
    return '<p class="notice" role="status">' + html.escape(notice) + '</p>' if notice else ''


def page(store: Store, notice: str = "", page_number: int = 1, finding_id: str = '') -> str:
    page_number = max(1,page_number)
    data = store.dashboard(limit=50,offset=(page_number-1)*50)
    if finding_id:
        finding=store.finding(finding_id)
        if not finding:raise ValueError('Finding not found')
        return finding_case(store,finding,kev_status(finding,data['source_health']),notice)
    cards = [("Devices in inventory", data["assets"], ""), ("Devices to identify", data["assets_needing_identity_review"], "Identity review"), ("Confirmed affected", data["confirmed_assets"], "Confirmed affected"), ("Possibly affected", data["potential_assets"], "Possibly affected"), ("Known-exploited flaws", data["kev_findings"], "KEV"), ("Critical devices at risk", data["critical_exposed_assets"], ""), ("Network connections seen", data["communication_relationships"], ""), ("New alerts", data["unacknowledged_alerts"], ""), ("Out-of-date data feeds", data["stale_sources"], "")]
    groups = {}
    for f in data["findings"]:
        groups.setdefault(f["cve_id"], []).append(f)
    confidence_label = {"CONFIRMED_MATCH": "high", "NO_MATCH_TO_THIS_ADVISORY": "high", "POTENTIAL_MATCH": "medium", "NEEDS_REVIEW": "low"}
    group_html = []
    for cve_id, items in groups.items():
        lead = items[0]
        references = reference_links(json.loads(lead["references_json"]))
        source_label = 'Demo fixture' if lead['synthetic'] else html.escape(lead['source'])
        published = f' · published {html.escape(lead["published"])}' if lead.get('published') else ''
        advisory_meta = (f'<details class="cve-about"><summary>Advisory details</summary>'
                         f'<p>{verbatim(lead["summary"])}</p>'
                         f'<p class="muted">{source_label}{published}</p>'
                         + (f'<p>{references}</p>' if references else '') + '</details>')
        head = (f'<tr class="cve-head"><th colspan="4" scope="colgroup">'
                f'<a class="mono" href="/?{urlencode({"finding_id": lead["finding_id"]})}#finding-{html.escape(lead["finding_id"], quote=True)}">{html.escape(cve_id)}</a>'
                f'<span class="cve-sev">{html.escape(lead["severity"] or "severity unrated")} severity</span>'
                + (f'<span class="cve-kev">Known exploited</span>' if lead.get("kev") else '')
                + f'<span class="cve-count">{len(items)} device{"s" if len(items) != 1 else ""}</span>'
                + f'{advisory_meta}</th></tr>')
        device_rows = []
        for f in items:
            evidence = evidence_html(json.loads(f["evidence"]))
            missing = "<br>".join(html.escape(x) for x in json.loads(f["missing_evidence"]))
            urgency = prioritize(f, f, f["status"])
            priority_detail = "; ".join(f"{x['input']}: {x['value']} (+{x['points']})" for x in urgency["factors"])
            score_text = f"{urgency['score']} / 12" if urgency["score"] is not None else "not scored"
            plan_data = store.get_remediation_plan(f["finding_id"])
            if plan_data:
                plan_action = (f'<p>Plan: {html.escape(plan_data["status"])} · updated {html.escape(plan_data["updated_at"])}</p>'
                               f'<a class="btn" href="/remediation?{urlencode({"finding_id": f["finding_id"]})}">Review plan</a>')
            else:
                plan_action = assist_link('remediation', 'Draft fix guidance (AI, for review)', f['finding_id'])
            mitigation = verbatim(f['mitigation']) if f['mitigation'] else html.escape('No verified vendor guidance supplied.')
            details = (f'<details class="finding-more"><summary>Details for {html.escape(f["hostname"] or f["ip_address"])}</summary>'
                       f'<p><b>Why this score</b><br><small>{html.escape(priority_detail)}<br>Match confidence: {confidence_label.get(f["status"], "unknown")}</small></p>'
                       f'<p><b>Evidence</b><br>{evidence}</p>'
                       + (f'<p><small>Missing evidence: {missing}</small></p>' if missing else '')
                       + f'<p><b>What to do</b><br>{mitigation}</p>{plan_action}</details>')
            device_rows.append(
                f'<tr id="finding-{html.escape(f["finding_id"], quote=True)}">'
                f'<td><span class="mono">{html.escape(f["ip_address"])}</span> {verbatim(f["hostname"])}'
                f'<br><small>{verbatim(f["vendor"])} {verbatim(f["product"])} {verbatim(f["version"])}</small></td>'
                f'<td>{html.escape((f["zone"] or "unknown").upper())}<br><small>{html.escape(f["criticality"])} criticality</small></td>'
                f'<td>{status_marker(f["status"])}</td>'
                f'<td><b>{html.escape(score_text)}</b> <small>{html.escape(f["priority"])}</small>{details}</td></tr>')
        group_html.append(f'<tbody class="cve-group">{head}{"".join(device_rows)}</tbody>')
    finding_table = "".join(group_html) or '<tbody><tr><td colspan="4" class="empty">No findings yet. Import assets and load a local fixture to begin.</td></tr></tbody>'
    alert_summary = (f'<p>{data["unacknowledged_alerts"]} unacknowledged alerts across vulnerability, network and device-management evidence.</p>'
                     '<p><a href="/triage">Review new alerts in Triage</a></p>')
    health_html = "".join(f'<div class="alert"><div><b>{html.escape(source["source"])} · {html.escape(source["health"])}</b><br><small>Last success: {html.escape(source["last_success_at"] or "Never")} · {html.escape(source["message"])}</small></div></div>' for source in data["source_health"]) or '<p class="empty">No synchronization yet. Stored offline data remains available.</p>'
    updates_html = "".join(f'<div class="alert"><div><b>{html.escape(item["change_type"])} · {html.escape(item["cve_id"])}</b><br><small>{html.escape(item["source"])} · {html.escape(item["changed_at"])}<br>{verbatim(item["summary"])}</small></div></div>' for item in data["recent_intelligence"]) or '<p class="empty">No intelligence records stored yet.</p>'
    identity_review_html = f'<p class="notice">{data["assets_needing_identity_review"]} assets need identity review. Unknown product or version information limits vulnerability assessment. <a href="/assets?identity_review=yes">Review these assets</a>.</p>' if data["assets_needing_identity_review"] else ""
    largest = data['findings_count']
    pager = (f'<a class="link" href="/?page={page_number-1}">Previous</a>' if page_number>1 else '')
    if page_number>1 or page_number*50 < largest:
        pager += f' <span class="muted">Page {page_number}</span> '
    if page_number*50 < largest:pager += f'<a class="link" href="/?page={page_number+1}">Next</a>'
    pager = f'<div class="controls">{pager}</div>' if pager.strip() else ''
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    scored = []
    for f in data["findings"]:
        u = prioritize(f, f, f["status"])
        if u["score"] is not None:
            scored.append((u["score"], u["priority"], f))
    scored.sort(key=lambda t: -t[0])
    tone = {"critical": "crit", "high": "high", "medium": "info"}
    total_assets, confirmed, possible, new_alerts = data["assets"], data["confirmed_assets"], data["potential_assets"], data["unacknowledged_alerts"]
    violation = zone_alert(store)
    zone_card = ''
    if violation:
        pair = html.escape(zone_pair(violation['policy']))
        source = html.escape(violation['source_ip'])
        destination = html.escape(violation['destination_ip'])
        zone_card = (f'<div class="headline zone-alert"><b>Zone policy violation</b> · {pair}'
                     f'<small><span class="mono">{source} → {destination}</span> · '
                     f'<a href="{html.escape(alert_topology_url(violation["alert_id"]), quote=True)}">Show on topology</a></small></div>')
    weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    all_assets = store.assets()
    unknown = data["assets_needing_identity_review"]
    pct = lambda n: f"{round(100 * n / total_assets)}%" if total_assets else "0%"
    history_rows, _ = triage_rows(store, limit=500, history=True)
    per_day = {}
    for row in history_rows:
        per_day[row["timestamp"][:10]] = per_day.get(row["timestamp"][:10], 0) + 1
    days = sorted(per_day)
    if days:
        from datetime import date, timedelta
        last = date.fromisoformat(days[-1])
        alert_days = [per_day.get((last - timedelta(days=13 - i)).isoformat(), 0) for i in range(14)]
    else:
        alert_days = [0] * 14
    advisories_loaded = data["advisories_count"] > 0
    logs_imported = data["network_events"] > 0
    critical_exposed = data["critical_exposed_assets"]
    confirmed_sub = f"of {total_assets} devices" + (f" · {critical_exposed} critical" if critical_exposed else "")
    kpis = "".join((
        kpi("Devices in inventory", total_assets, f"{unknown} need identity review" if unknown else "All identified",
            spark([weight.get(a["criticality"], 1) for a in all_assets][:18] or [0],
                  tuple({"critical": "crit", "high": "high", "medium": "gold"}.get(a["criticality"], "") for a in all_assets[:18])),
            href="/assets", glyph="server", color="olive"),
        kpi("Confirmed affected", confirmed, confirmed_sub, ring(confirmed, total_assets, pct(confirmed), "crit" if confirmed else "ok"),
            chip="Act now" if confirmed else "", tone="bad", href="#findings", glyph="shield", color="red",
            empty="" if advisories_loaded else "No advisories loaded yet"),
        kpi("Possibly affected", possible, "should be checked", gauge(possible, total_assets, pct(possible), "high" if possible else ""),
            chip="To check" if possible else "", tone="warn", href="#findings", glyph="search", color="amber",
            empty="" if advisories_loaded else "No advisories loaded yet"),
        kpi("New alerts", new_alerts, "to review in Triage", spark(alert_days),
            chip="Review" if new_alerts else "", tone="info", href="/triage", glyph="bell", color="blue",
            empty="" if (advisories_loaded or logs_imported) else "No evidence imported yet"),
    ))
    by_device = {}
    for score, priority, f in scored:
        name = f["hostname"] or f["ip_address"]
        if name not in by_device or score > by_device[name][0]:
            by_device[name] = (score, priority, f)
    ranked = sorted(by_device.items(), key=lambda kv: -kv[1][0])[:6]
    zone_of = {(a["hostname"] or a["ip_address"]): a["zone"] for a in all_assets}
    rank_html = "".join(
        f'<li><div class="row"><b>{score}</b><span>{verbatim(name)} · {html.escape(zone_of.get(name) or "Unknown")}</span></div>'
        f'<div class="bar"><i class="{"crit" if priority == "critical" else "high" if priority == "high" else ""}" style="width:{round(100 * score / 12)}%"></i></div></li>'
        for name, (score, priority, f) in ranked) or '<li class="empty">Nothing scored yet.</li>'
    todo = []
    if confirmed:
        todo.append(("red", "shield", confirmed, "Devices confirmed affected", "A known flaw matches these devices. Open the finding and plan a fix first.", "#findings", "See findings"))
    if new_alerts:
        todo.append(("blue", "bell", new_alerts, "New alerts to review", "Look at each alert and acknowledge the ones you have checked.", "/triage", "Open triage"))
    if possible:
        todo.append(("amber", "search", possible, "Devices possibly affected", "Check the version on the device to confirm or rule out the flaw.", "#findings", "Check versions"))
    if unknown:
        todo.append(("gold", "id", unknown, "Devices to identify", "Add vendor, product and version so Phylax can check them for flaws.", "/assets?identity_review=yes", "Identify devices"))
    if data["stale_sources"]:
        todo.append(("olive", "update", data["stale_sources"], "Data feeds out of date", "Update public intelligence so new flaws are included.", "/settings", "Update sources"))
    if not todo:
        todo.append(("olive", "check", 0, "Nothing urgent right now", "No confirmed or new issues in the stored data. That does not prove the network is safe.", "/reports", "Open reports"))
    minis = (("Known-exploited flaws", data["kev_findings"], "#findings", "red", advisories_loaded),
             ("Network connections seen", data["communication_relationships"], "/attack-surface", "", logs_imported),
             ("Out-of-date data feeds", data["stale_sources"], "/settings", "amber", advisories_loaded))
    mini_html = '<div class="mini-strip">' + "".join(
        f'<a class="mini" href="{href}"><span>{html.escape(label)}</span>'
        + (f'<b class="{tone if value else ""}">{value}</b>' if has_data else '<b class="none">no data</b>')
        + '</a>'
        for label, value, href, tone, has_data in minis) + '</div>'
    last_sync = next((s["last_success_at"] for s in data["source_health"] if s.get("last_success_at")), None)
    coverage = (
        (f'{data["network_events"]} network events' if logs_imported else 'Logs: none imported'),
        (f'{data["advisories_count"]} advisories' if advisories_loaded else 'Advisories: none loaded'),
        (f'synced {html.escape(last_sync)}' if last_sync else 'Feeds: never synced'),
    )
    coverage_html = ('<p class="coverage"><span class="coverage-label">Data coverage</span>'
                     + ' · '.join(f'<span>{c}</span>' for c in coverage)
                     + '</p>')
    if confirmed:
        status_text = f"{confirmed} device{'s' if confirmed != 1 else ''} confirmed affected. Fix them first."
    elif possible:
        status_text = f"{possible} device{'s' if possible != 1 else ''} possibly affected. Check their versions."
    elif new_alerts:
        status_text = f"{new_alerts} new alert{'s' if new_alerts != 1 else ''} to review."
    elif unknown:
        status_text = f"{unknown} device{'s' if unknown != 1 else ''} still need identifying."
    else:
        status_text = "Nothing urgent in the imported data. This does not prove the network is safe."
    status_html = f'<p class="status-line">{html.escape(status_text)}</p>'
    start_html = ('<section class="start" aria-labelledby="start-here"><header><h2 id="start-here">Start here</h2>'
                  '<p>The most important things to do now, in order.</p></header><ol class="steps-next">' + "".join(
        f'<li><b><i class="sev {c}" aria-hidden="true"></i>{html.escape(title)}' + (f'<span class="n">{n}</span>' if n else '') + '</b>'
        f'<p>{html.escape(text)}</p><a class="btn" href="{html.escape(href, quote=True)}">{html.escape(label)}</a></li>'
        for c, g, n, title, text, href, label in todo[:3]) + '</ol></section>')
    map_html = exposure_map(all_assets, {name: (score, priority) for name, (score, priority, _) in by_device.items()})
    events = []
    activity_rows, _ = triage_rows(store, limit=10)
    labels = {"exposure": "Vulnerability exposure", "network": "Network policy", "endpoint": "Device management"}
    kinds = {"exposure": ("shield", "high"), "network": ("pulse", "info"), "endpoint": ("device", "gold")}
    for row in activity_rows:
        asset = row["context"]
        icon_name, icon_tone = kinds.get(row["category"], ("bell", ""))
        if row["urgency"]["priority"] == "critical":
            icon_tone = "crit"
        events.append((row["timestamp"], icon_name, icon_tone, row.get("cve_id") or labels.get(row["category"], "Alert"),
                       f'{verbatim(asset.get("hostname") or row["ip"])} · {html.escape(row["timestamp"])}', alert_url(row["alert_id"])))
    for item in data["recent_intelligence"][:4]:
        events.append((item["changed_at"], "update", "olive", f'{html.escape(item["change_type"])} · {html.escape(item["cve_id"])}',
                       f'{html.escape(item["source"])} · {html.escape(item["changed_at"])}', "/intelligence"))
    events.sort(key=lambda e: e[0], reverse=True)
    feed_html = "".join(
        f'<li><a href="{html.escape(href, quote=True)}"><span class="ico {tone_}">{icon(icon_name)}</span><span><b>{title}</b><small>{sub_}</small></span><span class="go">{icon("arrow")}</span></a></li>'
        for _, icon_name, tone_, title, sub_, href in events[:10]) or '<li class="empty">No recent activity yet.</li>'
    content = f"""{notice_html}{zone_card}{pager}
<div class="dash">{status_html}
{start_html}
{coverage_html}
<div class="kpis">{kpis}</div>
{mini_html}
<div class="cards dash-main">
<section class="cardx"><header><h2>Exposure map</h2><span class="select-pill">Highest urgency</span></header>{map_html}<ul class="bars">{rank_html}</ul>
<div class="card-foot"><a class="btn" href="/reports">Full report</a><a class="btn sq" href="/triage" aria-label="Open triage">{icon("arrow")}</a></div></section>
<section class="cardx"><header><h2>Recent activity</h2><a class="select-pill" href="/triage">Latest first</a></header><ul class="feed">{feed_html}</ul></section>
</div></div>
{identity_review_html}
<section class="cardx wide"><header><h2 id="findings">Exposure findings</h2><a class="aux" href="/reports">Full report {icon("arrow")}</a></header><p class="panel-note">Grouped by advisory. Open Details on a device for evidence and what to do.</p><div class="panel"><table class="findings grouped"><thead><tr><th scope="col">Device</th><th scope="col">Zone</th><th scope="col">Status</th><th scope="col">Urgency</th></tr></thead>{finding_table}</table></div></section>
<div class="cards three">
<section class="cardx"><header><h2>Alerts</h2><span class="aux">{data["network_events"]} network events</span></header><div class="card-body">{alert_summary}</div></section>
<section class="cardx"><header><h2>Intelligence sources</h2><a class="aux" href="/intelligence">Open intelligence {icon("arrow")}</a></header><div class="card-body">{health_html}</div></section>
<section class="cardx"><header><h2>Recent intelligence updates</h2><a class="aux" href="/intelligence">Open intelligence {icon("arrow")}</a></header><div class="card-body">{updates_html}</div></section>
</div>
<footer>Urgency is a transparent rule-based priority; severity and applicability remain separate. KEV indicates catalog-listed exploitation, not an attack on this asset. Absence of a finding does not mean an asset is safe. Timestamps are stored in UTC. Exports are on the <a href="/reports">Reports</a> page.</footer>"""
    if not total_assets:
        content=notice_html+zone_card+f'''<section class="setup-start"><h2>Start with your asset inventory</h2><p>No devices loaded yet. Add an asset or import a CSV with an IP address for each device. Unknown product and firmware information can stay blank.</p>
<p><a class="btn primary" href="/assets">Open asset inventory</a></p>
<h3>Then build the evidence</h3><ol><li>Load cached advisories in <a href="/intelligence">Intelligence</a>.</li><li>Import Zeek logs in <a href="/network">Monitoring</a>.</li><li>Review applicability, missing evidence and policy alerts.</li></ol>
</section>'''
    return layout("Overview", content, "/", lead="Local inventory, recorded network activity, and stored intelligence.", heading="Security overview")


def exposure_map(assets, scores) -> str:
    """Dot-matrix zone map with one glow per device, sized by its urgency score."""
    import hashlib
    zones = {"IT": (110, 92, 92, 62), "DMZ": (300, 100, 62, 50), "OT": (480, 92, 100, 66)}
    dots = []
    for y in range(10, 196, 9):
        for x in range(8, 600, 9):
            for cx, cy, rx, ry in zones.values():
                wobble = (int(hashlib.md5(f"{x},{y}".encode()).hexdigest()[:2], 16) / 255 - .5) * .35
                if ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1 + wobble:
                    dots.append(f'<circle class="dot" cx="{x}" cy="{y}" r="1.4"/>')
                    break
    labels = "".join(f'<text class="zl" x="{cx}" y="{cy + ry + 22}" text-anchor="middle">{z}</text>' for z, (cx, cy, rx, ry) in zones.items())
    markers = []
    for asset in assets:
        name = asset["hostname"] or asset["ip_address"]
        cx, cy, rx, ry = zones.get((asset["zone"] or "").upper(), (300, 100, 62, 50))
        digest = hashlib.md5(asset["asset_id"].encode()).digest()
        x = cx + (digest[0] / 255 - .5) * rx * 1.2
        y = cy + (digest[1] / 255 - .5) * ry * 1.2
        score, priority = scores.get(name, (0, ""))
        tone = "crit" if priority == "critical" else "high" if priority == "high" else "ok"
        radius = 3.5 + score * 0.9
        title = html.escape(f"{name} · {asset['zone'] or 'Unknown'} · urgency {score} of 12")
        # Flat markers: solid fill sized by urgency, plus the score as a text label when it is worth reading.
        marker = f'<circle class="mk mk-{tone}" cx="{x:.0f}" cy="{y:.0f}" r="{radius:.1f}"/>'
        if score >= 1:
            marker += f'<text class="mk-num" x="{x:.0f}" y="{y - radius - 2:.0f}" text-anchor="middle">{score}</text>'
        markers.append(f'<g><title>{title}</title>{marker}</g>')
    return (f'<svg class="map" viewBox="0 0 600 212" role="img" aria-label="Devices by network zone, labelled with urgency score">'
            f'{"".join(dots)}{labels}{"".join(markers)}</svg>')


def assets_page(store: Store, search: str = "", page_number: int = 1, *, identity_review: bool = False, notice: str = "") -> str:
    page_number = max(1, page_number)
    limit = 50
    rows, total = store.search_assets(search, limit=limit, offset=(page_number - 1) * limit, identity_review=identity_review)
    def fingerprint_detail(ip):
        fingerprint = latest_fingerprint(store, ip)
        if fingerprint is None:
            return ''
        mapping = fingerprint['mapping']
        lines = ['Modbus responder observed']
        if fingerprint['conflict']:
            lines.append('Conflicting identity or multiple Modbus units')
        elif mapping and mapping['role'] == 'PLC':
            lines.append('PLC suggested')
        observed = ' '.join(fingerprint[field] for field in ('vendor','product_code') if fingerprint[field])
        revision = '<br>Reported revision: '+verbatim(fingerprint['revision']) if fingerprint['revision'] else ''
        link = html.escape(evidence_url(fingerprint['event_ref'], '/assets'), quote=True)
        return '<br><small>'+'<br>'.join(html.escape(line) for line in lines)+(
            '<br>'+verbatim(observed) if observed else '')+revision+f'<br><a href="{link}">Original event</a></small>'

    def needs_identity(row):
        return not (row['vendor'] or '').strip() or not (row['product'] or '').strip() or row['identity_confidence'] != 'high' or not row['verified']

    def device_row(row):
        edit = '/assets/edit?' + urlencode({'asset_id': row['asset_id']})
        make = ' '.join(v for v in (row['vendor'], row['product'], row['version']) if v)
        make_html = verbatim(make) if make else '<span class="missing">Unknown</span>'
        if needs_identity(row):
            state = f'<a class="state warn" href="{html.escape(edit, quote=True)}">Needs identifying</a>'
        else:
            state = '<span class="state good">Identified</span>'
        importance = row['criticality'] or 'unknown'
        zone = (row['zone'] or '?').upper()
        name = verbatim(row['hostname']) if row['hostname'] else html.escape('Unnamed device')
        more = (f'<details class="more"><summary>More details</summary><dl class="kv">'
                f'<div><dt>Asset ID</dt><dd>{html.escape(row["asset_id"])}</dd></div>'
                f'<div><dt>MAC address</dt><dd>{html.escape(row["mac_address"] or "MAC unknown")}</dd></div>'
                f'<div><dt>Operating system</dt><dd>{verbatim(row["operating_system"]) if row["operating_system"] else html.escape("Unknown")}</dd></div>'
                f'<div><dt>Identified by</dt><dd>{html.escape(row["identification_source"])} · {html.escape(row["identity_confidence"])} confidence · {"verified" if row["verified"] else "unverified"}</dd></div>'
                f'<div><dt>Last seen</dt><dd>{html.escape(row["last_seen"] or "Unknown")}</dd></div>'
                + (f'<div><dt>Notes</dt><dd>{verbatim(row["notes"])}</dd></div>' if row['notes'] else '')
                + f'</dl>{fingerprint_detail(row["ip_address"])}</details>')
        return (f'<tr><td class="device"><b>{name}</b><small><span class="mono">{html.escape(row["ip_address"])}</span> · {html.escape(row["asset_type"] or "Unknown type")}</small>{more}</td>'
                f'<td>{make_html}</td>'
                f'<td><span class="zone-badge zone-{html.escape(zone.lower())}" title="{html.escape(zone)} zone">{html.escape(zone[:3])}</span></td>'
                f'<td><span class="imp imp-{html.escape(importance)}">{html.escape(importance.capitalize())}</span></td>'
                f'<td>{state}</td>'
                f'<td class="row-action"><a class="btn" href="{html.escape(edit, quote=True)}">Edit</a></td></tr>')

    body = "".join(device_row(row) for row in rows) or '<tr><td colspan="6" class="empty">No assets found. Import a CSV or add a device.</td></tr>'
    query = urlencode({"q": search, **({"identity_review":"yes"} if identity_review else {})})
    previous = f'<a class="link" href="/assets?{query}&page={page_number - 1}">Previous</a>' if page_number > 1 else ""
    next_link = f'<a class="link" href="/assets?{query}&page={page_number + 1}">Next</a>' if page_number * limit < total else ""
    review_control = '<label class="inline-check"><input type="checkbox" name="identity_review" value="yes"'+(' checked' if identity_review else '')+'> Needs identity review</label>'
    counts = store.dashboard()
    tabs = (f'<nav class="quick-tabs" aria-label="Device filter"><a href="/assets"' + ('' if identity_review else ' class="on"') + f'>All devices <span>{counts["assets"]}</span></a>'
            f'<a href="/assets?identity_review=yes"' + (' class="on"' if identity_review else '') + f'>Needs identifying <span>{counts["assets_needing_identity_review"]}</span></a></nav>')
    pages = f'<span class="muted">{total} devices · page {page_number}</span>{previous}{next_link}'
    upload = '''<form method="post" action="/assets/import" enctype="multipart/form-data">
<div><label for="asset-import-file">Inventory CSV</label>
<input id="asset-import-file" required name="file" type="file" accept=".csv,text/csv" aria-describedby="asset-import-hint">
<small id="asset-import-hint">Choose a CSV with one row per device and an IP address for each.</small></div>
<button>Import asset CSV</button></form>'''
    content = f"""{action_notice(notice)}<div class="toolbar">{tabs}<div class="toolbar-actions"><a class="btn" href="/assets.csv">Export CSV</a><a class="btn primary" href="/assets/edit">Add asset</a></div></div>
<form class="search-row" method="get" action="/assets"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search by name, address, vendor or product" aria-label="Search assets">{review_control}<button>Search</button>{'<a href="/assets">Clear filters</a>' if search or identity_review else ''}</form>
<details class="workflow"><summary>Import inventory CSV</summary>{upload}</details>
<section class="panel"><table class="asset-inventory device-table"><thead><tr><th>Device</th><th>Make and model</th><th>Zone</th><th>Importance</th><th>Status</th><th><span class="vh">Actions</span></th></tr></thead><tbody>{body}</tbody></table></section>
<div class="controls pager-row">{pages}</div>"""
    return layout("Inventory", content, "/assets", lead="Observed metadata remains separate from operator verification. Unknown identity is not inferred from an IP address.", heading="Asset inventory")


def _pager(path: str, search: str, page_number: int, total: int, limit: int = 50) -> str:
    query = urlencode({"q": search})
    previous = f'<a class="link" href="{path}?{query}&page={page_number - 1}">Previous</a>' if page_number > 1 else ""
    following = f'<a class="link" href="{path}?{query}&page={page_number + 1}">Next</a>' if page_number * limit < total else ""
    return f'<span class="muted">{total} records · page {page_number}</span>{previous}{following}'


def intelligence_page(store: Store, search: str = "", page_number: int = 1, notice: str = "") -> str:
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
        <td>{verbatim(item['summary'])}<br><small>{html.escape(product_text)}</small></td><td>{verbatim(item['mitigation']) if item['mitigation'] else html.escape('No mitigation guidance supplied.')}<br><small>{reference_links(refs or ([item['source_url']] if item['source_url'] else [])) or 'No reference supplied'}</small></td></tr>""")
    pager = _pager("/intelligence", search, page_number, total, limit)
    offline = """<details class="workflow"><summary>Import offline advisory</summary>
<form method="post" action="/intelligence/import" enctype="multipart/form-data">
<label>Offline advisory JSON<input name="file" type="file" accept=".json,application/json" required></label>
<button>Import advisory JSON</button></form></details>"""
    content = f"""{action_notice(notice)}<div class="controls"><form method="get" action="/intelligence"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search CVE, summary, source" aria-label="Search intelligence"> <button>Search</button></form><form method="post" action="/sync"><button>Sync public sources</button></form>{pager}</div>{offline}
<section class="panel"><table><thead><tr><th>Identifier / source</th><th>Severity / status / dates</th><th>Summary / affected product data</th><th>Mitigation / references</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="4" class="empty">No intelligence records found.</td></tr>'}</tbody></table></section>"""
    return layout("CVE intelligence", content, "/intelligence", lead="Normalized CVE records are cached locally. Product/version applicability remains subject to source evidence and the documented matcher limits.")


def ics_advisories_page(store: Store, search: str = '', page_number: int = 1) -> str:
    page_number=max(1,page_number);limit=50
    records,total=store.search_ics_advisories(search,limit=limit,offset=(page_number-1)*limit)
    rows = ''.join(
        f"<tr><td>{verbatim(row['title'])}</td><td>{html.escape(row['published'] or 'Unknown')}</td>"
        f"<td>{reference_links([row['link']])}</td><td>{advisory_summary(row['summary'])}"
        "</td></tr>"
        for row in records
    )
    empty='No advisories match this search.' if search else 'No CISA ICS advisories stored. Sync public sources to load the advisory feed.'
    controls=f'''<div class="controls"><form method="get" action="/intelligence/ics"><input name="q" value="{html.escape(search,quote=True)}" placeholder="Search advisory, product or summary" aria-label="Search CISA ICS advisories"> <button>Search</button></form>{_pager('/intelligence/ics',search,page_number,total,limit)}</div>'''
    content=controls+'<section class="panel"><table><thead><tr><th>Advisory</th><th>Published</th><th>Reference</th><th>Summary</th></tr></thead><tbody>'+(rows or '<tr><td colspan="4" class="empty">'+html.escape(empty)+'</td></tr>')+'</tbody></table></section>'
    return layout('CISA ICS advisories',content,'/intelligence/ics',lead='Cached advisory feed entries for operator review. Affected versions are not inferred from advisory text.')


def network_page(store: Store, page_number: int = 1, notice: str = '') -> str:
    page_number = max(1, page_number)
    limit = 50
    events, total = store.recent_network_events(limit=limit, offset=(page_number - 1) * limit)
    def event_row(row):
        when = re.sub(r'\.0+(?=Z|$)', '', row['timestamp']).replace('T', ' ').replace('Z', ' UTC')
        record = html.escape(evidence_url(row['event_ref'], '/network?page=' + str(page_number)), quote=True)
        what = ' · '.join(v for v in (row['protocol'], row['event_type'], row['operation']) if v)
        notes = '; '.join(json.loads(row['diagnostics_json'] or '[]'))
        alert = (f'<span class="flag">{html.escape(row["rule_ids"])}</span>' if row['rule_ids']
                 else '<span class="muted">No active rule alert</span>')
        return (f'<tr><td><span class="nw">{html.escape(when)}</span><small><a href="{record}">{verbatim(row["event_ref"])}</a></small></td>'
                f'<td class="mono">{html.escape(row["source_ip"])}<span class="arrow" aria-hidden="true"> → </span>{html.escape(row["destination_ip"])}'
                f'<small>port {html.escape(str(row["source_port"] or "–"))} → {html.escape(str(row["destination_port"] or "–"))}</small></td>'
                f'<td>{html.escape(what)}</td><td>{alert}<small>{html.escape(notes)}' + (' · ' if notes else '') + f'{verbatim(row["source_file"])}</small></td></tr>')

    rows = "".join(event_row(row) for row in events) or '<tr><td colspan="4" class="empty">No network activity yet. Upload a Zeek log above to get started.</td></tr>'
    pager = _pager("/network", "", page_number, total, limit)
    kind = select('kind','Zeek log kind',[('','Detect from file name'),('conn','Connections'),('modbus','Modbus operations'),
        ('modbus-identity','Modbus device identification'),('dhcp','DHCP'),('software','Software')])
    banner = '<p class="notice success" role="status">'+html.escape(notice)+'</p>' if notice else ''
    content = f"""{banner}<section class="cardx upload-card"><div class="upload-text"><h2>Add a network log</h2>
<p>Choose a log file exported by Zeek, for example <span class="mono">conn.log</span> or <span class="mono">modbus.log</span>. Phylax uses the saved network policy to check imported activity.</p></div>
<form method="post" action="/network/import" enctype="multipart/form-data"><label class="file-pick"><span>Log file</span><input required name="file" type="file" accept=".log,.json,.jsonl,.tsv"></label>
<details class="more"><summary>More options</summary>{kind}<small>Phylax can usually tell the type from the file name.</small></details>
<button class="primary">Import Zeek log</button></form></section>
<section class="cardx wide"><header><h2>Recorded traffic</h2><span class="aux">{pager}</span></header><div class="panel"><table class="events-table"><thead><tr><th>When</th><th>From → to</th><th>What happened</th><th>Alert</th></tr></thead><tbody>{rows}</tbody></table></div></section>"""
    return layout("Network events", content, "/network", lead="Import Zeek logs or review recorded network activity.", heading="Passive network monitoring")


def attack_surface_page(store: Store, query=None) -> str:
    query=query or {}
    alert_id=query.get('alert',[''])[0]
    if alert_id:
        return layout('Alert topology', render_alert_topology(store, zone_alert(store, alert_id)), '/attack-surface',
                      heading='Alert topology')
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

    nodes=''.join('<tr><td class="nw mono">'+asset_link(n)+'</td><td>'+verbatim(n['identity'])
                  +'<br><small>'+esc(n['asset_type'])+' · '+verbatim(' '.join(str(n[k]) for k in ('vendor','product','version')))
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
        source=verbatim(row['source_identity'])+' ('+esc(row['source_ip'])+')'
        destination=verbatim(row['destination_identity'])+' ('+esc(row['destination_ip'])+')'
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
    return layout("Attack surface", content, "/attack-surface", lead="Inventory identity joined with relationships from imported Zeek logs. The map shows recorded traffic.", heading="Passive attack surface")


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
        language = request_language(self.headers)
        if content_type.startswith('text/html'):
            label=self.store.connection.execute("SELECT value FROM schema_meta WHERE key='dataset_label'").fetchone()
            chip = '<span class="dataset" translate="no">'+html.escape(label[0])+'</span>' if label else '<span></span>'
            markup = body.decode('utf-8')
            control = '<div class="topbar">'+chip+language_control(self.path, language)+'</div>'
            if '<main id="main-content" tabindex="-1">' in markup:
                markup = markup.replace('<main id="main-content" tabindex="-1">', '<main id="main-content" tabindex="-1">'+control, 1)
            elif label:
                markup = re.sub(r'<main\b[^>]*>', lambda match: match[0]+chip, markup, count=1)
            body = protect_forms(translate_html(markup, language),self.csrf_token).encode('utf-8')
        elif content_type.startswith('text/plain'):
            body = translate_text(body.decode('utf-8'), language).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if content_type.startswith(('text/html', 'text/plain', 'text/markdown')):
            self.send_header('Content-Language', language)
            self.send_header('Vary', 'Cookie, Accept-Language')
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
        if path == '/static/board.js':
            from .triage_views import BOARD_JS
            self._send(BOARD_JS.encode(), 'text/javascript; charset=utf-8')
            return
        if path == '/static/topology.js':
            self._send(VIEWPORT_SCRIPT.encode(), 'text/javascript; charset=utf-8')
            return
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
        elif path == '/assist':
            try:self._send(assistant_web.assistance_page(self.store, parse_qs(urlparse(self.path).query)).encode())
            except ValueError as exc:self._send(layout('Assistance unavailable', '<p>'+html.escape(str(exc))+'</p><a href="/">Return to overview</a>').encode(), status=400)
        elif path.startswith('/jobs/'):
            job = self.server.jobs.get(path.rsplit('/',1)[-1])
            if not job:
                self._send(b'Job not found','text/plain; charset=utf-8',404)
                return
            refresh = '<meta http-equiv="refresh" content="2">' if job['status'] in {'queued','running'} else ''
            running = job['status'] in {'queued', 'running'}
            back, back_label = JOB_RETURN.get(job['label'], ('/', 'Return to overview'))
            if job['label'].startswith('Generate remediation '):
                finding_id = job['label'].removeprefix('Generate remediation ')
                back = '/remediation?' + urlencode({'finding_id': finding_id}) if job['status'] == 'complete' else '/?' + urlencode({'finding_id': finding_id})
                back_label = 'Review plan' if job['status'] == 'complete' else 'Return to finding'
            if 'result' in job:
                body = layout(job['label'], assistant_web.result_content(job['result'], job['job_id']), '/reports')
            else:
                body = layout(job["label"], f'<p class="lead">{html.escape(job["message"])}</p><dl class="stats"><div><dt>Status</dt><dd>{html.escape(job["status"])}</dd></div><div><dt>Updated</dt><dd>{html.escape(str(job["updated_at"]))}</dd></div></dl>' + ('<p class="muted">This page refreshes every 2 seconds while the task is running.</p>' if running else
                    '<p><a class="btn" href="'+html.escape(back, quote=True)+'">'+back_label+'</a></p>'), "").replace("<title>", refresh + "<title>", 1)
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
            query = parse_qs(urlparse(self.path).query)
            self._send(settings_page(self.store, notice=query.get('notice', [''])[0]).encode())
        elif path == '/reports/draft.md':
            job_id = parse_qs(urlparse(self.path).query).get('job', [''])[0]
            try:
                report = assistant_web.report_download(self.server.jobs, job_id, 'http://' + self.headers['Host'])
            except ValueError as exc:
                self._send(layout('Report unavailable', action_notice(str(exc)) +
                                  '<p><a href="/reports">Return to reports</a></p>', '/reports').encode(), status=404)
            else:
                self._send(report.encode(), "text/markdown; charset=utf-8", download="phylax-investigation.md")
        elif path == '/reports':
            self._send(reports_page(self.store).encode())
        elif path == "/assets":
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            self._send(assets_page(self.store, query.get("q", [""])[0], page_number, identity_review=query.get("identity_review",[""])[0]=="yes", notice=query.get("notice", [""])[0]).encode())
        elif path in {"/intelligence", "/intelligence/ics"}:
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            render=ics_advisories_page if path=='/intelligence/ics' else intelligence_page
            kwargs = {'notice': query.get('notice', [''])[0]} if path == '/intelligence' else {}
            self._send(render(self.store, query.get("q", [""])[0], page_number, **kwargs).encode())
        elif path == "/network":
            query = parse_qs(urlparse(self.path).query)
            try:
                page_number = int(query.get("page", ["1"])[0])
            except ValueError:
                page_number = 1
            self._send(network_page(self.store, page_number, query.get('notice',[''])[0]).encode())
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
            self._send(self.store.report("markdown", language=request_language(self.headers)).encode(), "text/markdown; charset=utf-8", download="phylax-report.md")
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
            content_type = self.headers.get('Content-Type', '')
            parts = None
            if content_type.split(';', 1)[0].strip().casefold() == 'multipart/form-data':
                parts = multipart_fields(raw, content_type)
                token_part = parts.get('csrf_token')
                token = token_part.get_payload(decode=True).decode('utf-8', 'replace') if token_part and token_part.get_filename() is None else ''
            else:
                token = parse_qs(raw.decode('utf-8', 'replace')).get('csrf_token', [''])[0]
            if not valid_token(token,self.csrf_token):
                self._send(b'Invalid or expired form token. Reload the dashboard and retry.','text/plain; charset=utf-8',403)
                return
            path = urlparse(self.path).path
            if path == '/language':
                values = parse_qs(raw.decode('utf-8','strict'), keep_blank_values=True)
                language = values.get('language', [''])[0]
                if language not in LANGUAGES:
                    raise ValueError('Unsupported language')
                destination = local_destination(values.get('next', ['/'])[0])
                self.send_response(303)
                self.send_header('Set-Cookie', COOKIE_NAME+'='+language+'; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax')
                self.send_header('Location', destination)
                self.end_headers()
                return
            if path in release_web.ACTIONS:
                values=parse_qs(raw.decode('utf-8','strict'),keep_blank_values=True)
                try:destination=release_web.post(self.store,path,values)
                except (ValueError,RuntimeError) as exc:
                    self._send(release_web.error_page(self.store,path,values,str(exc)).encode(),status=400)
                    return
                self.send_response(303);self.send_header('Location',destination);self.end_headers();return
            if path == '/assist':
                values = parse_qs(raw.decode('utf-8', 'strict'), keep_blank_values=True)
                try:
                    destination, body = assistant_web.submit_assistance(self.store, self.server.jobs, values, request_language(self.headers))
                except (ValueError, RuntimeError) as exc:
                    body = assistant_web.error_page(self.store, values, str(exc))
                    self._send(body.encode(), status=400)
                    return
                if body is not None:
                    self._send(body.encode())
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
                if form.get('preview'):
                    job_id = assistant_web.apply_preview(self.server.jobs, form['preview'][0])
                else:
                    policy=validate_policy(read_json_limited(form.get('policy_json',[''])[0].encode(),max_bytes=100000))
                    job_id=self.server.jobs.submit('Reevaluate passive network policy',lambda store,update:str(reevaluate_events(store,policy)))
                self.send_response(303);self.send_header('Location','/jobs/'+job_id);self.end_headers()
                return
            elif path == "/remediation/update":
                form = parse_qs(raw.decode("utf-8", "replace"))
                finding_id = form.get("finding_id", [""])[0]
                self.store.update_remediation_plan(finding_id, form.get("status", [""])[0], reviewer=form.get("reviewer", [""])[0][:120], change_notes=form.get("change_notes", [""])[0][:2000], verification_evidence=form.get("verification_evidence", [""])[0][:4000])
                notice = "Remediation lifecycle updated and recorded. Finding applicability and risk are unchanged."
            elif path in {"/assets/import", "/intelligence/import", "/network/import", "/software/wazuh"}:
                if parts is None:
                    raise ValueError("Expected a multipart file upload")
                def upload_text(name):
                    field = parts.get(name)
                    return field.get_payload(decode=True).decode('utf-8') if field else ''
                part = parts.get('file')
                if not part:
                    raise ValueError("Uploaded file is missing")
                body = part.get_payload(decode=True)
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
                    policy_part = parts.get('policy')
                    policy = None
                    if policy_part:
                        policy_body = policy_part.get_payload(decode=True)
                        if policy_body:
                            policy = validate_policy(read_json_limited(policy_body, max_bytes=100_000))
                    filename = part.get_filename() or ''
                    original_name = filename.replace('\\', '/').rsplit('/', 1)[-1] if 0 < len(filename) <= 255 else 'conn.log'
                    with tempfile.TemporaryDirectory(prefix="phylax-upload-") as temp:
                        uploaded = Path(temp) / 'input'
                        uploaded.write_bytes(body)
                        if path == '/software/wazuh':
                            result = import_wazuh(self.store, uploaded, source_file=original_name, **{
                                key: upload_text(key) for key in ('manager','agent_id','asset_id','kind')})
                        else:
                            kind = upload_text('kind') or infer_zeek_kind(original_name)
                            if kind not in {'conn','modbus','dhcp','software','modbus-identity'}:
                                raise ValueError('Unsupported Zeek log kind')
                            result = ingest_file(self.store, uploaded, kind=kind, policy=policy, source_file=original_name)
                    notice = f"Network analysis: {result['events_inserted']} events, {result['alerts_created']} alerts, {result['duplicates_skipped']} duplicates. " + "; ".join(result["diagnostics"][:3])
                    if 'records_skipped' in result:
                        notice = f"Import complete: {result['events_inserted']} imported, {result['duplicates_skipped']} duplicates, {result['records_skipped']} skipped."
            else:
                self._send(b"Not found", "text/plain; charset=utf-8", 404)
                return
            self.send_response(303)
            destination = {'/assets/import': '/assets', '/assets/save': '/assets',
                           '/intelligence/import': '/intelligence', '/network/import': '/network',
                           '/software/wazuh': '/software', '/correlate': '/settings'}.get(path, '/')
            parameters = {'notice':notice}
            if path == '/remediation/update':
                destination = '/remediation'
                parameters = {'finding_id':finding_id,'notice':notice}
            destination += '?'+urlencode(parameters)
            self.send_header("Location", destination)
            self.end_headers()
        except (ValueError, UnicodeDecodeError, RuntimeError, TimeoutError, RecursionError) as exc:
            path=urlparse(self.path).path
            values=parse_qs(raw.decode('utf-8','replace'),keep_blank_values=True) if 'parts' in locals() and parts is None else {}
            submitted={k:v[0] for k,v in values.items() if v and k!='csrf_token'}
            if path=='/assets/save':
                body=inventory_form(self.store,submitted.get('asset_id',''),submitted=submitted,error=str(exc))
            elif path == '/assets/import':
                body = assets_page(self.store, notice=f'Input error: {exc}')
            elif path == '/intelligence/import':
                body = intelligence_page(self.store, notice=f'Input error: {exc}')
            elif path == '/network/import':
                body = network_page(self.store, notice=f'Input error: {exc}')
            elif path == '/software/wazuh':
                body = release_web.page(self.store, '/software', {}, error=str(exc))
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
