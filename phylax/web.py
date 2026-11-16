"""Small local-only operator dashboard built on Python's standard library."""

from __future__ import annotations

import html
import json
import os
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
from .remediation_presenter import alert_plan_card, plan_card
from .remediation import plan_finding_context
from .alert_fix_plans import plan_url as alert_plan_url, read_plan as read_alert_plan, save_plan as save_alert_plan
from .finding_views import finding_case
from .advisory_views import advisory_summary, passages, render_facts
from .operator_pages import inventory_form,policy_page,settings_page,reports_page
from .theme import layout, ring, status_marker, term, glossary_page, icon, kpi, spark, gauge
from .feeds import sync_store
from .monitoring import ingest_file, infer_zeek_kind, validate_policy, reevaluate_events
from .sensor_imports import import_wazuh
from .fingerprints import latest_fingerprint
from . import assistant_web, email_alerts, email_views, release_web
from .ui import (verbatim, field, select, table, pager, reference_links, evidence_url,
                 record_row, record_body, record_table)
from .topology import VIEWPORT_SCRIPT, alert_topology_url, render_alert_topology, render_topology, url as surface_url, values as surface_query
from .triage import asset_index, zone_alert, zone_pair, triage as triage_rows, alert_url
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


JOB_RETURN = {
    'Sync public sources': ('/intelligence', 'Return to intelligence'),
    'Reevaluate passive network policy': ('/policy', 'Return to network policy'),
    'Create investigation report': ('/reports', 'Return to reports'),
}


def action_notice(notice):
    if not notice:
        return ''
    attrs = 'class="notice error" role="alert"' if notice.startswith('Input error:') else 'class="notice" role="status"'
    return f'<p {attrs}>' + html.escape(notice) + '</p>'


def featured_connection(store):
    alert = zone_alert(store)
    if not alert:
        return ''
    source, destination = alert['source_ip'], alert['destination_ip']
    policy = alert['policy']
    assets = asset_index(store, (source, destination))

    def endpoint(address, zone):
        name = (assets.get(address, {}).get('hostname') or '').strip()
        return verbatim(name) if name else f'{verbatim(address)} ({html.escape(zone)})'

    source_label = endpoint(source, policy['source_zone'])
    destination_label = endpoint(destination, policy['destination_zone'])
    path = html.escape(alert_topology_url(alert['alert_id']), quote=True)
    return (
        '<section class="headline zone-alert" aria-label="Zone policy violation">'
        f'<p class="connection-summary"><b>{source_label} connected to {destination_label}.</b></p>'
        '<p>Your network rule disallows this connection.</p>'
        f'<small>{html.escape(zone_pair(policy))} · <span class="mono">{html.escape(source)} → '
        f'{html.escape(destination)}</span></small>'
        f'<a class="btn primary" href="{path}">See the connection</a></section>'
    )


def page(store: Store, notice: str = "", page_number: int = 1, finding_id: str = '') -> str:
    page_number = max(1,page_number)
    data = store.dashboard(limit=50,offset=(page_number-1)*50)
    if finding_id:
        finding=store.finding(finding_id)
        if not finding:raise ValueError('Finding not found')
        return finding_case(store,finding,kev_status(finding,data['source_health']),notice)
    groups = {}
    for f in data["findings"]:
        groups.setdefault(f["cve_id"], []).append(f)
    finding_headings = ("Device", "Zone", "Status", "Urgency")
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
        head = (f'<tr class="cve-head" role="row"><th role="columnheader" colspan="4" scope="colgroup">'
                f'<span class="mono">{html.escape(cve_id)}</span>'
                f'<span class="cve-sev">{html.escape(lead["severity"] or "severity unrated")} severity</span>'
                + (f'<span class="cve-kev">Known exploited</span>' if lead.get("kev") else '')
                + f'<span class="cve-count">{len(items)} device{"s" if len(items) != 1 else ""}</span>'
                + f'{advisory_meta}</th></tr>')
        device_rows = []
        for f in items:
            urgency = prioritize(f, f, f["status"])
            score_text = f"{urgency['score']} / 12" if urgency['score'] is not None else "not scored"
            finding_href = html.escape(urlencode({'finding_id': f['finding_id']}), quote=True)
            row_id = 'finding-' + f['finding_id']
            anchor = html.escape(row_id, quote=True)
            address = f'<span class="mono">{html.escape(f["ip_address"])}</span>'
            name = verbatim(f['hostname']) + ' · ' + address if f['hostname'] else address
            device_rows.append(record_row(finding_headings, (
                f'<span id="{anchor}-device">{name}</span>'
                f'<br><small>{verbatim(f["vendor"])} {verbatim(f["product"])} {verbatim(f["version"])}</small>'
                f'<br><a class="finding-review" href="/?{finding_href}#{anchor}" aria-describedby="{anchor}-device">Review finding</a>',
                f'{html.escape((f["zone"] or "unknown").upper())}<br><small>{html.escape(f["criticality"])} criticality</small>',
                status_marker(f['status']),
                f'<b>{html.escape(score_text)}</b> <small>{html.escape(f["priority"])}</small>',
            ), row_id=row_id))
        group_html.append(f'<tbody class="cve-group" role="rowgroup">{head}{"".join(device_rows)}</tbody>')
    finding_body = ''.join(group_html) or record_body(
        finding_headings, '', 'No findings yet. Import assets and load a local fixture to begin.')
    finding_table = record_table(finding_headings, finding_body, classes='findings grouped')
    alert_summary = (f'<p>{data["unacknowledged_alerts"]} unacknowledged alerts across vulnerability, network and device-management evidence.</p>'
                     '')
    health_html = "".join(f'<div class="alert"><div><b>{html.escape(source["source"])} · {html.escape(source["health"])}</b><br><small>Last success: {html.escape(source["last_success_at"] or "Never")} · {html.escape(source["message"])}</small></div></div>' for source in data["source_health"]) or '<p class="empty">No synchronization yet. Stored offline data remains available.</p>'
    updates_html = "".join(f'<div class="alert"><div><b>{html.escape(item["change_type"])} · {html.escape(item["cve_id"])}</b><br><small>{html.escape(item["source"])} · {html.escape(item["changed_at"])}<br>{verbatim(item["summary"])}</small></div></div>' for item in data["recent_intelligence"]) or '<p class="empty">No intelligence records stored yet.</p>'
    largest = data['findings_count']
    pager = (f'<a class="link" href="/?page={page_number-1}">Previous</a>' if page_number>1 else '')
    if page_number>1 or page_number*50 < largest:
        pager += f' <span class="muted">Page {page_number}</span> '
    if page_number*50 < largest:pager += f'<a class="link" href="/?page={page_number+1}">Next</a>'
    pager = f'<div class="controls">{pager}</div>' if pager.strip() else ''
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    total_assets, confirmed, possible, new_alerts = data["assets"], data["confirmed_assets"], data["potential_assets"], data["unacknowledged_alerts"]
    zone_card = featured_connection(store)
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
            chip="Act now" if confirmed else "", tone="bad", glyph="shield", color="red",
            empty="" if advisories_loaded else "No advisories loaded yet"),
        kpi("Possibly affected", possible, "should be checked", gauge(possible, total_assets, pct(possible), "high" if possible else ""),
            chip="To check" if possible else "", tone="warn", glyph="search", color="amber",
            empty="" if advisories_loaded else "No advisories loaded yet"),
        kpi("New alerts", new_alerts, "to review in Triage", spark(alert_days),
            chip="Review" if new_alerts else "", tone="info", href="/triage", glyph="bell", color="blue",
            empty="" if (advisories_loaded or logs_imported) else "No evidence imported yet"),
    ))
    scores = store.exposure_urgency()
    ranked = sorted((asset for asset in all_assets if asset['asset_id'] in scores),
                    key=lambda asset: (-scores[asset['asset_id']][0], asset['asset_id']))[:6]
    rank_rows = []
    for asset in ranked:
        score, priority = scores[asset['asset_id']]
        name = asset['hostname'] or asset['ip_address']
        address = f' · {verbatim(asset["ip_address"])}' if asset['hostname'] else ''
        zone = html.escape(exposure_zone(asset))
        tone = EXPOSURE_TONES[priority]
        rank_rows.append(
            f'<li><div class="row"><b>{score}/12</b><span>{verbatim(name)}{address} · {zone}</span></div>'
            f'<div class="bar"><i class="{tone}" style="width:{round(100 * score / 12)}%"></i></div></li>'
        )
    rank_html = ''.join(rank_rows) or '<li class="empty">No scored vulnerability findings yet.</li>'
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
        todo.append(("olive", "check", 0, "Nothing urgent right now", "No confirmed or new issues in the stored data. That does not prove the network is safe.", "/assets", "View devices"))
    minis = (("Known-exploited flaws", data["kev_findings"], "", "red", advisories_loaded),
             ("Network connections seen", data["communication_relationships"], "/attack-surface", "", logs_imported),
             ("Out-of-date data feeds", data["stale_sources"], "/settings", "amber", advisories_loaded))
    mini_html = '<div class="mini-strip">' + "".join(
        (f'<a class="mini" href="{href}">' if href else '<div class="mini">')
        + f'<span>{html.escape(label)}</span>'
        + (f'<b class="{tone if value else ""}">{value}</b>' if has_data else '<b class="none">no data</b>')
        + ('</a>' if href else '</div>')
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
    connections = store.connection.execute("""
        SELECT source_ip, destination_ip FROM network_events
        WHERE source_ip <> destination_ip
        GROUP BY source_ip, destination_ip
        ORDER BY MAX(timestamp) DESC, source_ip, destination_ip
    """)
    map_html = exposure_map(all_assets, scores, connections)
    events = []
    activity_rows, _ = triage_rows(store, limit=10)
    labels = {"exposure": "Vulnerability alert", "network": "Network policy", "endpoint": "Device management"}
    kinds = {"exposure": ("shield", "high"), "network": ("pulse", "info"), "endpoint": ("device", "gold")}
    for row in activity_rows:
        asset = row["context"]
        icon_name, icon_tone = kinds.get(row["category"], ("bell", ""))
        if row["urgency"]["priority"] == "critical":
            icon_tone = "crit"
        identifier = verbatim(row['cve_id']) + ' · ' if row.get('cve_id') else ''
        events.append((row["timestamp"], icon_name, icon_tone, labels.get(row["category"], "Alert"),
                       f'{identifier}{verbatim(asset.get("hostname") or row["ip"])} · {html.escape(row["timestamp"])}',
                       alert_url(row["alert_id"])))
    for item in data["recent_intelligence"][:4]:
        events.append((item["changed_at"], "update", "olive", "Advisory update",
                       f'{verbatim(item["cve_id"])} · {html.escape(item["change_type"])} · '
                       f'{html.escape(item["source"])} · {html.escape(item["changed_at"])}',
                       "/intelligence"))
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
<section class="cardx"><header><h2>Exposure map</h2></header>{map_html}<p class="muted exposure-key"><span class="unscored-dot" aria-hidden="true"></span> No urgency score · Numbered dots show vulnerability urgency out of 12.</p><p class="muted exposure-key">Lines show up to 24 recently observed connections between displayed devices. <a href="/attack-surface">Open network map</a></p><ul class="bars">{rank_html}</ul>
</section>
<section class="cardx"><header><h2>Recent activity</h2></header><ul class="feed">{feed_html}</ul></section>
</div></div>
<section class="cardx wide"><header><h2 id="findings">Exposure findings</h2><a class="aux" href="/reports">Full report {icon("arrow")}</a></header><div class="panel">{finding_table}</div></section>
<div class="cards three">
<section class="cardx"><header><h2>Alerts</h2><span class="aux">{data["network_events"]} network events</span></header><div class="card-body">{alert_summary}</div></section>
<section class="cardx"><header><h2>Intelligence sources</h2></header><div class="card-body">{health_html}</div></section>
<section class="cardx"><header><h2>Recent intelligence updates</h2><a class="aux" href="/intelligence">Open intelligence {icon("arrow")}</a></header><div class="card-body">{updates_html}</div></section>
</div>
<footer>Urgency is a transparent rule-based priority; severity and applicability remain separate. KEV indicates catalog-listed exploitation, not an attack on this asset. Absence of a finding does not mean an asset is safe. Timestamps are stored in UTC.</footer>"""
    if not total_assets:
        content=notice_html+zone_card+f'''<section class="setup-start"><h2>Start with your asset inventory</h2><p>No devices loaded yet. Add an asset or import a CSV with an IP address for each device. Unknown product and firmware information can stay blank.</p>
<p><a class="btn primary" href="/assets">Open device inventory</a></p>
<h3>Then build the evidence</h3><ol><li>Load cached advisories in <a href="/intelligence">Intelligence</a>.</li><li>Import Zeek logs in <a href="/network">Monitoring</a>.</li><li>Review applicability, missing evidence and policy alerts.</li></ol>
</section>'''
    return layout("Overview", content, "/", lead="Local inventory, recorded network activity, and stored intelligence.", heading="Security overview")


EXPOSURE_TONES = {"critical": "crit", "high": "high", "medium": "medium", "low": "low"}


def exposure_zone(asset):
    zone = (asset['zone'] or '').upper()
    return zone if zone in {'IT', 'DMZ', 'OT'} else 'Unknown zone'


def exposure_map(assets, scores, connections=()) -> str:
    """Group devices by inventory zone and show their highest vulnerability urgency."""
    import hashlib
    # Stagger the island centers without shifting the map between visits.
    zones = {'IT': (85, 86), 'DMZ': (207, 140), 'OT': (360, 72), 'Unknown zone': (526, 115)}
    counts = dict.fromkeys(zones, 0)
    for asset in assets:
        counts[exposure_zone(asset)] += 1
    # Scale the area by device count while keeping every shape inside its column.
    scales = {zone: (0.12 + 0.88 * count / (count + 4)) ** .5 for zone, count in counts.items()}
    contours = (
        'M-67 5Q-63 -13 -48 -29T-22 -48Q-8 -47 4 -36Q20 -30 36 -35Q61 -31 66 -11Q68 0 53 15T28 34Q15 53 -3 43Q-15 34 -34 39Q-57 33 -67 5Z',
        'M-55 -1Q-41 -13 -45 -28Q-32 -45 -13 -40Q5 -27 22 -32Q43 -36 52 -16Q49 -4 61 10Q62 28 38 31Q21 26 9 41Q-12 52 -31 34Q-53 33 -55 -1Z',
        'M-68 -10Q-60 -34 -37 -29Q-24 -29 -13 -44Q1 -51 16 -37Q30 -22 47 -27Q68 -17 66 8Q63 22 48 24Q30 21 26 37Q9 52 -12 38Q-25 27 -44 34Q-64 23 -68 -10Z',
        'M-53 -5Q-63 -24 -38 -31Q-22 -33 -12 -39Q3 -42 17 -29Q37 -21 48 -13Q61 5 43 20Q32 23 24 37Q8 51 -10 37Q-20 27 -34 32Q-55 23 -53 -5Z',
    )
    island_shapes = ''.join(
        f'<path transform="translate({cx} {cy}) scale({scales[zone]:.4f})" d="{shape}"/>'
        for (zone, (cx, cy)), shape in zip(zones.items(), contours)
    )
    labels = ''.join(
        f'<text class="zl" x="{cx}" y="{cy + 52 * scales[zone] + 14:.0f}" text-anchor="middle">{zone}</text>'
        for zone, (cx, cy) in zones.items()
    )
    markers = []
    positions = {}
    # Draw higher scores last so an overlapping marker cannot hide them.
    for asset in sorted(assets, key=lambda asset: scores.get(asset['asset_id'], (-1, ''))[0]):
        asset_id = asset['asset_id']
        name = asset['hostname'] or asset['ip_address']
        address = f' · {asset["ip_address"]}' if asset['hostname'] else ''
        zone = exposure_zone(asset)
        digest = hashlib.md5(asset_id.encode()).digest()
        cx, cy = zones[zone]
        x = cx + (digest[0] / 255 - .5) * 70 * scales[zone]
        y = cy + (digest[1] / 255 - .5) * 58 * scales[zone]
        ip = asset['ip_address']
        # Shared IPs do not establish which inventory identity sent the traffic.
        positions[ip] = (round(x), round(y)) if ip not in positions else None
        score, priority = scores.get(asset_id, (None, ''))
        tone = EXPOSURE_TONES[priority] if score is not None else 'unscored'
        radius = 3.5 if score is None else 4.5 + score * .9
        label = 'No urgency score' if score is None else f'Urgency {score} of 12'
        title = html.escape(f'{name}{address} · {zone} · {label}')
        marker = f'<circle class="mk mk-{tone}" cx="{x:.0f}" cy="{y:.0f}" r="{radius:.1f}"/>'
        if score is not None:
            marker += f'<text class="mk-num" x="{x:.0f}" y="{y - radius - 2:.0f}" text-anchor="middle">{score}</text>'
        markers.append(f'<g><title>{title}</title>{marker}</g>')
    links = []
    seen = set()
    for source, target in connections:
        start, end = positions.get(source), positions.get(target)
        pair = tuple(sorted((source, target)))
        if not start or not end or pair in seen:
            continue
        seen.add(pair)
        x1, y1 = start
        x2, y2 = end
        mid = (x1 + x2) / 2
        lift = min(32, abs(x2 - x1) * .1 + 9)
        links.append(f'<path class="map-connection" d="M{x1} {y1} Q{mid:g} {min(y1, y2)-lift:g} {x2} {y2}">'
                     f'<title>{html.escape(source)} · {html.escape(target)}</title></path>')
        if len(links) == 24:
            break
    return ('<svg class="map" viewBox="0 0 600 222" role="img" aria-label="Inventory devices and vulnerability urgency by zone">'
            '<defs><pattern id="island-dots" width="8" height="8" patternUnits="userSpaceOnUse">'
            '<circle class="dot" cx="2" cy="2" r="1.2"/></pattern>'
            f'<clipPath id="exposure-islands">{island_shapes}</clipPath></defs>'
            '<rect width="600" height="222" fill="url(#island-dots)" clip-path="url(#exposure-islands)"/>'
            f'{labels}{"".join(links)}{"".join(markers)}</svg>')


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

    device_headings = ('Device', 'Zone', 'Status', 'Make and model', 'Importance', 'Actions')

    def device_row(row):
        edit = '/assets/edit?' + urlencode({'asset_id': row['asset_id']})
        make = ' '.join(v for v in (row['vendor'], row['product'], row['version']) if v)
        make_html = verbatim(make) if make else '<span class="missing">Unknown</span>'
        if needs_identity(row):
            state = '<span class="state warn">Needs identifying</span>'
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
        return record_row(device_headings, (
            f'<b>{name}</b><small><span class="mono">{html.escape(row["ip_address"])}</span> · {html.escape(row["asset_type"] or "Unknown type")}</small>{more}',
            f'<span class="zone-badge zone-{html.escape(zone.lower())}" title="{html.escape(zone)} zone">{html.escape(zone[:3])}</span>',
            state,
            make_html,
            f'<span class="imp imp-{html.escape(importance)}">{html.escape(importance.capitalize())}</span>',
            f'<a class="btn" href="{html.escape(edit, quote=True)}">Edit</a>',
        ), cell_classes=('device', '', '', '', '', 'row-action'))

    body = record_body(device_headings, ''.join(device_row(row) for row in rows),
                       'No assets found. Import a CSV or add a device.')
    device_table = record_table(device_headings, body, classes='asset-inventory device-table')
    query = urlencode({"q": search, **({"identity_review":"yes"} if identity_review else {})})
    previous = f'<a class="link" href="/assets?{query}&page={page_number - 1}">Previous</a>' if page_number > 1 else ""
    next_link = f'<a class="link" href="/assets?{query}&page={page_number + 1}">Next</a>' if page_number * limit < total else ""
    clear_search = '/assets?identity_review=yes' if identity_review else '/assets'
    review_control = '<input type="hidden" name="identity_review" value="yes">' if identity_review else ''
    counts = store.dashboard()
    tabs = '<nav class="quick-tabs" aria-label="Device filter">'
    for label, enabled, count in (('All devices', False, counts['assets']),
                                   ('Needs identifying', True, counts['assets_needing_identity_review'])):
        filters = {'q': search} if search else {}
        if enabled:
            filters['identity_review'] = 'yes'
        href = '/assets' + ('?' + urlencode(filters) if filters else '')
        current = ' class="on" aria-current="page"' if identity_review == enabled else ''
        tabs += f'<a href="{html.escape(href, quote=True)}"{current}>{label} <span>{count}</span></a>'
    tabs += '</nav>'
    pages = f'<span class="muted">{total} devices · page {page_number}</span>{previous}{next_link}'
    upload = '''<form method="post" action="/assets/import" enctype="multipart/form-data">
<div><label for="asset-import-file">Inventory CSV</label>
<input id="asset-import-file" required name="file" type="file" accept=".csv,text/csv" aria-describedby="asset-import-hint">
<small id="asset-import-hint">Choose a CSV with one row per device and an IP address for each.</small></div>
<button>Import asset CSV</button></form>'''
    content = f"""{action_notice(notice)}<div class="toolbar">{tabs}<div class="toolbar-actions"><a class="btn" href="/assets.csv">Export CSV</a><a class="btn primary" href="/assets/edit">Add asset</a></div></div>
<form class="search-row" method="get" action="/assets"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search by name, address, vendor or product" aria-label="Search assets">{review_control}<button>Search</button>{f'<a href="{clear_search}">Clear search</a>' if search else ''}</form>
<details class="workflow"{' open' if notice.startswith('Input error:') else ''}><summary>Import inventory CSV</summary>{upload}</details>
<section class="panel">{device_table}</section>
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
    headings = ('Product and summary', 'Affected versions and action', 'Advisory and source')
    rows = []
    for item in records:
        sources = [entry['record'] for entry in store.vulnerability_provenance(item['cve_id'])
                   if entry['public_trusted'] and not entry['record'].get('synthetic')]
        if not sources:
            sources = [item | {'affected_products': json.loads(item['affected_products'])}]
        refs = json.loads(item.get("references_json", "[]"))
        products = list(dict.fromkeys(p['product'] for source in sources for p in (source.get('affected_products') or [])
                                      if p.get('product')))
        title = verbatim(', '.join(products[:3])) if products else 'Product name unavailable'
        facts = passages(sources)
        scope = render_facts(facts)
        mitigation = item['mitigation']
        if mitigation and not any(label == 'Fixed versions or recommended action' and value == mitigation
                                  for label, value, _, _ in facts.values()):
            scope += '<details><summary>Stored mitigation guidance</summary><p>' + verbatim(mitigation) + '</p></details>'
        metadata = (f'{html.escape(item["severity"] or "Unknown")} severity'
                    + (f' · CVSS {html.escape(str(item["cvss"]))}' if item['cvss'] is not None else '')
                    + f'<br>KEV {"Yes" if item["kev"] else "No"}<br>'
                    + f'Published {html.escape(item["published"] or "Unknown")}<br>'
                    + f'Modified {html.escape(item["modified"] or "Unknown")}<br>'
                    + f'Retrieved {html.escape(item["retrieved_at"])}')
        rows.append(record_row(headings, (
            f'<strong>{title}</strong><p>{verbatim(item["summary"])}</p>',
            scope,
            f'<b class="mono">{html.escape(item["cve_id"])}</b><br>{verbatim(item["source"])}'
            + '<p>' + (reference_links(refs or ([item['source_url']] if item['source_url'] else [])) or 'No reference supplied') + '</p>'
            + '<details><summary>Technical details</summary><p>' + metadata + '</p></details>',
        )))
    advisory_table = record_table(headings, record_body(headings, ''.join(rows), 'No intelligence records found.'))
    pager = _pager("/intelligence", search, page_number, total, limit)
    offline = f"""<details class="workflow"{' open' if notice.startswith('Input error:') else ''}><summary>Import offline advisory</summary>
<form method="post" action="/intelligence/import" enctype="multipart/form-data">
<label>Offline advisory JSON<input name="file" type="file" accept=".json,application/json" required></label>
<button>Import advisory JSON</button></form></details>"""
    content = f"""{action_notice(notice)}<div class="controls"><form method="get" action="/intelligence"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search CVE, summary, source" aria-label="Search intelligence"> <button>Search</button></form><form method="post" action="/sync"><button>Sync public sources</button></form>{pager}</div>{offline}
<section class="panel">{advisory_table}</section>"""
    return layout("CVE intelligence", content, "/intelligence", lead="Normalized CVE records are cached locally. Product/version applicability remains subject to source evidence and the documented matcher limits.")


def ics_advisories_page(store: Store, search: str = '', page_number: int = 1) -> str:
    page_number=max(1,page_number);limit=50
    records,total=store.search_ics_advisories(search,limit=limit,offset=(page_number-1)*limit)
    headings = ('Advisory', 'Affected versions and action', 'Advisory and source')
    rows = ''.join(record_row(headings, (
        '<strong>' + verbatim(row['title']) + '</strong>' + advisory_summary(row['summary']),
        render_facts(passages([row | {'source_url': row['link']}], ics=True)),
        '<p>Published ' + html.escape(row['published'] or 'Unknown') + '</p>' + reference_links([row['link']]),
    )) for row in records)
    empty='No advisories match this search.' if search else 'No CISA ICS advisories stored. Sync public sources to load the advisory feed.'
    controls=f'''<div class="controls"><form method="get" action="/intelligence/ics"><input name="q" value="{html.escape(search,quote=True)}" placeholder="Search advisory, product or summary" aria-label="Search CISA ICS advisories"> <button>Search</button></form>{_pager('/intelligence/ics',search,page_number,total,limit)}</div>'''
    content = controls + '<section class="panel">' + record_table(headings, record_body(headings, rows, empty)) + '</section>'
    return layout('CISA ICS advisories',content,'/intelligence/ics',lead='Cached advisory feed entries for operator review. Check the original advisory for version scope.')


def network_page(store: Store, page_number: int = 1, notice: str = '') -> str:
    page_number = max(1, page_number)
    limit = 50
    events, total = store.recent_network_events(limit=limit, offset=(page_number - 1) * limit)
    headings = ('When', 'From → to', 'What happened', 'Alert')
    names = asset_index(store, (row[side] for row in events for side in ('source_ip', 'destination_ip') if row[side]))

    def endpoint(address):
        name = names.get(address, {}).get('hostname')
        return verbatim(name or address or 'Unknown') + (f'<small>{verbatim(address)}</small>' if name else '')

    def event_row(row):
        when = re.sub(r'\.0+(?=Z|$)', '', row['timestamp']).replace('T', ' ').replace('Z', ' UTC')
        record = html.escape(evidence_url(row['event_ref'], '/network?page=' + str(page_number)), quote=True)
        what = ' · '.join(v for v in (row['protocol'], row['event_type'], row['operation']) if v)
        notes = '; '.join(json.loads(row['diagnostics_json'] or '[]'))
        rules = ', '.join(rule.replace('_', ' ').capitalize() for rule in (row['rule_ids'] or '').split(',') if rule)
        alert = (f'<span class="flag">{html.escape(rules)}</span>' if rules
                 else '<span class="muted">No active rule alert</span>')
        return record_row(headings, (
            f'<span class="nw">{html.escape(when)}</span><small><a href="{record}">Original event</a></small>',
            f'{endpoint(row["source_ip"])}<span class="arrow" aria-hidden="true"> → </span>{endpoint(row["destination_ip"])}'
            f'<small>port {html.escape(str(row["source_port"] or "–"))} → {html.escape(str(row["destination_port"] or "–"))}</small>',
            html.escape(what),
            alert + f'<small>{html.escape(notes)}' + (' · ' if notes else '') + f'{verbatim(row["source_file"])}</small>',
        ))

    rows = record_body(headings, ''.join(event_row(row) for row in events),
                       'No network activity yet. Upload a Zeek log above to get started.')
    event_table = record_table(headings, rows, classes='events-table')
    pager = _pager("/network", "", page_number, total, limit)
    kind = select('kind','Zeek log kind',[('','Detect from file name'),('conn','Connections'),('modbus','Modbus operations'),
        ('modbus-identity','Modbus device identification'),('dhcp','DHCP'),('software','Software')])
    banner = action_notice(notice)
    upload = f"""<section class="cardx upload-card" id="network-import"><div class="upload-text"><h2>Add a network log</h2>
<p>Choose a log file exported by Zeek, for example <span class="mono">conn.log</span> or <span class="mono">modbus.log</span>. Phylax uses the saved network policy to check imported activity.</p></div>
<form method="post" action="/network/import" enctype="multipart/form-data"><label class="file-pick"><span>Log file</span><input required name="file" type="file" accept=".log,.json,.jsonl,.tsv"></label>
<details class="more"><summary>More options</summary>{kind}<small>Phylax can usually tell the type from the file name.</small></details>
<button class="primary">Import Zeek log</button></form></section>"""
    traffic = f'<section class="cardx wide"><header><h2>Recorded traffic</h2><span class="aux">{pager}</span></header><div class="panel">{event_table}</div></section>'
    content = banner + (upload + traffic if not events or notice.startswith('Input error:') else traffic + upload)
    return layout("Network events", content, "/network", lead="Import Zeek logs or review recorded network activity.", heading="Passive network monitoring")


def attack_surface_page(store: Store, query=None, *, filter_error='') -> str:
    query=query or {}
    alert_id=query.get('alert',[''])[0]
    if alert_id:
        return layout('Alert topology', render_alert_topology(store, zone_alert(store, alert_id)), '/attack-surface',
                      heading='Alert topology')
    params=surface_query(query)
    filter_keys={'subnet','zone','criticality','management_status','since','until','node'}
    filters={k:v for k,v in params.items() if k in filter_keys}
    active_filters={k:v for k,v in filters.items() if v}
    data=store.attack_surface({} if filter_error else filters)
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

    node_headings = ('Address', 'Identity and product', 'Zone / criticality / confidence / visibility', 'Inventory last seen')
    nodes = ''.join(record_row(node_headings, (
        asset_link(n), verbatim(n['identity']) + '<br><small>' + esc(n['asset_type']) + ' · '
        + verbatim(' '.join(str(n[k]) for k in ('vendor', 'product', 'version'))) + '</small>',
        esc(n['zone']) + ' zone · ' + esc(n['criticality']) + ' criticality<br>'
        + esc(n['identity_confidence']) + ' confidence · ' + ('verified' if n['verified'] else 'unverified')
        + '<br><small>' + esc(n['visibility']) + '</small>',
        timestamp(n['last_seen']),
    ), cell_classes=('nw mono',)) for n in visible_nodes)
    assets_table = ('<section class="panel">' + record_table(node_headings, record_body(node_headings, nodes, ''))
                    + '</section>') if nodes else (
        '<p class="empty">' + ('No endpoints match these surface filters. Widen or clear the filters.' if active_filters
                              else 'No inventory assets or imported network observations yet. Import inventory or Zeek logs to begin.') + '</p>')
    edge_headings = ('Relationship', 'Observed ports', 'Protocol / operation', 'Time / evidence')
    edges = []
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
        edges.append(record_row(edge_headings, (
            source + ' → ' + destination,
            esc(row['source_port'] if row['source_port'] is not None else 'unknown') + ' → '
            + esc(row['destination_port'] if row['destination_port'] is not None else 'unknown'),
            metadata,
            timestamp(row['first_seen']) + '<br>to ' + timestamp(row['last_seen']) + '<br><small>'
            + esc(row['event_count']) + ' event(s)</small><br>' + evidence,
        )))
    communication = ('<section class="panel">' + record_table(edge_headings, record_body(edge_headings, ''.join(edges), ''))
                     + '</section>') if edges else (
        '<p class="empty">' + ('No communication relationships match these filters. Widen or clear the filters; missing traffic does not establish absence.'
                              if active_filters else 'No communication relationships have been observed in imported logs. Import Zeek logs to add communication evidence.') + '</p>')
    inventory_only=[n for n in visible_nodes if not n.get('ever_observed',n['observed'])]
    inventory_count=sum(not n.get('ever_observed',n['observed']) for n in data['nodes'])
    inventory_table=table(inventory_only,[('ip_address','Address'),('identity','Identity'),('zone','Zone'),('visibility','Visibility')],
                          actions=lambda n:asset_link(n,'Inspect asset')) if inventory_only else (
                          '<p class="empty">'+('No inventory-only assets on this page.' if inventory_count else 'No inventory assets without imported traffic in this view.')+'</p>')

    keep=''.join('<input type="hidden" name="'+esc(k)+'" value="'+esc(v)+'">' for k,v in params.items()
                 if k in {'q','selected','zoom','processes'})
    controls='<details class="workflow" id="surface-filters"'+(' open' if filter_error else '')+'><summary>Filter recorded connections'+(' · '+str(len(active_filters))+' active' if active_filters and not filter_error else '')+'</summary><form method="get" action="/attack-surface#topology">'+keep
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
    error=('<p class="notice error" role="alert">'+esc(filter_error)+' <a href="#surface-filters">Review filters</a></p>') if filter_error else ''
    content=error + render_topology(store,data,{} if filter_error else query) + controls
    content+='<details class="workflow"><summary>Network evidence</summary><p class="muted">'+esc(counts)+'. Visibility is limited to imported logs. Unknown peers and missing metadata remain unknown. Unseen traffic is not evidence of absence. A recorded connection does not prove a firewall permits other traffic between these networks.</p>'
    content+='<details class="workflow"><summary>Inventory without observed traffic · '+str(inventory_count)+' assets</summary>'+inventory_table+'<p class="muted">This list follows the asset table page below. These assets have no imported traffic across all stored times; this does not mean a device is offline or removed.</p></details>'
    content+='<details class="workflow"><summary>Assets and peers · '+str(total_nodes)+' endpoints</summary>'+assets_table+'<p class="muted">Find asset or peer locates endpoints across this eligible inventory and peer list; it does not narrow the list.</p></details>'
    content+=pager('/attack-surface',{k:[v] for k,v in params.items()},surface_page_number,total_nodes,100)
    content+='<h2>Observed communication</h2>'+communication
    process_rows=[{**r,'relationship_type':'Operator-confirmed support'} for r in data['process_links']]
    content+='<h2>Operator-confirmed process support</h2>'+(table(process_rows,[('ip_address','Asset address'),('name','Supported process'),('relationship_type','Relationship'),('actor','Confirmed by'),('note','Evidence')]) if process_rows else '<p class="empty">No operator-confirmed process support in this view.</p>')
    content+='<p class="muted">Time filters apply to observations, not inventory or confirmed process support.</p></details>'
    return layout("Attack surface", content, "/attack-surface", lead="Inventory identity joined with relationships from imported Zeek logs. The map shows recorded traffic.", heading="Passive attack surface")


def remediation_page(store: Store, page_number: int = 1, *, finding_id='', category='', alert_id='', submitted=None,error='',notice='') -> str:
    page_number=max(1,page_number)
    if submitted:
        finding_id = submitted.get('finding_id', finding_id)
        category = submitted.get('category', category)
        alert_id = submitted.get('alert_id', alert_id)

    def render_finding(finding_key):
        selected=store.get_remediation_plan(finding_key)
        finding=store.finding(finding_key)
        if not selected or not finding:raise ValueError('Remediation plan not found')
        item=selected | {key:finding[key] for key in ('cve_id','hostname','ip_address')} | plan_finding_context(finding)
        return plan_card(item, submitted, error)

    pager = ''
    if alert_id or category:
        body = alert_plan_card(read_alert_plan(store, category, alert_id), submitted, error)
        pager = '<p><a href="/remediation">All remediation plans</a></p>'
    elif finding_id:
        body = render_finding(finding_id)
        target = '/?' + urlencode({'finding_id': finding_id}) + '#finding-' + finding_id
        pager = '<p><a href="/remediation">All remediation plans</a> · <a href="'+html.escape(target, quote=True)+'">Back to finding</a></p>'
    else:
        rows=store.connection.execute('''SELECT 'exposure' AS category,finding_id AS subject,updated_at FROM remediation_plans
            UNION ALL SELECT category,alert_id,updated_at FROM alert_fix_plans ORDER BY updated_at DESC,category,subject
            LIMIT 51 OFFSET ?''', ((page_number-1)*50,)).fetchall()
        body=''.join(render_finding(row['subject']) if row['category'] == 'exposure' else
                     alert_plan_card(read_alert_plan(store, row['category'], row['subject'])) for row in rows[:50])
        if page_number>1:pager=f'<a href="/remediation?page={page_number-1}">Previous</a> '
        if len(rows)==51:pager+=f'<a href="/remediation?page={page_number+1}">Next</a>'
    body = pager + body if body else pager + '<section class="panel empty">No remediation plans yet. <a href="/triage">Open an alert</a> to start a plan.</section>'
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
            language_form = language_control(self.path, language)
            control = '<div class="topbar">'+chip+language_form+'</div>'
            markup = markup.replace('<div class="mobile-language"></div>',
                                    '<div class="mobile-language">'+language_form+'</div>', 1)
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
        if getattr(self, 'public', False):
            return True
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
            try:self._send(release_web.page(self.store,path,parse_qs(urlparse(self.path).query),
                                            public=getattr(self,'public',False)).encode())
            except ValueError as exc:self._send(str(exc).encode(),'text/plain; charset=utf-8',400)
            return
        if path == "/":
            notice = parse_qs(urlparse(self.path).query).get("notice", [""])[0]
            try: page_number=int(parse_qs(urlparse(self.path).query).get("page",["1"])[0])
            except ValueError: page_number=1
            try:self._send(page(self.store,notice,page_number,parse_qs(urlparse(self.path).query).get('finding_id',[''])[0]).encode())
            except ValueError as exc:self._send(layout('Finding unavailable','<p>'+html.escape(str(exc))+'</p><a href="/">Return to overview</a>','/').encode(),status=404)
        elif path == '/assist':
            values = parse_qs(urlparse(self.path).query)
            destination = assistant_web.legacy_destination(self.store, values)
            if destination:
                self.send_response(303)
                self.send_header('Location', destination)
                self.end_headers()
                return
            try:self._send(assistant_web.assistance_page(self.store, values).encode())
            except ValueError as exc:self._send(layout('Assistance unavailable', '<p>'+html.escape(str(exc))+'</p><a href="/">Return to overview</a>').encode(), status=400)
        elif path.startswith('/jobs/'):
            job = self.server.jobs.get(path.rsplit('/',1)[-1])
            if not job:
                self._send(b'Job not found','text/plain; charset=utf-8',404)
                return
            refresh = '<meta http-equiv="refresh" content="2">' if job['status'] in {'queued','running'} else ''
            running = job['status'] in {'queued', 'running'}
            back, back_label = JOB_RETURN.get(job['label'], ('/', 'Return to overview'))
            if 'result' in job:
                body = layout(job['label'], assistant_web.result_content(job['result'], job['job_id']), '/reports')
            else:
                body = layout(job["label"], f'<p class="lead">{html.escape(job["message"])}</p><dl class="stats"><div><dt>Status</dt><dd>{html.escape(job["status"])}</dd></div><div><dt>Updated</dt><dd>{html.escape(str(job["updated_at"]))}</dd></div></dl>' + ('<p class="muted">This page refreshes every 2 seconds while the task is running.</p>' if running else
                    '<p><a class="btn" href="'+html.escape(back, quote=True)+'">'+back_label+'</a></p>'), "").replace("<title>", refresh + "<title>", 1)
            self._send(body.encode())
        elif path == '/assets/edit':
            try:
                query = parse_qs(urlparse(self.path).query)
                self._send(inventory_form(self.store, query.get('asset_id', [''])[0], notice=query.get('notice', [''])[0]).encode())
            except ValueError as exc:self._send(str(exc).encode(),'text/plain; charset=utf-8',400)
        elif path == '/glossary':
            self._send(glossary_page().encode())
        elif path == '/policy':
            self._send(policy_page(self.store).encode())
        elif path == '/settings':
            query = parse_qs(urlparse(self.path).query)
            self._send(settings_page(self.store, notice=query.get('notice', [''])[0],
                                     public=getattr(self,'public',False)).encode())
        elif path == '/email-alerts/preview':
            if email_alerts.public_disabled(public=getattr(self,'public',False)):
                self._send(b'Not found', status=404, content_type='text/plain; charset=utf-8')
                return
            query = parse_qs(urlparse(self.path).query)
            body = email_views.preview_page(self.store, query.get('alert', [''])[0], request_language(self.headers))
            if body is None:
                self._send(b'Email preview not found', status=404, content_type='text/plain; charset=utf-8')
            else:
                self._send(body.encode())
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
            query=parse_qs(urlparse(self.path).query)
            try:self._send(attack_surface_page(self.store,query).encode())
            except ValueError as exc:self._send(attack_surface_page(self.store,query,filter_error=str(exc)).encode(),status=400)
        elif path == "/remediation":
            query=parse_qs(urlparse(self.path).query)
            try: page_number=int(query.get("page",["1"])[0])
            except ValueError: page_number=1
            try:self._send(remediation_page(self.store,page_number,finding_id=query.get("finding_id",[""])[0],
                                            category=query.get('category',[''])[0],alert_id=query.get('alert_id',[''])[0],
                                            notice=query.get("notice",[""])[0]).encode())
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
            if origin and not getattr(self, 'public', False) and not valid_origin(origin,self.headers['Host'],self.server.server_address[1]):
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
            if path == '/email-alerts/retry':
                if email_alerts.public_disabled(public=getattr(self,'public',False)):
                    self._send(b'Not found', status=404, content_type='text/plain; charset=utf-8')
                    return
                alert_id = parse_qs(raw.decode('utf-8','strict')).get('alert',[''])[0]
                try:
                    email_alerts.retry(self.store, alert_id)
                except ValueError as exc:
                    self._send(settings_page(self.store, notice=str(exc)).encode(), status=400)
                    return
                self.send_response(303)
                self.send_header('Location', '/settings?' + urlencode({'notice':'Email queued for retry.'}) + '#email-alerts')
                self.end_headers()
                return
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
            elif path in {'/remediation/create','/remediation/update','/remediation/close'} and (
                     path == '/remediation/close' or parse_qs(raw.decode('utf-8','replace')).get('alert_id')):
                fields = {key: vals[0] for key, vals in parse_qs(raw.decode('utf-8','replace'), keep_blank_values=True).items()}
                action = path.rsplit('/', 1)[-1]
                save_alert_plan(self.store, action, fields)
                alert_id = fields['alert_id']
                if action == 'close':
                    destination = alert_url(alert_id)
                else:
                    notice = 'Fix plan draft saved.' if action == 'create' else 'Fix plan status updated.'
                    destination = alert_plan_url(fields['category'], alert_id, notice=notice)
                self.send_response(303);self.send_header('Location',destination);self.end_headers()
                return
            elif path == "/remediation/create":
                form = parse_qs(raw.decode("utf-8", "replace"))
                finding_id = form.get("finding_id", [""])[0]
                notice = generate_plan(self.store, finding_id,
                                       expected_plan_id=form.get('replace_plan_id', [''])[0],
                                       expected_plan_version=form.get('replace_plan_version', [''])[0])
                destination = '/remediation?' + urlencode({'finding_id': finding_id, 'notice': notice})
                self.send_response(303);self.send_header('Location',destination);self.end_headers()
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
                asset_id = form.get('asset_id', [''])[0]
                if asset_id:
                    self.send_response(303)
                    self.send_header('Location', '/assets/edit?' + urlencode({'asset_id': asset_id, 'notice': notice}))
                    self.end_headers()
                    return
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
                self.store.update_remediation_plan(finding_id, form.get("status", [""])[0], reviewer=form.get("reviewer", [""])[0][:120],
                                                   change_notes=form.get("change_notes", [""])[0][:2000], verification_evidence=form.get("verification_evidence", [""])[0][:4000],
                                                   expected_plan_id=form.get('plan_id', [''])[0], expected_plan_version=form.get('plan_version', [''])[0])
                notice = "Remediation lifecycle updated and recorded. Finding applicability and risk are unchanged."
            elif path in {"/assets/import", "/intelligence/import", "/network/import", "/software/wazuh"}:
                if parts is None:
                    raise ValueError("Expected a multipart file upload")
                def upload_text(name):
                    field = parts.get(name)
                    return field.get_payload(decode=True).decode('utf-8') if field else ''
                if path == '/software/wazuh':
                    wazuh_fields = {key: upload_text(key) for key in ('manager','agent_id','asset_id','kind')}
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
                            result = import_wazuh(self.store, uploaded, source_file=original_name, **wazuh_fields)
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
                body = release_web.page(self.store, '/software', {},
                                        submitted=locals().get('wazuh_fields', {'manager': ''}), error=str(exc))
            elif path=='/policy/apply':body=policy_page(self.store,submitted=submitted,error=str(exc))
            elif path.startswith('/remediation/') and submitted.get('alert_id'):
                try:body=remediation_page(self.store,submitted=submitted,error=str(exc))
                except ValueError:
                    body=release_web.page(self.store,'/triage',{'alert':[submitted['alert_id']]},error=str(exc),
                                          public=getattr(self,'public',False))
            elif path == '/remediation/create' and self.store.get_remediation_plan(submitted.get('finding_id', '')):
                body = remediation_page(self.store, finding_id=submitted['finding_id'], notice=str(exc))
            elif path == '/remediation/create' and self.store.finding(submitted.get('finding_id', '')):
                body = page(self.store, f"Input error: {exc}", finding_id=submitted['finding_id'])
            elif path=='/remediation/update' and self.store.get_remediation_plan(submitted.get('finding_id','')):
                body=remediation_page(self.store,submitted=submitted,error=str(exc))
            else:body=page(self.store,f"Input error: {exc}")
            self._send(body.encode(),status=400)

    def log_message(self, fmt: str, *args: object) -> None:
        # Keep the local console useful without logging request payloads or uploaded filenames.
        super().log_message(fmt, *args)


def serve(database: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    public = os.environ.get("PHYLAX_PUBLIC") == "1"
    if not public and host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Dashboard binds to loopback only (set PHYLAX_PUBLIC=1 for hosted deploy)")
    bind = "0.0.0.0" if public else ("127.0.0.1" if host == "localhost" else host)
    store = Store(database)
    Handler.store = store
    Handler.public = public
    # SQLite connection is intentionally confined to this single request thread.
    class LocalHTTPServer(HTTPServer):
        address_family=socket.AF_INET6 if host=="::1" and not public else socket.AF_INET
    server = LocalHTTPServer((bind, port), Handler)
    server.jobs = Jobs(database)
    notifications = email_alerts.EmailWorker(database, email_alerts.config(store, public=public))
    Handler.csrf_token = secrets.token_urlsafe(32)
    print(f"Phylax dashboard: http://{bind}:{port}" + (" (public)" if public else " (local-only)"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping Phylax dashboard")
    finally:
        server.server_close()
        notifications.close()
        server.jobs.close()
        store.close()
