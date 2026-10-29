"""Small local-only operator dashboard built on Python's standard library."""

from __future__ import annotations

import html
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from .core import Store, read_json_limited
from .feeds import sync_store
from .monitoring import ingest_file, validate_policy


MAX_UPLOAD = 5_000_000


def page(store: Store, notice: str = "") -> str:
    data = store.dashboard()
    cards = [("Known assets", data["assets"]), ("Confirmed exposure", data["confirmed_assets"]), ("Potential matches", data["potential_assets"]), ("KEV findings", data["kev_findings"]), ("Unacknowledged alerts", data["unacknowledged_alerts"])]
    card_html = "".join(f'<article class="metric"><span>{html.escape(str(label))}</span><strong>{value}</strong></article>' for label, value in cards)
    rows = []
    for f in data["findings"]:
        evidence = "<br>".join(html.escape(x) for x in json.loads(f["evidence"]))
        missing = "<br>".join(html.escape(x) for x in json.loads(f["missing_evidence"])) or "None recorded"
        references = ", ".join(json.loads(f["references_json"])) or "No references supplied"
        assessment_confidence = {"CONFIRMED_MATCH": "high", "NO_MATCH_TO_THIS_ADVISORY": "high", "POTENTIAL_MATCH": "medium", "NEEDS_REVIEW": "low"}.get(f["status"], "unknown")
        rows.append(f"""<tr><td><b>{html.escape(f['cve_id'])}</b><br>{'DEMO FIXTURE' if f['synthetic'] else html.escape(f['source'])}<br><small>Published {html.escape(f['published'] or 'Unknown')} · modified {html.escape(f['modified'] or 'Unknown')}<br>{html.escape(references)}</small></td>
          <td>{html.escape(f['ip_address'])} {html.escape(f['hostname'])}<br>{html.escape(f['vendor'])} {html.escape(f['product'])} {html.escape(f['version'])}<br><small>{html.escape(f['criticality'])} criticality · identity {html.escape(f['identity_confidence'])} · {html.escape(f['zone'])} zone</small></td>
          <td><span class="pill">{html.escape(f['status'])}</span><br>Assessment confidence: {assessment_confidence}<br>{html.escape(f['priority'])} priority · {html.escape(f['severity'] or 'Unknown')} severity · KEV {'Yes' if f['kev'] else 'No'}</td>
          <td>{evidence}<br><small>Missing: {missing}</small></td>
          <td>{html.escape(f['summary'])}<br><small>{html.escape(f['mitigation'] or 'No mitigation guidance supplied.')}</small></td></tr>""")
    finding_table = "".join(rows) or '<tr><td colspan="5" class="empty">No findings yet. Import assets and load a local fixture to begin.</td></tr>'
    alerts = []
    for a in data["alerts"]:
        button = "Acknowledged" if a["acknowledged"] else f'<form method="post" action="/ack"><input type="hidden" name="alert_id" value="{html.escape(a["alert_id"])}"><button>Acknowledge</button></form>'
        observed_asset = f" · asset {html.escape(a['destination_hostname'] or a['destination_asset_id'])}" if a.get("destination_asset_id") else ""
        evidence = f"<br><small>Rule: {html.escape(a['rule_id'])} · Event: {html.escape(a['event_ref'])} · {html.escape(a['source_ip'])} → {html.escape(a['destination_ip'])}{observed_asset} · {html.escape(a['event_timestamp'])}<br>Policy evidence: {html.escape(a['policy_evidence'])}</small>" if a.get("rule_id") else ""
        alerts.append(f'<div class="alert"><div><b>{html.escape(a["severity"])} · {html.escape(a["alert_id"][:8])}</b><p>{html.escape(a["explanation"])}</p>{evidence}<small>{html.escape(a["created_at"])}</small></div>{button}</div>')
    alert_html = "".join(alerts) or '<p class="empty">No evidence-backed exposure alerts.</p>'
    health_html = "".join(f'<div class="alert"><div><b>{html.escape(source["source"])} · {html.escape(source["health"])}</b><br><small>Last success: {html.escape(source["last_success_at"] or "Never")} · {html.escape(source["message"])}</small></div></div>' for source in data["source_health"]) or '<p class="empty">No synchronization yet. Stored offline data remains available.</p>'
    updates_html = "".join(f'<div class="alert"><div><b>{html.escape(item["change_type"])} · {html.escape(item["cve_id"])}</b><br><small>{html.escape(item["source"])} · {html.escape(item["changed_at"])}<br>{html.escape(item["summary"])}</small></div></div>' for item in data["recent_intelligence"]) or '<p class="empty">No intelligence records stored yet.</p>'
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"><title>Phylax</title>
<style>
:root{{--bg:#0a1118;--panel:#111d27;--line:#263744;--text:#edf5f7;--muted:#94a9b5;--mint:#63e0b4;--amber:#f3c66c}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 ui-sans-serif,system-ui,sans-serif}}header{{padding:24px max(24px,calc((100% - 1320px)/2));border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}}.brand{{font-size:20px;font-weight:750;letter-spacing:.02em}}.brand i{{color:var(--mint);font-style:normal}}.tag{{color:var(--muted);font-size:12px}}main{{max-width:1320px;margin:28px auto;padding:0 24px}}h1{{font-size:28px;margin:0 0 4px}}h2{{font-size:18px;margin:0 0 16px}}.sub{{color:var(--muted);margin:0 0 22px}}.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0 26px}}.metric,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}}.metric span{{display:block;color:var(--muted);font-size:13px}}.metric strong{{display:block;font-size:29px;margin-top:6px}}.columns{{display:grid;grid-template-columns:1.55fr 1fr;gap:16px;margin-bottom:18px}}form.inline{{display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap}}.toolbar{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}}input[type=file]{{max-width:230px;color:var(--muted)}}button,.link{{background:#17352f;color:var(--mint);border:1px solid #276050;border-radius:7px;padding:8px 12px;cursor:pointer;text-decoration:none;font-weight:650}}button:hover,.link:hover{{background:#214a3f}}table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;color:var(--muted);font-weight:600;padding:10px;border-bottom:1px solid var(--line)}}td{{padding:12px 10px;vertical-align:top;border-bottom:1px solid #1e2c36;max-width:310px}}small{{color:var(--muted)}}.pill{{display:inline-block;border:1px solid #4e5d3e;color:var(--amber);border-radius:20px;padding:2px 8px;font-size:11px}}.alert{{display:flex;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid var(--line)}}.alert p{{margin:4px 0}}.alert form{{align-self:center}}.empty{{color:var(--muted);padding:24px;text-align:center}}.notice{{background:#17352f;border:1px solid #276050;border-radius:8px;padding:12px;margin-bottom:12px}}.section-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}}footer{{color:var(--muted);font-size:12px;padding:20px 0 40px}}@media(max-width:900px){{.metrics{{grid-template-columns:repeat(2,1fr)}}.columns{{grid-template-columns:1fr}}}}@media(max-width:600px){{header{{padding:16px 20px}}main{{padding:0 16px}}table{{display:block;overflow:auto}}}}
</style><body><header><div class="brand"><i>◆</i> Phylax</div><div class="tag">LOCAL · PASSIVE · EVIDENCE FIRST</div></header><main>
{notice_html}<h1>Security overview</h1><p class="sub">Local inventory and stored intelligence. No active scanning or device control.</p>
<div class="metrics">{card_html}</div><div class="toolbar">
<form class="inline" method="post" action="/assets/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".csv,text/csv"><button>Import asset CSV</button></form>
<form class="inline" method="post" action="/intelligence/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".json,application/json"><button>Load offline fixture</button></form>
<form class="inline" method="post" action="/correlate"><button>Run correlation</button></form>
<form class="inline" method="post" action="/sync"><button>Sync public sources</button></form>
<form class="inline" method="post" action="/network/import" enctype="multipart/form-data"><input required name="file" type="file" accept=".log,.json,.tsv,text/plain"><input name="policy" type="file" accept=".json,application/json"><button>Analyze Zeek log</button></form>
<a class="link" href="/assets">Asset inventory</a><a class="link" href="/intelligence">Threat intelligence</a><a class="link" href="/network">Network monitoring</a><a class="link" href="/report.json">Export JSON</a><a class="link" href="/report.csv">Export CSV</a><a class="link" href="/assets.csv">Export assets</a></div>
<div class="columns"><section class="panel"><div class="section-head"><h2>Exposure findings</h2></div><table><thead><tr><th>Intelligence</th><th>Affected asset</th><th>Assessment</th><th>Evidence</th><th>Summary / guidance</th></tr></thead><tbody>{finding_table}</tbody></table></section>
<section class="panel"><h2>Security alerts · {data["network_events"]} network events</h2>{alert_html}<h2>Intelligence sources</h2>{health_html}<h2>Recent intelligence updates</h2>{updates_html}</section></div>
<footer>Urgency is a transparent rule-based priority; severity and applicability remain separate. KEV indicates catalog-listed exploitation, not an attack on this asset. Absence of a finding does not mean an asset is safe. Timestamps are stored in UTC.</footer></main></body></html>"""


def assets_page(store: Store, search: str = "", page_number: int = 1) -> str:
    page_number = max(1, page_number)
    limit = 50
    rows, total = store.search_assets(search, limit=limit, offset=(page_number - 1) * limit)
    body = "".join(f"""<tr><td>{html.escape(row['ip_address'])}<br><small>ID {html.escape(row['asset_id'])} · {html.escape(row['mac_address'] or 'MAC unknown')}</small></td><td>{html.escape(row['hostname'] or 'Unknown')}</td>
      <td>{html.escape(row['asset_type'])}<br><small>{html.escape(row['vendor'])} {html.escape(row['product'])} {html.escape(row['version'])}<br>{html.escape(row['operating_system'])}</small></td>
      <td>{html.escape(row['zone'])}<br>{html.escape(row['criticality'])}</td><td>{html.escape(row['identification_source'])}<br><small>{html.escape(row['identity_confidence'])} confidence · {'verified' if row['verified'] else 'unverified'}</small></td><td>{html.escape(row['last_seen'] or 'Unknown')}<br><small>{html.escape(row['notes'])}</small></td></tr>""" for row in rows) or '<tr><td colspan="6" class="empty">No assets found. Import a CSV from the overview.</td></tr>'
    query = urlencode({"q": search})
    previous = f'<a class="link" href="/assets?{query}&page={page_number - 1}">Previous</a>' if page_number > 1 else ""
    next_link = f'<a class="link" href="/assets?{query}&page={page_number + 1}">Next</a>' if page_number * limit < total else ""
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Phylax · Asset inventory</title>
<style>body{{margin:0;background:#0a1118;color:#edf5f7;font:15px/1.5 system-ui,sans-serif}}header,main{{max-width:1320px;margin:auto;padding:20px 24px}}header{{border-bottom:1px solid #263744;display:flex;justify-content:space-between}}a,button{{color:#63e0b4}}.brand{{font-size:20px;font-weight:750}}.panel{{background:#111d27;border:1px solid #263744;border-radius:12px;padding:18px;margin-top:20px}}table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;color:#94a9b5;padding:10px;border-bottom:1px solid #263744}}td{{padding:12px 10px;border-bottom:1px solid #1e2c36;vertical-align:top}}small,.muted{{color:#94a9b5}}input{{background:#0a1118;color:#edf5f7;border:1px solid #263744;border-radius:6px;padding:9px}}button,.link{{background:#17352f;color:#63e0b4;border:1px solid #276050;border-radius:7px;padding:8px 12px;text-decoration:none}}.controls{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}}.empty{{text-align:center;padding:24px;color:#94a9b5}}</style>
<body><header><a class="brand" href="/">◆ Phylax</a><a href="/">Overview</a></header><main><h1>Asset inventory</h1><p class="muted">Observed metadata remains separate from operator verification. Unknown identity is not inferred from an IP address.</p>
<div class="controls"><form method="get" action="/assets"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search IP, hostname, vendor, product"><button>Search</button></form><a class="link" href="/assets.csv">Export CSV</a><span class="muted">{total} assets · page {page_number}</span>{previous}{next_link}</div>
<section class="panel"><table><thead><tr><th>Address</th><th>Hostname</th><th>Type and identity</th><th>Zone / criticality</th><th>Source / confidence</th><th>Last seen / notes</th></tr></thead><tbody>{body}</tbody></table></section></main></body></html>"""


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
        rows.append(f"""<tr><td><b>{html.escape(item['cve_id'])}</b><br><small>{html.escape(item['source'])}</small></td>
        <td>{html.escape(item['severity'] or 'Unknown')} {('· CVSS ' + html.escape(str(item['cvss']))) if item['cvss'] is not None else ''}<br>KEV {'Yes' if item['kev'] else 'No'}<br><small>Published {html.escape(item['published'] or 'Unknown')}<br>Modified {html.escape(item['modified'] or 'Unknown')}<br>Retrieved {html.escape(item['retrieved_at'])}</small></td>
        <td>{html.escape(item['summary'])}<br><small>{html.escape(product_text)}</small></td><td>{html.escape(item['mitigation'] or 'No mitigation guidance supplied.')}<br><small>{html.escape('; '.join(refs) or item['source_url'] or 'No reference supplied')}</small></td></tr>""")
    advisory_rows = "".join(f"<tr><td>{html.escape(row['title'])}</td><td>{html.escape(row['published'] or 'Unknown')}</td><td>{html.escape(row['link'])}</td><td>{html.escape(row['summary'])}</td></tr>" for row in advisories) or '<tr><td colspan="4" class="empty">No CISA ICS advisories stored.</td></tr>'
    pager = _pager("/intelligence", search, page_number, total, limit)
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Phylax · Threat intelligence</title>
<style>body{{margin:0;background:#0a1118;color:#edf5f7;font:15px/1.5 system-ui,sans-serif}}header,main{{max-width:1320px;margin:auto;padding:20px 24px}}header{{border-bottom:1px solid #263744;display:flex;justify-content:space-between}}a,button{{color:#63e0b4}}.brand{{font-size:20px;font-weight:750}}.panel{{background:#111d27;border:1px solid #263744;border-radius:12px;padding:18px;margin-top:20px}}table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;color:#94a9b5;padding:10px;border-bottom:1px solid #263744}}td{{padding:12px 10px;border-bottom:1px solid #1e2c36;vertical-align:top;max-width:360px}}small,.muted{{color:#94a9b5}}input{{background:#0a1118;color:#edf5f7;border:1px solid #263744;border-radius:6px;padding:9px}}button,.link{{background:#17352f;color:#63e0b4;border:1px solid #276050;border-radius:7px;padding:8px 12px;text-decoration:none}}.controls{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}}.empty{{text-align:center;padding:24px;color:#94a9b5}}</style>
<body><header><a class="brand" href="/">◆ Phylax</a><a href="/">Overview</a></header><main><h1>Threat intelligence</h1><p class="muted">Normalized records are cached locally. Product/version applicability remains subject to source evidence and the documented matcher limits.</p>
<div class="controls"><form method="get" action="/intelligence"><input name="q" value="{html.escape(search, quote=True)}" placeholder="Search CVE, summary, source"><button>Search</button></form><form method="post" action="/sync"><button>Sync public sources</button></form>{pager}</div>
<section class="panel"><table><thead><tr><th>Identifier / source</th><th>Severity / status / dates</th><th>Summary / affected product data</th><th>Mitigation / references</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="4" class="empty">No intelligence records found. Sync sources or load the offline fixture.</td></tr>'}</tbody></table></section>
<h2>CISA ICS advisories</h2><p class="muted">Feed entries and references are retained for operator review; affected versions are not inferred from advisory text.</p><section class="panel"><table><thead><tr><th>Advisory</th><th>Published</th><th>Reference</th><th>Summary</th></tr></thead><tbody>{advisory_rows}</tbody></table></section></main></body></html>"""


def network_page(store: Store, page_number: int = 1) -> str:
    page_number = max(1, page_number)
    limit = 50
    events, total = store.recent_network_events(limit=limit, offset=(page_number - 1) * limit)
    rows = "".join(f"""<tr><td>{html.escape(row['timestamp'])}<br><small>{html.escape(row['event_ref'])}</small></td><td>{html.escape(row['source_ip'])}:{html.escape(str(row['source_port'] or ''))}<br>↓ {html.escape(row['destination_ip'])}:{html.escape(str(row['destination_port'] or ''))}</td><td>{html.escape(row['protocol'])} · {html.escape(row['event_type'])}<br>{html.escape(row['operation'])}</td><td>{html.escape(row['rule_ids'] or 'No rule alert')}<br><small>{html.escape(row['source_file'])}</small></td></tr>""" for row in events) or '<tr><td colspan="4" class="empty">No network events imported yet. Add Zeek conn.log or Modbus logs from the overview.</td></tr>'
    pager = _pager("/network", "", page_number, total, limit)
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Phylax · Network monitoring</title>
<style>body{{margin:0;background:#0a1118;color:#edf5f7;font:15px/1.5 system-ui,sans-serif}}header,main{{max-width:1320px;margin:auto;padding:20px 24px}}header{{border-bottom:1px solid #263744;display:flex;justify-content:space-between}}a{{color:#63e0b4}}.brand{{font-size:20px;font-weight:750}}.panel{{background:#111d27;border:1px solid #263744;border-radius:12px;padding:18px;margin-top:20px}}table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;color:#94a9b5;padding:10px;border-bottom:1px solid #263744}}td{{padding:12px 10px;border-bottom:1px solid #1e2c36;vertical-align:top}}small,.muted{{color:#94a9b5}}.link{{background:#17352f;color:#63e0b4;border:1px solid #276050;border-radius:7px;padding:8px 12px;text-decoration:none}}.controls{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}}.empty{{text-align:center;padding:24px;color:#94a9b5}}</style>
<body><header><a class="brand" href="/">◆ Phylax</a><a href="/">Overview</a></header><main><h1>Passive network monitoring</h1><p class="muted">Stored Zeek observations. This view does not capture live traffic or send packets to devices.</p><div class="controls"><a class="link" href="/">Import logs from overview</a>{pager}</div><section class="panel"><table><thead><tr><th>Timestamp / event reference</th><th>Source / destination</th><th>Protocol / operation</th><th>Detection / source file</th></tr></thead><tbody>{rows}</tbody></table></section></main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Phylax/0.1"
    store: Store

    def _send(self, body: bytes, content_type: str = "text/html; charset=utf-8", status: int = 200, download: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            notice = parse_qs(urlparse(self.path).query).get("notice", [""])[0]
            self._send(page(self.store, notice).encode())
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
        elif path == "/assets.csv":
            from io import StringIO
            out = StringIO()
            self.store.export_assets_csv(out)
            self._send(out.getvalue().encode(), "text/csv; charset=utf-8", download="sentinelot-assets.csv")
        elif path == "/report.json":
            self._send(self.store.report("json").encode(), "application/json; charset=utf-8", download="sentinelot-report.json")
        elif path == "/report.csv":
            self._send(self.store.report("csv").encode(), "text/csv; charset=utf-8", download="sentinelot-report.csv")
        else:
            self._send(b"Not found", "text/plain; charset=utf-8", 404)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_UPLOAD + 64_000:
                raise ValueError("Request is too large")
            raw = self.rfile.read(length)
            path = urlparse(self.path).path
            if path == "/correlate":
                result = self.store.correlate()
                notice = f"Correlation complete: {result or 'no matching records'}"
            elif path == "/sync":
                result = sync_store(self.store)
                self.store.correlate()
                notice = "Source sync results: " + "; ".join(f"{name}: {'ok, ' + str(item['records']) + ' records' if item['ok'] else 'unavailable (' + item['error'] + ')'}" for name, item in result.items())
            elif path == "/ack":
                form = parse_qs(raw.decode("utf-8", "replace"))
                if not self.store.acknowledge(form.get("alert_id", [""])[0]):
                    raise ValueError("Alert not found")
                notice = "Alert acknowledged."
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
                    policy = {}
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
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
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
    server = HTTPServer((host, port), Handler)
    print(f"Phylax dashboard: http://{host}:{port} (local-only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping Phylax dashboard")
    finally:
        server.server_close()
        store.close()
