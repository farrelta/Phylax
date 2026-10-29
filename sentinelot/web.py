"""Small local-only operator dashboard built on Python's standard library."""

from __future__ import annotations

import html
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from .core import Store, read_json_limited


MAX_UPLOAD = 5_000_000


def page(store: Store, notice: str = "") -> str:
    data = store.dashboard()
    cards = [("Known assets", data["assets"]), ("Confirmed exposure", data["confirmed_assets"]), ("Potential matches", data["potential_assets"]), ("KEV findings", data["kev_findings"]), ("Unacknowledged alerts", data["unacknowledged_alerts"])]
    card_html = "".join(f'<article class="metric"><span>{html.escape(str(label))}</span><strong>{value}</strong></article>' for label, value in cards)
    rows = []
    for f in data["findings"]:
        evidence = "<br>".join(html.escape(x) for x in json.loads(f["evidence"]))
        missing = "<br>".join(html.escape(x) for x in json.loads(f["missing_evidence"])) or "None recorded"
        rows.append(f"""<tr><td><b>{html.escape(f['cve_id'])}</b><br>{'DEMO FIXTURE' if f['synthetic'] else html.escape(f['source'])}</td>
          <td>{html.escape(f['ip_address'])} {html.escape(f['hostname'])}<br>{html.escape(f['vendor'])} {html.escape(f['product'])} {html.escape(f['version'])}</td>
          <td><span class="pill">{html.escape(f['status'])}</span><br>{html.escape(f['priority'])} priority · {html.escape(f['severity'] or 'Unknown')} severity · KEV {'Yes' if f['kev'] else 'No'}</td>
          <td>{evidence}<br><small>Missing: {missing}</small></td>
          <td>{html.escape(f['summary'])}<br><small>{html.escape(f['mitigation'] or 'No mitigation guidance supplied.')}</small></td></tr>""")
    finding_table = "".join(rows) or '<tr><td colspan="5" class="empty">No findings yet. Import assets and load a local fixture to begin.</td></tr>'
    alerts = []
    for a in data["alerts"]:
        button = "Acknowledged" if a["acknowledged"] else f'<form method="post" action="/ack"><input type="hidden" name="alert_id" value="{html.escape(a["alert_id"])}"><button>Acknowledge</button></form>'
        alerts.append(f'<div class="alert"><div><b>{html.escape(a["severity"])} · {html.escape(a["alert_id"][:8])}</b><p>{html.escape(a["explanation"])}</p><small>{html.escape(a["created_at"])}</small></div>{button}</div>')
    alert_html = "".join(alerts) or '<p class="empty">No evidence-backed exposure alerts.</p>'
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
<a class="link" href="/report.json">Export JSON</a><a class="link" href="/report.csv">Export CSV</a><a class="link" href="/assets.csv">Export assets</a></div>
<div class="columns"><section class="panel"><div class="section-head"><h2>Exposure findings</h2></div><table><thead><tr><th>Intelligence</th><th>Affected asset</th><th>Assessment</th><th>Evidence</th><th>Summary / guidance</th></tr></thead><tbody>{finding_table}</tbody></table></section>
<section class="panel"><h2>Security alerts</h2>{alert_html}</section></div>
<footer>Urgency is a transparent rule-based priority; severity and applicability remain separate. KEV indicates catalog-listed exploitation, not an attack on this asset. Absence of a finding does not mean an asset is safe. Timestamps are stored in UTC.</footer></main></body></html>"""


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
            elif path == "/ack":
                form = parse_qs(raw.decode("utf-8", "replace"))
                if not self.store.acknowledge(form.get("alert_id", [""])[0]):
                    raise ValueError("Alert not found")
                notice = "Alert acknowledged."
            elif path in {"/assets/import", "/intelligence/import"}:
                boundary = self.headers.get("Content-Type", "").split("boundary=", 1)[-1].strip('"')
                if not boundary or not raw.startswith(("--" + boundary).encode()):
                    raise ValueError("Expected a multipart file upload")
                parts = raw.split(("--" + boundary).encode())
                part = next((p for p in parts if b"Content-Disposition" in p), b"")
                if b"\r\n\r\n" not in part:
                    raise ValueError("Uploaded file is missing")
                body = part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]
                if len(body) > MAX_UPLOAD:
                    raise ValueError("File is too large")
                if path == "/assets/import":
                    import io
                    result = self.store.import_csv(io.StringIO(body.decode("utf-8-sig")))
                    notice = f"Imported {result['imported']} asset rows; {len(result['errors'])} row errors. " + "; ".join(f"row {e['row']}: {e['error']}" for e in result["errors"][:5])
                else:
                    result = self.store.ingest_fixture(read_json_limited(body))
                    notice = f"Loaded {len(result['ingested'])} locally stored vulnerability record(s)."
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
