"""Shared page chrome and stylesheet for every operator page.

Fonts are system stacks on purpose: the app is offline-first and its CSP
(default-src 'self') would block any web font.
"""
from __future__ import annotations
import html
import re
from urllib.parse import urlencode

NAV = (
    ("Workspace", (("/", "Dashboard"), ("/assets", "Devices"), ("/network", "Network"),
                   ("/intelligence", "Vulnerabilities"), ("/triage", "Alerts"),
                   ("/reports", "Reports"), ("/settings", "Settings"))),
)

# Keep bookmarked routes available within their operator task.
SECONDARY_NAV = {
    "/assets": ("Asset tools", (("/assets", "All devices"), ("/approvals", "Approvals"),
        ("/software", "Software"),
        ("/changes", "Changes"), ("/processes", "Owners and use"))),
    "/network": ("Monitoring views", (("/network", "Traffic"), ("/attack-surface", "Network map"))),
    "/intelligence": ("Intelligence views", (("/intelligence", "Known flaws"), ("/intelligence/ics", "Industrial advisories"))),
    "/triage": ("Triage views", (("/triage", "All alerts"), ("/remediation", "Fix plans"))),
    "/settings": ("Settings views", (("/settings", "Data sources"),
        ("/policy", "Network rules"), ("/glossary", "Glossary"))),
}


# Plain page names and one-sentence explanations, keyed by the page's internal title.
PAGE_GUIDE = {
    "Inventory": ("Devices", "Every device Phylax knows about. A device can only be checked for flaws once its vendor, product and version are filled in."),
    "Add asset": ("Add asset", "Fill in what you know. Fields you are unsure about can stay empty."),
    "Edit asset": ("Edit asset", "Correct or complete what is known about this device."),
    "Device management approvals": ("Device approvals", "Decide which devices are allowed on each monitored network. New unknown devices wait here for a decision."),
    "Software evidence and verification": ("Software on devices", "Software found on your devices, and whether a person has confirmed it."),
    "Asset change timeline": ("Device changes", "A history of what changed on each device, and who changed it."),
    "Operational context and processes": ("Owners and use", "Who is responsible for each device and which work depends on it."),
    "Network events": ("Network activity", "Traffic recorded in your network logs. Phylax only reads the files; it never sends anything to your devices."),
    "Attack surface": ("Network map", "Which devices talk to each other, based on recorded traffic."),
    "Alert topology": ("Network map", "Where this alert happened on the network."),
    "CVE intelligence": ("Known vulnerabilities", "Public security flaws Phylax has downloaded. They are compared with your devices automatically."),
    "CISA ICS advisories": ("Industrial advisories", "Security notices about industrial equipment, published by CISA."),
    "Unified security triage": ("Alerts", "Everything that needs a person to look at it. Open an alert to see why it was raised and what to do next."),
    "Remediation plans": ("Fix plans", "Suggested steps to fix a problem. Phylax never changes anything by itself; a person approves each plan."),
    "Reports": ("Reports", "Download what Phylax found, to share with your team or keep as a record."),
    "Settings and data sources": ("Settings", "Where Phylax gets its data from, and whether that data is up to date."),
    "Passive network policy": ("Network rules", "Which parts of the network may talk to each other. Traffic that breaks a rule becomes an alert."),
    "Glossary": ("Glossary", "Plain meanings of the words used in Phylax."),
    "Original event evidence": ("Original record", "The raw data an alert was based on, exactly as it was imported."),
    "Vulnerability finding": ("Vulnerability finding", "What was found, why it matters, and what to do about it."),
}


def globe() -> str:
    """Wireframe globe used for empty states."""
    lines = ['<circle cx="100" cy="100" r="78"/>']
    for k in (0.2, 0.45, 0.7, 0.9):
        lines.append(f'<ellipse cx="100" cy="100" rx="{78 * k:.1f}" ry="78"/>')
    for d in (-60, -35, -10, 15, 40, 62):
        half = (78 ** 2 - d ** 2) ** .5
        lines.append(f'<ellipse cx="100" cy="{100 + d}" rx="{half:.1f}" ry="{half * .18:.1f}"/>')
    dots = "".join(f'<circle class="node" cx="{100 + 78 * k * s:.1f}" cy="{100 + d}" r="1.6"/>'
                   for k, d in ((.45, -35), (.7, 15), (.2, 40), (.9, -10), (.45, 62), (.7, -60)) for s in (-1, 1))
    return f'<svg class="globe" viewBox="0 0 200 200" aria-hidden="true">{"".join(lines)}{dots}</svg>'


def _empty_states(body: str) -> str:
    body = re.sub(r'(<p class="empty">.*?</p>)', lambda m: '<div class="empty-state">' + globe() + m[1] + '</div>', body, flags=re.S)
    return re.sub(r'(<td colspan="[^"]*" class="empty">)(.*?)(</td>)',
                  lambda m: m[1] + '<div class="empty-state">' + globe() + '<p>' + m[2] + '</p></div>' + m[3], body, flags=re.S)


STATUS_CLASS = {
    "CONFIRMED_MATCH": "crit",
    "POTENTIAL_MATCH": "high",
    "NEEDS_REVIEW": "info",
    "NO_MATCH_TO_THIS_ADVISORY": "none",
}

CSS = """
.language-control{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin:0 0 18px}.language-control label{margin:0}.language-control select{width:auto;max-width:100%}
:root{color-scheme:dark;--bg:#070806;--surface:#0f110b;--raised:#15180f;--line:#252a1a;--text:#eef0e6;--muted:#9ea18c;--accent:#a3b35c;--accent-ink:#f3f5e6;--link:#bfcc85;--action:#556b2f;--action-hover:#64803a;--control-line:#454d33;--placeholder:#9ea18c;--control-hover:#1e2216;
--graph-edge:#6f877b;--graph-node:#13150f;--graph-process:#14170e;--zone-it:#a3b35c;--zone-ot:#e8923a;--zone-dmz:#5fb4e8;--zone-unknown:#7a8a82;
--crit:#ff5d5d;--high:#f0a03c;--info:#5fb4e8;--none:#7a8a82;--ok:#a3b35c;
--sans:"IBM Plex Sans","Segoe UI",Helvetica,Arial,sans-serif;--display:"Bahnschrift","Segoe UI Variable Display","Segoe UI",Helvetica,Arial,sans-serif;--mono:"IBM Plex Mono",ui-monospace,Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1000px 460px at 70% -12%,#2b301566,transparent 70%),var(--bg);color:var(--text);font:15px/1.55 var(--sans);display:grid;grid-template-columns:208px minmax(0,1fr);min-height:100vh}
::selection{background:#4b5320;color:#fff}input,textarea{caret-color:var(--link)}html{scrollbar-color:#4b5320 var(--bg)}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
aside{border-right:1px solid var(--line);padding:18px 0;position:sticky;top:0;height:100vh;overflow:auto}
.brand{display:flex;align-items:center;gap:10px;padding:0 18px 20px;color:var(--text)}
.brand:hover{text-decoration:none}
.brand svg{flex:none;width:30px;height:30px}
.brand .shield{fill:#a3b35c14;stroke:var(--accent);stroke-width:1.7;stroke-linejoin:round}
.brand .eye{fill:var(--accent)}
.brand b{display:block;font:700 17px/1 var(--display);letter-spacing:.2em;text-transform:uppercase}
.brand small{display:block;margin-top:5px;color:var(--muted);font:400 12px/1.4 var(--sans)}
aside .nav-group-label{margin:16px 18px 4px;color:var(--muted);font:600 12px var(--sans);text-transform:uppercase;letter-spacing:.08em}
aside nav a{display:block;padding:6px 18px;color:var(--text);border-left:2px solid transparent}
aside nav a:hover{background:var(--surface);text-decoration:none}
aside nav a[aria-current]{border-left-color:var(--accent);background:linear-gradient(90deg,#a3b35c1f,transparent);color:#fff}
.secondary-navigation{display:flex;flex-wrap:wrap;gap:4px 18px;margin:0 0 24px;border-bottom:1px solid var(--line)}
.secondary-navigation a{display:inline-flex;align-items:center;min-height:44px;padding:6px 0;color:var(--muted);border-bottom:2px solid transparent}
.secondary-navigation a[aria-current]{color:var(--text);border-bottom-color:var(--accent)}
main{padding:24px 32px 48px;min-width:0;max-width:1400px;overflow-wrap:anywhere}
h1{font:600 26px/1.15 var(--display);margin:0 0 6px;letter-spacing:.005em}
h2{font:500 12px var(--mono);text-transform:uppercase;letter-spacing:.08em;margin:30px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h2::before{content:"// ";color:var(--accent)}
.lead,.muted,small{color:var(--muted)}.lead{margin:0 0 18px;max-width:78ch}
small{font-size:13px}
.nw{white-space:nowrap}.asset-inventory td{overflow-wrap:anywhere}.asset-address small{display:block;margin:3px 0}.mono,td code{font-family:var(--mono);font-size:12px}
.stats{display:flex;flex-wrap:wrap;margin:0 0 20px;padding:0;border:1px solid var(--line);background:var(--surface);box-shadow:0 8px 24px #00000040}
.stats div{padding:10px 18px;border-right:1px solid var(--line);min-width:120px}
.stats div:last-child{border-right:0}
.stats div:has(.term[open]){flex-basis:100%}
.stats dt{color:var(--muted);font-size:13px}
.stats dd{margin:0;font:500 20px var(--mono)}
.stats .hot dd{color:var(--crit)}
.steps{margin:0 0 22px;padding:0;list-style:none;display:flex;flex-wrap:wrap;gap:12px}
.steps li{flex:1 1 260px;border:1px solid var(--line);background:var(--surface);padding:10px 12px}
.steps b{display:block;font-size:13px;color:var(--muted);font-weight:600;margin-bottom:6px}
.steps form{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:0 0 6px}
form.overview-import{display:grid;gap:12px;align-items:start;justify-items:start}
.steps .overview-import + .overview-import{margin-top:14px}
.overview-import>div{min-width:0;max-width:100%}
.overview-import label{margin:0 0 4px}.overview-import small{display:block;margin-top:4px}
.assistance-request{white-space:pre-wrap;overflow-wrap:anywhere;max-height:28rem;overflow:auto;padding:12px;border:1px solid var(--line)}
button,.btn{font:inherit;background:var(--raised);color:var(--text);border:1px solid var(--control-line);border-radius:2px;padding:4px 10px;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,.btn:hover{background:var(--control-hover);text-decoration:none}
button.primary,.btn.primary{background:var(--action);color:#fff;border-color:var(--action);font-weight:600}
button.primary:hover,.btn.primary:hover{background:var(--action-hover)}
button:disabled{cursor:not-allowed;opacity:.65}
a.link{display:inline-block;margin-right:12px}
input,select,textarea{font:inherit;background:var(--bg);color:var(--text);border:1px solid var(--control-line);border-radius:2px;padding:4px 8px;max-width:100%}
input::placeholder,textarea::placeholder{color:var(--placeholder);opacity:1}
[aria-invalid=true]{border-color:var(--crit)}.field-error{color:var(--crit)}label small{display:block;margin-top:5px;line-height:1.45}
.workflow fieldset+fieldset{margin-top:24px}fieldset{border:0;margin:0;padding:0;min-width:0}legend{font-weight:600;margin:0 0 10px;padding:0}
.lifecycle-form{margin:20px 0 4px;padding-top:16px;border-top:1px solid var(--line)}.error-summary h2{margin:0 0 8px;padding:0;border:0;font:600 17px/1.4 var(--sans);text-transform:none;letter-spacing:normal}.error-summary h2::before{content:none}
input[type=file]{padding:2px;color:var(--muted);max-width:210px}
textarea{width:100%;font:12px/1.5 var(--mono)}
label{display:block;margin:0 0 14px;color:var(--text);font-size:13px}
label input,label select{display:block;width:100%;max-width:520px;margin-top:3px;color:var(--text);font-size:14px}
table{width:100%;border-collapse:collapse;font-size:14px}
.panel{overflow-x:auto;border:1px solid var(--line);background:var(--surface);box-shadow:0 1px 0 #ffffff08 inset,0 8px 24px #00000040}
th{text-align:left;color:var(--muted);font:600 12px var(--sans);text-transform:uppercase;letter-spacing:.05em;padding:7px 10px;border-bottom:1px solid var(--line);background:var(--raised);white-space:nowrap}
td{padding:9px 10px;vertical-align:top;border-bottom:1px solid var(--line);max-width:340px;overflow-wrap:break-word}
tbody tr:last-child td{border-bottom:0}
.findings td:nth-child(1){min-width:150px}.findings td:nth-child(2){min-width:150px}.findings td:nth-child(3){min-width:190px}.findings td:nth-child(4){min-width:210px}.findings td:nth-child(5){min-width:240px}
tbody tr:hover{background:#ffffff06}
.pill,.st{white-space:nowrap;display:inline-flex;align-items:center;gap:6px;font:600 13px var(--sans);color:var(--text);padding:0;border:0}
.pill::before,.st::before{content:"";width:8px;height:8px;background:var(--none)}
.st-crit::before{background:var(--crit)}.st-high::before{background:var(--high)}
.st-info::before{background:var(--info)}.st-none::before{background:var(--none)}
.split{display:grid;grid-template-columns:minmax(0,1fr);gap:20px;align-items:start}
.alert{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:10px 12px;border-bottom:1px solid var(--line)}
.alert p{margin:3px 0}.alert>form{margin:0;flex:0 0 auto}.alert>form button{white-space:nowrap;overflow-wrap:normal}.alert>div{flex:1 1 0;min-width:0;overflow-wrap:anywhere}
code.block{display:block;margin-top:4px;padding:6px 8px;background:var(--bg);border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;color:var(--muted)}
small .mono{font-size:11px}
.plan p{margin:6px 0}.plan b{color:var(--muted);font-weight:600}.plan ul,.plan ol{margin:4px 0 10px;padding-left:20px}
.plan form{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.plan form input{flex:1 1 200px}
.focus{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(250px,100%),1fr));gap:12px;margin:0 0 22px}
.card{display:flex;gap:14px;align-items:center;padding:14px;border:1px solid var(--line);background:var(--surface);box-shadow:0 8px 24px #00000040;color:var(--text)}
a.card:hover{border-color:#3a4658;text-decoration:none}
.card b{display:block;font:600 13px var(--mono)}.card small{display:block}.card .t{margin-top:4px}
.ring{flex:none;width:68px;height:68px}
.ring circle{fill:none;stroke-width:4}
.ring .trk{stroke:#273141}
.ring .arc{stroke:var(--none);stroke-linecap:butt;transform:rotate(-90deg);transform-origin:22px 22px}
.ring-crit .arc{stroke:var(--accent)}.ring-high .arc{stroke:var(--high)}.ring-info .arc{stroke:var(--info)}.ring-ok .arc{stroke:var(--ok)}
.ring text{fill:var(--text);font:500 12px var(--mono);text-anchor:middle;dominant-baseline:central}
article h2{margin-top:0}
.term{margin:0;max-width:100%;white-space:normal}.term>summary{color:inherit;text-decoration:underline dotted;text-underline-offset:3px;overflow-wrap:anywhere}
.term>p{font:400 13px/1.5 var(--sans);color:var(--muted);margin:8px 0;max-width:32ch;overflow-wrap:anywhere}
.headline{margin:0 0 22px;padding:14px 18px;border-left:1px solid var(--accent);background:var(--surface);font-size:17px;line-height:1.5;box-shadow:0 8px 24px #00000040}
.headline small{display:block;margin-top:4px;font-size:14px}
.gloss dt{margin-top:16px;font-weight:600}.gloss dd{margin:2px 0 0;color:var(--muted);max-width:75ch}
article.panel{padding:14px 16px;margin-bottom:14px}
.empty{color:var(--muted);padding:18px;text-align:left}
.notice{background:var(--raised);border-left:1px solid var(--high);padding:8px 12px;margin:0 0 14px;overflow-wrap:anywhere}
.notice.success{border-left-color:var(--ok)}.notice.error{border-left-color:var(--crit)}.notice p{margin:4px 0}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 12px}.controls form{margin:0}
details{margin-top:8px}summary{cursor:pointer;color:var(--link)}
footer{color:var(--muted);font-size:12px;margin-top:28px;max-width:100ch}
.panel>svg{width:100%;min-width:700px;max-height:680px}.legend{color:var(--muted);font-size:12px;padding:0 12px 10px}

.topology-toolbar{display:flex;align-items:end;justify-content:space-between;flex-wrap:wrap;gap:16px;padding:14px;border:1px solid var(--line);background:var(--surface)}
.topology-toolbar form{display:flex;align-items:end;flex-wrap:wrap;gap:12px;margin:0;min-width:0}.topology-toolbar label{margin:0}.topology-toolbar input{width:210px;max-width:100%}.topology-toolbar button,.topology-zoom .btn{flex:none;white-space:nowrap}
.topology-zoom{display:flex;gap:6px;flex-wrap:wrap}.topology-workspace{display:grid;grid-template-columns:minmax(0,1fr) 260px;border:1px solid var(--line);border-top:0;background:var(--surface)}
.topology-canvas{min-width:0;grid-column:1;grid-row:1}.topology-scroll{overflow:auto;max-height:720px}.topology-scale{min-width:0}.topology-svg{display:block;width:100%;height:auto}.topology-svg text{font-family:var(--sans);fill:var(--text)}
.topology-zone{fill:none;stroke:var(--line)}.topology-zone-name{font-size:13px}.topology-svg .topology-meta{font-size:11px;fill:var(--muted)}.topology-plate{fill:var(--raised);stroke:var(--control-line)}
.topology-node:hover .topology-plate{fill:var(--control-hover)}.topology-node:focus-visible{outline:none}.topology-node:focus-visible .topology-plate,.topology-node.is-selected .topology-plate{stroke:var(--link);stroke-width:2}
.topology-node.is-search-match .topology-plate{stroke:var(--link);stroke-dasharray:4 3}.topology-node.is-selected .topology-plate{stroke-dasharray:none}
.topology-icon{fill:none;stroke:var(--text);stroke-width:1.3;stroke-linecap:round;stroke-linejoin:round}.topology-name{font-size:14px;font-weight:600}.topology-svg .topology-ip{font:12px var(--mono);fill:var(--muted)}.topology-svg .topology-state{font-size:11px;fill:var(--muted)}
.topology-edge path{fill:none;stroke:var(--graph-edge);stroke-width:1.5}.topology-edge:hover path,.topology-edge:focus path{stroke:var(--link);stroke-width:2}.topology-edge text{font-size:11px;fill:var(--muted)}#topology-arrow path{fill:none;stroke:var(--graph-edge);stroke-width:1}
.topology-support{fill:none;stroke:var(--zone-ot);stroke-width:1.2;stroke-dasharray:4 5}.topology-process rect{fill:var(--raised);stroke:var(--zone-ot)}.topology-process text{font-size:12px}.topology-process:hover rect,.topology-process:focus rect{stroke:var(--link);stroke-width:2}
.topology-caption{padding:12px 18px;margin:0;color:var(--muted);font-size:12px}.topology-legend{display:flex;flex-wrap:wrap;gap:12px 24px;padding:12px 18px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}.topology-legend span::before{content:"";display:inline-block;width:24px;margin-right:8px;vertical-align:middle;border-top:1px solid var(--graph-edge)}.topology-legend .support-key::before{border-top:1px dashed var(--zone-ot)}
.alert-topology{display:grid;grid-template-columns:minmax(0,1fr) minmax(108px,auto) minmax(0,1fr);align-items:center;gap:12px;padding:16px;background:var(--surface);border:1px solid var(--line)}
.alert-topology-endpoint{display:grid;gap:4px;min-width:0;padding:12px 16px;background:var(--raised);border:1px solid var(--control-line);border-radius:4px;overflow-wrap:anywhere}
.alert-topology-endpoint>span{color:var(--muted)}.alert-topology-edge{display:grid;gap:2px;justify-items:center;min-height:44px;padding:6px 10px;border:1px solid var(--crit);border-radius:4px;text-align:center;color:var(--text);font-weight:600}
.alert-topology-edge:hover{background:var(--raised)}.alert-topology-arrow::before{content:"→";color:var(--crit);font-size:32px;line-height:1}
@media(max-width:620px){.alert-topology{grid-template-columns:minmax(0,1fr);gap:8px}.alert-topology-edge{justify-self:center;min-width:108px}.alert-topology-arrow::before{content:"↓"}}
.topology-detail{grid-column:2;grid-row:1;min-width:0;border-left:1px solid var(--line);padding:20px;font-size:13px;overflow-wrap:anywhere}.topology-detail h3{margin:0;font-size:18px}.topology-detail h4{margin:22px 0 8px;padding-top:18px;border-top:1px solid var(--line);font-size:13px}.topology-detail p{margin:6px 0 14px}.topology-detail dl{margin:20px 0}.topology-detail dl>div{display:flex;justify-content:space-between;gap:16px;margin:10px 0}.topology-detail dt{color:var(--muted)}.topology-detail dd{margin:0;text-align:right}.topology-detail .topology-times>div{display:block}.topology-times dd{text-align:left;margin-top:3px}.topology-detail ul{padding-left:18px}.topology-detail li{margin-bottom:8px}.topology-empty{padding:30px 24px;min-height:220px}
@media(max-width:1150px){.topology-workspace{grid-template-columns:minmax(0,1fr)}.topology-detail{grid-column:1;grid-row:1;border-left:0;border-bottom:1px solid var(--line)}.topology-canvas{grid-column:1;grid-row:2}.topology-detail dl{max-width:500px}.topology-detail dd{text-align:left}.topology-detail dl>div{justify-content:flex-start}.topology-detail dt{flex:0 0 140px}}
.split>div,.record-actions>*{min-width:0}
.skip-link{position:fixed;inset:8px auto auto 8px;z-index:10;padding:10px;background:var(--raised);transform:translateY(-180%)}.skip-link:focus{transform:none}
.site-navigation{margin:0}.site-navigation>summary{display:none}.mobile-navigation{display:none}
.current-location{display:none}.editor{margin:24px 0;padding-block:8px 20px;border-block:1px solid var(--line)}
.editor h2{margin-top:8px}.editor h3{margin-top:0}h3{font:600 16px/1.4 var(--sans);margin:20px 0 8px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(260px,100%),1fr));gap:0 20px;max-width:1000px}
.workflow{margin:24px 0;padding-block:12px;border-block:1px solid var(--line)}.workflow>summary{font-weight:600}.workflow form{margin-top:16px}
.record{padding:12px 0;border-bottom:1px solid var(--line)}.record h3{margin:4px 0}.record p{margin:4px 0}
.raw-record{margin:14px 0}.raw-record pre,pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 var(--mono);max-width:100%}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(210px,100%),1fr));gap:10px 24px;margin:16px 0}
.facts>div{min-width:0}.facts dt{color:var(--muted);font-size:13px}.facts dd{margin:2px 0;overflow-wrap:anywhere}
.triage-record{overflow-wrap:anywhere}.triage-record h2{font:600 19px/1.4 var(--sans);text-transform:none;letter-spacing:normal;border:0;margin:0;padding:0}.triage-record h2::before{content:none}
.triage-record header p{margin:2px 0 14px}.triage-record h3{margin:20px 0 8px}.triage-record .evidence-lines{padding-left:20px}
.score-details{margin:20px 0}.record-actions{display:flex;align-items:center;flex-wrap:wrap;gap:12px 20px;margin-top:16px}.record-actions form{margin:0}
.filter-bar{display:flex;align-items:end;flex-wrap:wrap;gap:12px;margin:18px 0 24px}.filter-bar label{margin:0;flex:1 1 160px}.filter-bar input,.filter-bar select{max-width:none}
.text-panel{padding:12px 16px}.text-panel p:first-child{margin-top:0}.text-panel p:last-child{margin-bottom:0}
.advisory-preview,.advisory-text{max-width:65ch;line-height:1.6;margin-block:8px}
.advisory-text{white-space:pre-wrap}.advisory-content>summary{color:var(--link);cursor:pointer}
.advisory-content[open]+.advisory-preview,.advisory-content[open] .advisory-expand,.advisory-content:not([open]) .advisory-collapse{display:none}
.advisory-actions{margin-top:10px}
button,.btn{flex-shrink:0;overflow-wrap:normal;word-break:normal;max-width:100%}
.triage-viewbar{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.triage-viewbar a{padding:7px 12px;border:1px solid var(--line);border-radius:6px;color:var(--muted)}
.triage-viewbar a[aria-current]{background:var(--raised);color:var(--text);border-color:var(--control-line)}
.triage-reports{margin-inline-start:auto}
.alert-board{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-block:20px}
.alert-column{padding:12px;border:1px solid var(--line);border-radius:8px;background:linear-gradient(160deg,#38271e42,var(--surface) 135px);min-width:0}
.alert-column h2{display:flex;align-items:center;gap:8px;margin:0 0 12px;padding:0;border:0;text-transform:none;font:600 15px var(--sans);letter-spacing:normal}
.alert-column h2::before{content:'';inline-size:9px;block-size:9px;border:2px solid var(--muted);border-radius:50%}
.alert-column:nth-child(2) h2::before{border-color:var(--high)}
.alert-column:nth-child(3) h2::before{border-color:var(--ok);background:var(--ok)}
.alert-count{color:var(--muted);font-weight:400}
.alert-card{display:grid;gap:5px;padding:12px;margin-block:8px;border:1px solid var(--line);border-radius:6px;background:var(--raised);color:var(--muted);font-size:13px}
.alert-card:hover{background:var(--surface);border-color:var(--control-line);text-decoration:none}
.alert-card strong{color:var(--text);font-size:14px}
.alert-card-meta{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px;margin-top:6px;font-variant-numeric:tabular-nums}
.alert-urgency::before{content:'';display:inline-block;inline-size:7px;block-size:7px;background:currentColor;border-radius:2px;margin-inline-end:5px}
.alert-urgency.critical{color:var(--crit)}.alert-urgency.high{color:var(--high)}.alert-urgency.medium{color:var(--info)}
@media(max-width:720px){.alert-board{grid-template-columns:minmax(0,1fr)}}
.triage-case{border-block-end:1px solid var(--line);margin:0}.triage-case>summary{padding:16px 12px;color:var(--text)}
.triage-case>summary:hover{background:var(--surface)}.case-title{font-size:17px;font-weight:600}.case-title .mono{font-weight:400;color:var(--muted);margin-inline-start:8px}
.case-subject,.case-state,.case-meta{display:block;margin:3px 0 0 16px}.case-subject{font-size:14px}.case-state{font-size:13px}.case-meta{font-size:12px;color:var(--muted)}.case-inspect{display:inline-block;margin:8px 0 0 16px;color:var(--link);font-size:13px}
.case-detail{padding:0 16px 24px;border-top:1px solid var(--line)}.triage-case[open]>summary .case-inspect{display:none}
.finding-case{max-width:90ch}.finding-case>h2,.plan-header h2{font:600 20px/1.4 var(--sans);text-transform:none;letter-spacing:normal;border:0;margin:18px 0 12px;padding:0}.finding-case>h2::before,.plan-header h2::before{content:none}
.finding-case .record-actions{margin:20px 0}.finding-case .facts{grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr))}
.plan-summary{max-width:85ch}.plan-summary .facts{margin-top:8px}.plan-review{padding:12px 0;border-block:1px solid var(--line);margin:20px 0}.plan-review>summary{font-weight:600;min-height:32px}
.plan-sections>details{margin:0;padding:12px 0;border-bottom:1px solid var(--line)}.plan-section-body{padding-top:12px;max-width:85ch}.plan-score-factors{margin:12px 0}.plan-score-factors>div{margin:12px 0}.plan-score-factors dt{color:var(--muted)}.plan-score-factors dd{margin:2px 0 0}.plan-references{overflow-wrap:anywhere}
.inline-check{display:inline-flex;align-items:center;gap:8px;margin:0 8px}.inline-check input{display:inline-block;width:auto;max-width:none;margin:0}
.pagination{display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin:24px 0}.active-filters{display:flex;gap:10px;flex-wrap:wrap}.active-filters span{border:1px solid var(--line);padding:4px 8px;overflow-wrap:anywhere}
.setup-start{padding:18px 0 24px;max-width:75ch}.setup-start h2{font:600 21px var(--sans);text-transform:none;letter-spacing:normal;border:0;margin:0 0 12px}.setup-start h2::before{content:none}
@media(max-width:900px){body{grid-template-columns:minmax(0,1fr);grid-template-rows:auto 1fr}aside{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);padding:12px 16px}
.brand{padding:0;display:inline-flex}.current-location{display:block;margin:8px 0 0;color:var(--muted);font-size:14px}
.site-navigation{margin:8px 0 0}.site-navigation>summary{display:list-item;padding:8px 0;min-height:44px}
.site-navigation nav a{padding:10px 12px;min-height:44px}.site-navigation .nav-group-label{margin:18px 12px 4px}
.desktop-navigation{display:none}.mobile-navigation{display:block}main{padding:20px 16px 40px}
.split{grid-template-columns:minmax(0,1fr)}input,select,textarea,button,.btn,label input,label select{font-size:16px}input,select,button,.btn,.term>summary{min-height:44px}
.alert{flex-wrap:wrap}.alert>div{flex-basis:100%}.alert>form{margin-inline-start:auto}.brand small{font-size:13px}.stats div{flex:1 1 130px}.controls form{max-width:100%}}
@media(max-width:900px){.plan-review>summary{min-height:44px}.case-title .mono{display:block;margin:3px 0 0 16px}.case-meta{font-size:13px}.finding-case .facts{grid-template-columns:minmax(0,1fr)}.inline-check{margin:8px 0;min-height:44px}.inline-check input{min-height:auto;width:20px;height:20px}.plan .plan-score-factors dd{margin-left:0}}
.language-control{margin:0 0 14px}
body{grid-template-columns:240px minmax(0,1fr)}
aside{display:flex;flex-direction:column;padding:20px 14px 16px;background:linear-gradient(180deg,#0b1210,#070a09);border-right:1px solid var(--line)}
.brand{padding:0 8px 18px}.brand b{letter-spacing:.28em;font-size:16px}
.primary-action{display:flex;align-items:center;justify-content:space-between;margin:0 0 18px;padding:9px 8px 9px 16px;border-radius:12px;background:var(--action);color:var(--accent-ink);font-weight:700}
.primary-action:hover{background:var(--action-hover);text-decoration:none}
.primary-action span{display:grid;place-items:center;width:28px;height:28px;border-radius:8px;background:#f3f5e633;font-size:20px;line-height:1}
.desktop-navigation .nav-group-label{display:none}
.site-navigation nav a{display:flex;align-items:center;gap:12px;margin:2px 0;padding:9px 12px;border-radius:10px;border-left:0;color:var(--muted)}
.site-navigation nav a svg{width:18px;height:18px;flex:none;stroke:currentColor;fill:none;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.site-navigation nav a:hover{background:var(--surface);color:var(--text);text-decoration:none}
.site-navigation nav a[aria-current]{background:#a3b35c1c;color:#fff;border:0;box-shadow:inset 0 0 0 1px #a3b35c40}
.site-navigation nav a[aria-current] svg{stroke:var(--accent)}
.aside-foot{margin-top:auto;padding-top:16px;display:grid;gap:8px;border-top:1px solid var(--line)}
.aside-foot .help{display:flex;gap:12px;align-items:center;padding:8px 12px;border-radius:10px;color:var(--muted)}
.aside-foot .help:hover{background:var(--surface);color:var(--text);text-decoration:none}
.aside-foot svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.operator{display:flex;gap:10px;align-items:center;padding:6px 8px}
.operator .avatar{flex:none;width:34px;height:34px;border-radius:50%;background:#a3b35c22;color:var(--accent);display:grid;place-items:center;font-weight:700}
.operator b{display:block;font-size:14px;line-height:1.2}.operator small{font-size:12px}
main{padding:26px 34px 56px;max-width:1380px}
h1{font-size:28px;letter-spacing:-.01em}
h2{font:600 16px/1.3 var(--sans);text-transform:none;letter-spacing:0;border:0;padding:0;margin:28px 0 12px}
h2::before{content:none}
button,.btn{border-radius:10px;padding:8px 16px}
button.primary,.btn.primary{color:var(--accent-ink);font-weight:700}
input,select,textarea{border-radius:10px;padding:8px 12px}
.panel{border-radius:14px}
.stats,.workflow,.record,.editor,.triage-case,.plan-review,.notice,.headline,.setup-start,.alert-topology,.topology-toolbar,.advisory-text{border-radius:14px}
.notice{border-left-width:1px}
.headline{border:1px solid var(--line);border-left:1px solid var(--accent);background:var(--surface)}
.zone-alert{border-left-color:var(--crit)}
.pill,.st{border-radius:999px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr));gap:16px;margin:0 0 16px}
.kpi{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:end;padding:18px 18px 16px;border:1px solid var(--line);border-radius:16px;background:linear-gradient(180deg,#13150f,#0c0d09);color:var(--text);min-width:0}
a.kpi:hover{border-color:#4b5320;text-decoration:none}
.kpi .label{grid-column:1/-1;display:flex;justify-content:space-between;align-items:center;gap:8px;color:var(--muted);font-size:13px}
.chip{font-size:11px;line-height:18px;padding:0 8px;border-radius:999px;background:#a3b35c1a;color:var(--accent);white-space:nowrap}
.chip.bad{background:#ff5d5d1a;color:var(--crit)}.chip.warn{background:#f0a03c1a;color:var(--high)}
.kpi b{grid-column:1;font:700 38px/1 var(--display);letter-spacing:-.02em;margin-top:6px}
.kpi small{grid-column:1;color:var(--muted);font-size:13px}
.kpi .viz{grid-column:2;grid-row:2/4;align-self:end}
.kpi .ring{width:58px;height:58px}
.spark{display:flex;align-items:flex-end;gap:4px;height:42px}
.spark i{display:block;width:6px;min-height:4px;border-radius:2px;background:var(--accent)}
.spark i.crit{background:var(--crit)}.spark i.high{background:var(--high)}.spark i.info{background:var(--info)}.spark i.dim{background:#a3b35c66}
.cards{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px;margin:0 0 16px;align-items:stretch}
.cardx{border:1px solid var(--line);border-radius:16px;background:linear-gradient(180deg,#13150f,#0c0d09);padding:18px 18px 16px;min-width:0}
.cardx>header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 0 14px}
.cardx>header h2{margin:0;font-size:15px}
.cardx>header .aux{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:13px}
.cardx>header .aux svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.cardx>.panel{border:0;background:transparent;margin:0 -8px}
.cardx>.text-panel{padding:0}
.cardx .alert{padding-inline:0}
.rank{display:grid;gap:16px;margin:0;padding:0;list-style:none}
.rank li{display:grid;gap:7px}
.rank .row{display:flex;justify-content:space-between;align-items:baseline;gap:12px;font-size:14px}
.rank .row b{font:600 13px var(--mono);color:var(--muted);white-space:nowrap}
.rank .row small{margin-inline-start:8px}
.bar{height:5px;border-radius:999px;background:#ffffff10;overflow:hidden}
.bar i{display:block;height:100%;border-radius:999px;background:var(--accent)}
.bar i.crit{background:var(--crit)}.bar i.high{background:var(--high)}.bar i.info{background:var(--info)}
.feed{display:grid;gap:8px;margin:0;padding:0;list-style:none}
.feed a{display:grid;grid-template-columns:36px minmax(0,1fr) auto;gap:12px;align-items:center;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:#ffffff05;color:var(--text)}
.feed a:hover{border-color:#4b5320;background:#a3b35c0d;text-decoration:none}
.feed .ico{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:#a3b35c14;color:var(--accent)}
.feed .ico.crit{background:#ff5d5d14;color:var(--crit)}.feed .ico.high{background:#f0a03c14;color:var(--high)}.feed .ico.info{background:#5fb4e814;color:var(--info)}
.feed svg{width:17px;height:17px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.feed b{display:block;font-size:14px;font-weight:600;overflow-wrap:anywhere}.feed small{display:block;font-size:12px;overflow-wrap:anywhere}
.feed .go{color:var(--muted)}
.cards.three{grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr))}
.cardx.wide{margin:0 0 16px}
.cardx.workflow{padding:16px 18px;margin:0 0 16px}
.cardx.workflow>summary{font-weight:600;color:var(--text)}
footer{margin-top:24px}
@media(max-width:1100px){.cards{grid-template-columns:minmax(0,1fr)}}
@media(max-width:900px){body{grid-template-columns:minmax(0,1fr)}aside{padding:12px 16px}.aside-foot{display:none}.primary-action{margin:10px 0}main{padding:20px 16px 40px}}

/* ---- CyFocus layout layer ---- */
:root{--bg:#070806;--card:#0e100b;--card-2:#13150f;--line:#22261a;--line-2:#ffffff14;--muted:#9a9d88;--text-2:#dcdfcf;--text-3:#c3c6b2;--overlay-1:#ffffff06;--overlay-2:#ffffff08;--overlay-3:#ffffff0d;--sans:"Segoe UI Variable Text","Segoe UI",Inter,Helvetica,Arial,sans-serif;--display:"Segoe UI Variable Display","Segoe UI",Inter,Helvetica,Arial,sans-serif}
body{grid-template-columns:248px minmax(0,1fr);gap:0;font-size:14px;background:radial-gradient(760px 520px at -4% -6%,#4b53205c,transparent 62%),radial-gradient(900px 600px at 105% 110%,#2b301533,transparent 70%),var(--bg);background-attachment:fixed}
aside{position:sticky;top:14px;height:calc(100vh - 28px);margin:14px 0 14px 14px;padding:22px 14px 14px;border:1px solid var(--line-2);border-radius:18px;background:linear-gradient(180deg,#11130df2,#0b0c08f2);box-shadow:0 20px 50px #00000080}
.brand{padding:0 6px 22px;gap:9px}.brand svg{width:22px;height:22px}.brand small{display:none}
.brand b{font:600 15px/1 var(--display);letter-spacing:.26em}
.brand b::after{content:none}
.new-row{display:flex;gap:6px;margin:0 0 22px}
.primary-action{flex:1;justify-content:center;margin:0;padding:9px 12px;border-radius:8px;font-size:14px;font-weight:600;background:var(--action);color:var(--accent-ink);box-shadow:0 8px 24px #00000059}
.plus{flex:none;display:grid;place-items:center;width:38px;border-radius:8px;background:var(--action);color:var(--accent-ink);font-size:20px;font-weight:600;line-height:1}
.plus:hover{background:var(--action-hover);text-decoration:none}
.site-navigation nav a{position:relative;gap:11px;margin:1px 0;padding:8px 12px;border-radius:8px;font-size:13.5px;color:var(--text-3)}
.site-navigation nav a svg{width:16px;height:16px;stroke:#9a9d88}
.site-navigation nav a:hover{background:#ffffff08}
.site-navigation nav a[aria-current]{background:#ffffff0d;box-shadow:none;color:#fff}
.site-navigation nav a[aria-current]::before{content:"";position:absolute;left:-14px;top:7px;bottom:7px;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
.site-navigation nav a[aria-current] svg{stroke:#fff}
.aside-foot{border-top:0;gap:6px}
.aside-foot .help{padding:8px 12px;font-size:13.5px;color:var(--text-3)}
.operator{border-top:1px solid var(--line-2);padding:14px 6px 2px;margin-top:4px}
.operator .avatar{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#556b2f,#343d17);color:#f3f5e6;font-size:13px}
.operator>span:nth-child(2){flex:1;min-width:0}.operator .chev{color:var(--muted);font-size:12px}
main{padding:14px 18px 48px 16px;max-width:none}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:0 0 14px;min-height:38px}
.topbar .language-control{margin:0;gap:6px;font-size:12px}.topbar .language-control label{color:var(--muted);font-size:12px}
.topbar .language-control select,.topbar .language-control button{padding:5px 10px;font-size:12px;border-radius:8px}
.dataset{display:inline-flex;align-items:center;gap:8px;max-width:70ch;padding:5px 12px;border:1px solid var(--line-2);border-radius:999px;background:#ffffff06;color:var(--muted);font-size:12px;line-height:1.35}
.dataset::before{content:"";flex:none;width:6px;height:6px;border-radius:50%;background:var(--high)}
main:has(.dash)>h1,main:has(.dash)>.lead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
h1{font:600 26px/1.2 var(--display);margin:4px 0 6px}
.kpis{grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:0 0 14px}
.kpi,.cardx{border:1px solid var(--line-2);border-radius:14px;background:linear-gradient(180deg,#13150fe6,#0c0d09e6);box-shadow:0 10px 30px #00000059}
.kpi{grid-template-columns:minmax(0,1fr) auto;gap:2px 10px;padding:14px 16px 14px}
.kpi .label{font-size:13px;color:var(--text-2)}
.chip,.chip.bad,.chip.warn{display:inline-flex;align-items:center;gap:5px;padding:1px 7px;border:1px solid var(--line-2);border-radius:6px;background:var(--overlay-2);color:var(--text-2);font-size:11px;line-height:18px}
.chip::before{content:"↗";font-size:11px;color:var(--accent)}.chip.bad::before{color:var(--crit)}.chip.warn::before{color:var(--high)}
.kpi b{font:600 30px/1.05 var(--display);margin-top:10px}
.kpi small{font-size:11.5px;color:var(--muted)}
.kpi .viz{align-self:end}
.kpi .ring{width:52px;height:52px}.kpi .ring circle{stroke-width:4.5}.kpi .ring .trk{stroke:#ffffff14}.kpi .ring .arc{stroke-linecap:round}
.kpi .ring text{font:600 10px var(--sans)}
.gauge{display:block;width:74px;height:44px}.gauge path{fill:none;stroke-width:7;stroke-linecap:round}.gauge .trk{stroke:#ffffff14}.gauge .arc{stroke:var(--accent)}
.gauge.high .arc{stroke:var(--high)}.gauge.crit .arc{stroke:var(--crit)}
.spark{gap:3px;height:36px}.spark i{width:4px;border-radius:1px}
.cards{gap:14px;margin:0 0 14px}
.cards.dash-main{grid-template-columns:minmax(0,1.5fr) minmax(0,1fr)}
.cardx{padding:16px 18px}
.cardx>header{margin:0 0 12px}
.cardx>header h2{font:600 15px/1.3 var(--sans)}
.select-pill{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:7px;color:var(--muted);font-size:12px}
.select-pill::after{content:"";width:5px;height:5px;border-right:1.5px solid currentColor;border-bottom:1.5px solid currentColor;transform:rotate(45deg) translateY(-2px)}
.map{display:block;width:100%;height:auto;margin:2px 0 14px}
.map .dot{fill:#ffffff1f}.map .zl{fill:var(--text-3);font:600 12px var(--sans);letter-spacing:.12em}
.map .mk{stroke:#070806;stroke-width:1}.map .mk-ok{fill:var(--olive-soft)}.map .mk-high{fill:var(--amber)}.map .mk-crit{fill:var(--red)}
.map .mk-num{fill:#eef0e6;font:600 12px var(--mono)}
.bars{display:grid;gap:12px;margin:0;padding:0;list-style:none}
.bars li{display:grid;gap:6px}
.bars .row{display:flex;justify-content:space-between;gap:12px;font-size:12px;color:var(--text-2)}
.bars .row b{font:600 12px var(--sans);font-variant-numeric:tabular-nums}
.bars .row span{color:var(--muted);text-align:right;overflow-wrap:anywhere}
.bars .bar{height:4px;border-radius:999px;background:#ffffff12}
.bars .bar i{background:var(--accent)}.bars .bar i.crit{background:var(--crit)}
.card-foot{display:flex;justify-content:flex-end;gap:6px;margin-top:16px}
.card-foot .btn{padding:7px 16px;border-radius:8px;background:#ffffff0a;border-color:var(--line-2);font-size:13px;font-weight:600}
.card-foot .sq{display:grid;place-items:center;width:34px;padding:0}.card-foot .sq svg,.feed .go svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.feed{gap:6px}
.feed a{grid-template-columns:30px minmax(0,1fr) auto;gap:12px;padding:9px 12px;border-radius:10px;border-color:var(--line-2);background:#ffffff07}
.feed a:hover{background:#ffffff0d;border-color:#ffffff24}
.feed .ico,.feed .ico.high,.feed .ico.info{width:30px;height:30px;border-radius:50%;background:#ffffff0d;color:#cfd2bf}
.feed .ico.crit{background:#ff5d5d1a;color:var(--crit)}
.feed svg{width:15px;height:15px}
.feed b{font-size:13px;font-weight:600}.feed small{font-size:11.5px}
.feed .go{color:var(--text-2)}
.alert-board{grid-template-columns:repeat(3,minmax(220px,1fr));gap:14px}
.alert-column{border:0;border-radius:12px;background:#ffffff05;padding:12px 10px}
.alert-column h2{font:600 14px var(--sans);margin:2px 4px 14px}
.alert-column h2::before{width:10px;height:10px;border:1.5px solid var(--muted)}
.alert-count::before{content:"("}.alert-count::after{content:")"}
.alert-card{border-color:var(--line-2);border-radius:10px;background:#141b18;padding:12px 12px 10px;box-shadow:0 6px 18px #00000040}
.alert-card:hover{background:#18201d;border-color:#ffffff26}
.alert-card strong{display:flex;align-items:center;gap:8px;font-size:13.5px}
.alert-card strong::before{content:"";flex:none;width:8px;height:8px;border-radius:2px;background:var(--accent)}
.alert-card:has(.alert-urgency.critical) strong::before{background:var(--crit)}.alert-card:has(.alert-urgency.high) strong::before{background:var(--high)}.alert-card:has(.alert-urgency.medium) strong::before{background:var(--info)}
.alert-card-meta{padding-top:8px;margin-top:4px;border-top:1px solid var(--line-2)}
.triage-viewbar a{border-radius:8px;border-color:var(--line-2)}
.secondary-navigation{border-bottom-color:var(--line-2)}
.panel{border-color:var(--line-2);background:#0e100bcc}
th{background:var(--overlay-1)}

/* ---- TNI palette, restrained: olive is the only brand colour, gold marks the current place, signal colours only carry meaning ---- */
:root{--olive:#556b2f;--olive-hover:#61793a;--olive-soft:#a3b35c;--gold:#c9a646;--blue:#5aa9d6;--amber:#e39b3a;--red:#e5534b;--crit:#e5534b;--high:#e39b3a;--info:#5aa9d6;--ok:#8fa84a;--link:#c2cf8a}
body{background:radial-gradient(800px 520px at -6% -8%,#556b2f40,transparent 62%),var(--bg);background-attachment:fixed}
:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
.brand .eye{fill:var(--gold)}.brand .shield{stroke:var(--olive-soft);fill:none}
.site-navigation nav a[aria-current]{background:#ffffff0f}
.site-navigation nav a[aria-current]::before{background:var(--gold)}
.primary-action,.plus{background:var(--olive);border:0;box-shadow:none;color:#f3f5e6}
.primary-action:hover,.plus:hover{background:var(--olive-hover)}
button.primary,.btn.primary{background:var(--olive);border-color:var(--olive);color:#f3f5e6}
button.primary:hover,.btn.primary:hover{background:var(--olive-hover)}
.kpi,.cardx{background:#11130f;box-shadow:none}
.dataset::before{background:var(--gold)}
.operator .avatar{background:#2a3118;color:var(--olive-soft);border:1px solid #3a4422}
.kpi .label .name{display:inline-flex;align-items:center;gap:9px}
.kpi-ico{display:grid;place-items:center;width:26px;height:26px;border-radius:7px;background:var(--overlay-2);border:1px solid var(--line-2);color:var(--text-3)}
.kpi-ico svg,.step-ico svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.chip.bad{color:#f2a19c}.chip.warn{color:#efc58e}.chip.info{color:#a9d2ea}.chip.info::before{color:var(--blue)}
.spark i.gold{background:var(--gold)}
.start{margin:0 0 14px;border:1px solid var(--line-2);border-radius:14px;background:#11130f}
.start>header{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:14px 18px;border-bottom:1px solid var(--line-2)}
.start>header h2{margin:0;font:600 15px/1.3 var(--sans)}.start>header p{margin:0;color:var(--muted);font-size:12.5px}
.steps-next{margin:0;padding:0;list-style:none;counter-reset:step}
.steps-next li{display:grid;grid-template-columns:28px minmax(0,1fr) auto;gap:2px 14px;align-items:center;padding:12px 18px;border-top:1px solid var(--line-2)}
.steps-next li:first-child{border-top:0}
.steps-next li::before{counter-increment:step;content:counter(step);grid-row:1/3;display:grid;place-items:center;width:26px;height:26px;border:1px solid #ffffff2e;border-radius:50%;color:var(--text-2);font:600 12px var(--sans)}
.steps-next b{display:flex;align-items:center;gap:8px;font-size:14px;font-weight:600;color:#fff}
.steps-next b .n{min-width:22px;padding:0 6px;border-radius:6px;background:#ffffff10;font-size:12px;text-align:center;font-variant-numeric:tabular-nums}
.steps-next .sev{width:7px;height:7px;border-radius:50%;background:#9a9d88}.sev.red{background:var(--red)}.sev.amber{background:var(--amber)}.sev.blue{background:var(--blue)}
.steps-next p{grid-column:2;margin:0;color:var(--muted);font-size:12.5px;line-height:1.45}
.steps-next .btn{grid-column:3;grid-row:1/3;padding:6px 14px;border-radius:8px;font-size:12.5px;font-weight:600;background:#ffffff0a;border-color:var(--line-2);color:#e6e8dc}
.steps-next li:first-child .btn{background:var(--olive);border-color:var(--olive);color:#f3f5e6}
.feed .ico.crit{background:#e5534b1a;color:var(--red)}
.bars .bar i{background:var(--olive-soft);box-shadow:none}.bars .bar i.high{background:var(--amber);box-shadow:none}.bars .bar i.crit{background:var(--red);box-shadow:none}
.notice{border:1px solid var(--line-2);border-left:1px solid var(--gold);background:#ffffff08;color:var(--text)}
.notice.success{border-left-color:var(--ok)}.notice.error{border-left-color:var(--red)}
.st-crit::before{background:var(--red)}.st-high::before{background:var(--amber)}.st-info::before{background:var(--blue)}
.secondary-navigation a[aria-current]{border-bottom-color:var(--gold)}
.board-tip{color:var(--muted)}
.alert-column.drop-ok{box-shadow:inset 0 0 0 1.5px var(--olive-soft)}.alert-column.drop-ok .drop-slot{border-color:var(--olive-soft)}
.triage-viewbar a[aria-current]{background:#ffffff17}
@media(max-width:700px){.steps-next li{grid-template-columns:28px minmax(0,1fr)}.steps-next .btn{grid-column:2;grid-row:auto;justify-self:start;margin-top:8px}}

/* ---- page chrome from the CyFocus detail and findings screens ---- */
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin:2px 0 6px}
.page-title{min-width:0}
.crumbs{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:0 0 8px;color:var(--muted);font-size:12.5px}
.crumbs a{display:inline-flex;align-items:center;color:var(--muted)}.crumbs a:hover{color:var(--text);text-decoration:none}
.crumbs svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.crumbs .sep{opacity:.6}.crumbs .here{color:var(--text-2);font-style:normal}
.page-head h1{margin:0}
.page-actions{display:flex;gap:6px}
.page-actions .btn{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:8px;font-weight:600;font-size:13px;background:#ffffff0d;border-color:var(--line-2)}
.page-actions .btn.sq{padding:8px 10px}.page-actions svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
main>.lead{margin:0 0 18px;max-width:70ch;color:#b7bba5;font-size:14px}
main:has(.dash)>.page-head{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.empty-state{display:grid;justify-items:center;gap:6px;padding:26px 16px 30px;text-align:center}
.empty-state .globe{width:150px;height:150px;fill:none;stroke:#a3b35c;stroke-width:.7;opacity:.55}
.empty-state .globe .node{fill:var(--gold);stroke:none;opacity:.9}
.empty-state p,.empty-state .empty{margin:0;padding:0;max-width:52ch;color:var(--text-2);font-size:15px;text-align:center}
td .empty-state{padding:20px 10px}
.cardx .empty-state,.alert-column .empty-state,.feed .empty-state,.rank .empty-state{padding:8px 0}
.cardx .empty-state .globe,.alert-column .empty-state .globe{display:none}
.cardx .empty-state p,.cardx .empty-state .empty{font-size:13px;color:var(--muted)}
/* finding detail */
.case-head{margin:0 0 14px;padding:18px 20px 14px;border:1px solid var(--line-2);border-radius:14px;background:#11130f}
.case-top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.finding-case .case-head h2{margin:0 0 4px;font:600 20px/1.3 var(--display)}
.case-pills{display:flex;gap:6px;flex-wrap:wrap}
.case-pills>span{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border:1px solid var(--line-2);border-radius:8px;background:#ffffff08;font-size:12.5px}
.u-dot{width:8px;height:8px;border-radius:2px;background:var(--olive-soft)}.u-critical{background:var(--red)}.u-high{background:var(--amber)}.u-medium{background:var(--blue)}
.case-facts{display:flex;flex-wrap:wrap;gap:12px 36px;margin:16px 0 14px}
.case-facts dt{color:var(--muted);font:600 10.5px var(--sans);letter-spacing:.09em;text-transform:uppercase}
.case-facts dd{margin:4px 0 0;font-size:14px}
.tabs{display:flex;gap:4px;flex-wrap:wrap}
.tabs a{padding:6px 14px;border-radius:8px;color:var(--muted);font-size:13px}
.tabs a:hover{color:var(--text);background:#ffffff0a;text-decoration:none}
.tabs a.on{background:#eef0e6;color:#11130d;font-weight:600}
.case-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.25fr);gap:14px;margin:0 0 14px}
.finding-case .cardx h3{margin:0 0 12px;font:600 15px/1.3 var(--sans)}
.finding-case .cardx h3+h3,.finding-case .cardx * + h3{margin-top:18px}
.kv{margin:0}.kv>div{display:flex;justify-content:space-between;gap:16px;padding:8px 0;border-bottom:1px solid var(--line-2)}
.kv>div:last-child{border-bottom:0}.kv dt{color:var(--muted);font-style:italic;font-size:13px}.kv dd{margin:0;text-align:right;font-size:13.5px}
.radar{display:block;width:100%;max-width:440px;height:auto;margin:0 auto}
.radar .grid{fill:none;stroke:#ffffff1f}.radar .axis{stroke:#ffffff17}
.radar .max{fill:#d8b24c0d;stroke:var(--gold);stroke-dasharray:4 4;stroke-width:1.2}
.radar .val{fill:#a3b35c40;stroke:var(--olive-soft);stroke-width:1.6}
.radar .pt{fill:var(--olive-soft)}
.radar text{fill:var(--text-2);font:500 11px var(--sans)}
.legend-row{display:flex;gap:14px;color:var(--muted);font-size:12px}
.legend-row span{display:inline-flex;align-items:center;gap:6px}.legend-row i{width:8px;height:8px;border-radius:50%}
.lg-val{background:var(--olive-soft)}.lg-max{border:1.5px dashed var(--gold)}
.cardx>header .legend-row{margin-left:auto}
.finding-case .record-actions{margin:14px 0 0}
.score-details{margin:12px 0 0}
/* settings and reports */
.status-list{display:grid;gap:0;margin:0;padding:0;list-style:none}
.status-list li{display:grid;grid-template-columns:10px minmax(0,1fr);gap:2px 12px;padding:10px 0;border-bottom:1px solid var(--line-2)}
.status-list li:last-child{border-bottom:0}
.status-list .sev{grid-row:1/3;margin-top:7px;width:8px;height:8px;border-radius:50%;background:var(--ok)}
.status-list .sev.amber{background:var(--amber)}.status-list .sev.red{background:var(--red)}
.status-list small{display:block;color:var(--muted);font-size:12.5px}
.report-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(240px,100%),1fr));gap:14px;margin:0 0 16px}
.report-grid .cardx{display:grid;align-content:start;gap:8px}
.report-grid h2{margin:0;font:600 15px var(--sans)}.report-grid p{margin:0;color:var(--muted);font-size:13px}
.report-grid .btn{justify-self:start;margin-top:6px;display:inline-flex;gap:8px;align-items:center}
.report-grid .btn svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.report-grid .cardx:first-child .btn{background:var(--olive);border-color:var(--olive);color:#f3f5e6}
.cardx.workflow>summary{list-style:none;display:flex;justify-content:space-between;align-items:center}
.cardx.workflow>summary::after{content:"+";color:var(--muted);font-size:18px}.cardx.workflow[open]>summary::after{content:"–"}
.cardx.workflow[open]>summary{margin-bottom:12px}
.cardx h2{margin-top:0}
.finding-case{max-width:none}
.finding-case .cardx>header{flex-direction:column;align-items:flex-start;gap:6px}
.cardx>header .legend-row{margin-left:0}
.radar{max-width:520px}
.page-actions{align-items:center}
.page-actions .btn.sq{display:grid;place-items:center;width:38px;height:36px;padding:0}
.page-actions .btn.sq svg{width:16px;height:16px}
@media(max-width:900px){.case-grid{grid-template-columns:minmax(0,1fr)}.page-head{align-items:flex-start}}

/* ---- simplified Devices and Network pages ---- */
.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 12px}
.toolbar-actions{display:flex;gap:8px}
.quick-tabs{display:flex;gap:4px;padding:3px;border:1px solid var(--line-2);border-radius:10px;background:#ffffff06}
.quick-tabs a{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:7px;color:var(--muted);font-size:13px}
.quick-tabs a:hover{color:var(--text);text-decoration:none}
.quick-tabs a.on{background:#ffffff14;color:#fff}
.quick-tabs span{padding:0 7px;border-radius:999px;background:#ffffff12;font-size:11.5px;font-variant-numeric:tabular-nums}
.search-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 14px}
.search-row input[name=q]{flex:1 1 280px;max-width:460px}
.search-row .inline-check{margin:0;color:var(--muted)}
.device-table td{vertical-align:middle;max-width:none}
.device-table td:first-child{min-width:220px}
.device-table .device b{display:block;font-size:14px;font-weight:600}
.device-table .device small{display:block;margin-top:2px;color:var(--muted);font-size:12px}
.missing{color:var(--muted);font-style:italic}
.imp{display:inline-flex;align-items:center;gap:7px;font-size:13px}
.imp::before{content:"";width:8px;height:8px;border-radius:50%;background:#9a9d88}
.imp-critical::before{background:var(--red)}.imp-high::before{background:var(--amber)}.imp-medium::before{background:var(--blue)}.imp-low::before{background:var(--olive-soft)}
.state{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;font-size:12.5px;white-space:nowrap}
.state.good{background:#8fa84a1f;color:#c9dc95}.state.good::before{content:"✓"}
.state.warn{background:#e39b3a1f;color:#f1c78d}.state.warn::before{content:"!";font-weight:700}
a.state.warn:hover{background:#e39b3a33;text-decoration:none}
.row-action{text-align:right;width:1%}
.row-action .btn{padding:5px 14px;border-radius:8px;font-size:12.5px;background:#ffffff0a;border-color:var(--line-2)}
details.more{margin-top:6px}details.more>summary{font-size:12px;color:var(--muted)}
details.more[open]>summary{margin-bottom:6px}
details.more .kv{max-width:420px}details.more .kv>div{padding:5px 0}
.pager-row{margin-top:10px}
.minis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:0 0 14px}
.mini{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:2px 12px;align-items:center;padding:12px 16px;border:1px solid var(--line-2);border-radius:12px;background:#11130f;color:var(--text)}
.mini:hover{border-color:#ffffff26;text-decoration:none}
.mini span{font-size:13px;color:var(--text-2)}.mini b{grid-row:1/3;grid-column:2;font:600 22px var(--display);font-variant-numeric:tabular-nums}
.mini b.red{color:var(--red)}.mini b.amber{color:var(--amber)}
.mini small{font-size:11.5px;color:var(--muted)}
@media(max-width:1200px){.minis{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.minis{grid-template-columns:minmax(0,1fr)}}
.panel{position:relative}
.upload-card{display:grid;grid-template-columns:minmax(0,1fr) minmax(280px,420px);gap:18px 28px;align-items:start;margin:0 0 14px}
.upload-card h2{margin:0 0 6px;font:600 16px var(--sans)}
.upload-card p{margin:0;color:var(--muted);font-size:13.5px;max-width:60ch}
.upload-card form{display:grid;gap:10px}
.file-pick{display:grid;gap:6px;margin:0;padding:14px;border:1.5px dashed #a3b35c55;border-radius:12px;background:#a3b35c0a}
.file-pick span{font-weight:600}
.file-pick input[type=file]{max-width:100%}
.upload-card form>button{justify-self:start}
.upload-card details.more label{margin:6px 0 4px}
.events-table td{vertical-align:middle}
.events-table td small{display:block;margin-top:2px;color:var(--muted);font-size:12px}
.events-table .arrow{color:var(--muted)}
.flag{display:inline-block;padding:2px 9px;border-radius:999px;background:#e39b3a1f;color:#f1c78d;font-size:12px}
@media(max-width:900px){.upload-card{grid-template-columns:minmax(0,1fr)}.toolbar-actions{width:100%}}
@media(max-width:1200px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.cards.dash-main{grid-template-columns:minmax(0,1fr)}}
@media(max-width:900px){body{grid-template-columns:minmax(0,1fr)}aside{position:static;height:auto;margin:10px 10px 0;border-radius:14px;padding:14px}.brand{padding:0 0 4px}.dataset{max-width:100%}.new-row{margin:10px 0}.site-navigation nav a[aria-current]::before{display:none}main{padding:14px 12px 40px}}
@media(max-width:560px){.kpis{grid-template-columns:minmax(0,1fr)}.alert-board{grid-template-columns:minmax(0,1fr)}}

/* ---- Kanban board (CyFocus findings board) ---- */
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
main:has(.alert-board) .triage-viewbar{position:absolute;top:58px;right:18px;margin:0;gap:6px;align-items:center}
main:has(.alert-board){position:relative}
.triage-viewbar a{display:inline-grid;place-items:center;min-width:36px;height:34px;padding:0 10px;border:1px solid var(--line-2);border-radius:8px;background:#ffffff08;color:var(--text-2)}
.triage-viewbar a[aria-current]{background:#ffffff17;border-color:#ffffff26;color:#fff}
.triage-viewbar a:hover{text-decoration:none;background:#ffffff12}
.triage-viewbar svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}
.triage-viewbar .triage-reports{margin-inline-start:6px;padding:0 18px;font-weight:600;font-size:13px}
main:has(.alert-board) h1{margin-bottom:14px}
main:has(.alert-board)>.secondary-navigation{margin-bottom:16px}
main:has(.alert-board) .triage-viewbar+p.muted{margin:0 0 12px;font-size:13px}
main:has(.alert-board) .filter-bar{display:flex;align-items:center;gap:6px;margin:0 0 14px;max-width:520px}
main:has(.alert-board) .filter-bar{align-items:end}main:has(.alert-board) .filter-bar label{margin:0;flex:1;font-size:12.5px;color:var(--muted)}main:has(.alert-board) .filter-bar input{margin-top:5px}
main:has(.alert-board) .filter-bar input{margin:0;padding:6px 12px;font-size:13px;border-radius:8px;background:#ffffff08;border-color:var(--line-2)}
main:has(.alert-board) .filter-bar input::placeholder{color:var(--muted)}
main:has(.alert-board) .filter-bar button{padding:6px 14px;font-size:13px;border-radius:8px}
.filter-chips{display:flex;gap:8px;margin:-4px 0 16px}
.filter-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 6px 4px 10px;border:1px solid var(--line-2);border-radius:8px;background:#ffffff08;font-size:12.5px}
.filter-chip a{display:grid;place-items:center;width:20px;height:20px;border-radius:5px;color:var(--muted);font-size:15px}
.filter-chip a:hover{background:#ffffff14;color:#fff;text-decoration:none}
.alert-board{grid-template-columns:repeat(4,minmax(200px,1fr));gap:12px;margin:0;align-items:stretch}
.alert-column{display:flex;flex-direction:column;gap:10px;min-height:540px;padding:0 8px 12px;border:0;border-radius:10px;background:linear-gradient(180deg,#ffffff06,#ffffff03)}
.alert-column h2{display:flex;align-items:center;gap:8px;margin:0 -8px 4px;padding:10px 6px 12px;background:var(--bg);font:600 14px var(--sans);color:#fff}
.alert-column h2::before{content:none}
.alert-column .state{width:15px;height:15px;flex:none;fill:none;stroke:var(--text-2);stroke-width:1.6}
.col-progress .state{stroke:var(--high)}.col-progress .state .fill{fill:var(--high);stroke:none}
.col-resolved .state .disc{fill:var(--ok);stroke:none}.col-resolved .state .tick{stroke:#0b0d07;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.alert-count{color:var(--text-2);font-weight:500;letter-spacing:.08em}
.alert-column>.muted{margin:4px;font-size:12.5px}
.col-hint{margin:-10px 2px 4px;color:var(--muted);font-size:12px;line-height:1.4}
.board-legend{display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;margin:0 0 14px;color:var(--muted);font-size:12px}.board-legend span{display:inline-flex;align-items:center;gap:6px}.board-legend .zone-badge{min-width:24px;height:18px;font-size:9.5px}
.dots{font-size:18px}
.alert-card{display:grid;gap:4px;margin:0;padding:14px 14px 12px;border:1px solid #ffffff12;border-radius:8px;background:#ffffff0d;box-shadow:0 8px 20px #00000059;color:var(--muted);font-size:12.5px}
.alert-card:hover{background:#ffffff14;border-color:#ffffff24;text-decoration:none;transform:translateY(-1px)}
.card-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.alert-card strong{display:flex;align-items:center;gap:8px;min-width:0;color:#fff;font-size:14px;font-weight:500;overflow-wrap:anywhere}
.alert-card strong::before{content:none}
.sq{flex:none;width:8px;height:8px;border-radius:1px;background:var(--accent)}
.sq.critical{background:var(--crit)}.sq.high{background:#e2c84a}.sq.medium{background:var(--info)}
.dots{color:var(--muted);letter-spacing:.05em;font-size:14px;line-height:1}
.card-sub{padding-left:16px;color:var(--muted)}
.card-pair{padding-left:16px;font-size:12px}
.alert-card-meta{display:flex;align-items:center;justify-content:flex-start;gap:8px;margin-top:12px;padding-top:0;border-top:0;color:#e3e8dc;font-size:13px}
.when{display:inline-flex;align-items:center;gap:8px}
.cal{width:15px;height:15px;fill:none;stroke:#c9d0bf;stroke-width:1.3;stroke-linecap:round}
.alert-card-meta .alert-urgency{margin-inline-start:auto;font-size:11.5px}
.zone-badge{display:grid;place-items:center;min-width:26px;height:26px;padding:0 4px;border-radius:5px;font:700 10.5px var(--sans);color:#fff;background:#5c6b3a}
.zone-ot{background:#b8572a}.zone-it{background:#4f6b2a}.zone-dmz{background:#2f74a8}

.board-tip{margin:-6px 0 14px;color:var(--muted);font-size:12.5px}.board-tip b{color:var(--text);font-weight:600}
.board-status{margin:0 0 14px;padding:10px 14px;border:1px solid var(--line-2);border-left:1px solid var(--accent);border-radius:10px;background:#ffffff0a;font-size:13px}
.alert-card[draggable="true"]{cursor:grab}.alert-card[draggable="true"]:active{cursor:grabbing}
.alert-card.dragging{opacity:.35;transform:rotate(-2deg)}
.alert-card.saving{opacity:.6;pointer-events:none}
.drop-slot{display:none;min-height:92px;border:1.5px dashed #ffffff2e;border-radius:8px;background:repeating-linear-gradient(135deg,#ffffff05 0 6px,transparent 6px 12px)}
.alert-column.drop-ok{box-shadow:inset 0 0 0 1.5px var(--accent)}.alert-column.drop-ok .drop-slot{display:block;border-color:var(--accent)}
.alert-column.drop-no{opacity:.55}
.alert-board.is-dragging .alert-column{transition:opacity .15s,box-shadow .15s}
@media(max-width:1100px){.alert-board{grid-template-columns:repeat(2,minmax(0,1fr))}main:has(.alert-board) .triage-viewbar{position:static;margin:0 0 14px}}
@media(max-width:560px){.alert-board{grid-template-columns:minmax(0,1fr)}.alert-column{min-height:0}}

/* ---- dashboard: status line, coverage, mini-strip, grouped findings ---- */
.status-line{margin:0 0 10px;color:var(--text-2);font:600 15px/1.4 var(--sans)}
.coverage{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;margin:0 0 14px;color:var(--muted);font-size:13px}
.coverage-label{color:var(--text-2);font-weight:600}
.coverage a{font-weight:600}
.mini-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:0 0 14px}
.mini-strip .mini{grid-template-columns:minmax(0,1fr) auto;min-height:44px}
.mini-strip .mini .none{color:var(--muted);font-size:14px;font-weight:400}
@media(max-width:900px){.mini-strip{grid-template-columns:minmax(0,1fr)}}

/* grouped findings table */
.findings.grouped{border-collapse:collapse;width:100%}
.findings.grouped th,.findings.grouped td{text-align:left;vertical-align:top}
.cve-group+.cve-group .cve-head{border-top:1px solid var(--line-2)}
.cve-head th{padding:14px 12px 8px;background:var(--overlay-1);font-size:14px;font-weight:600;color:#fff}
.cve-head .mono{margin-right:10px}
.cve-sev{display:inline-block;margin-left:4px;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:600;background:var(--overlay-3);color:var(--text-2)}
.cve-kev{display:inline-block;margin-left:6px;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700;background:#e5534b1a;color:#f2a19c}
.cve-count{display:inline-block;margin-left:8px;color:var(--muted);font-size:12px;font-weight:400}
.cve-about{display:inline;margin-left:8px}
.cve-about>summary{display:inline;color:var(--muted);font-size:12px;font-weight:400;cursor:pointer}
.cve-about>summary:hover{color:var(--text)}
.cve-about p{margin:8px 0 4px;color:var(--text-2);font-size:13px;font-weight:400;max-width:72ch;line-height:1.5}
.cve-group tr:not(.cve-head) td{padding:8px 12px;border-top:1px solid #ffffff0a;font-size:13px}
.cve-group tr:not(.cve-head) td small{display:block;margin-top:2px;color:var(--muted);font-size:12px}
.panel-note{margin:0 0 8px;color:var(--muted);font-size:13px;line-height:1.45}

/* finding-more disclosure inside table rows */
.finding-more{margin:6px 0 0}
.finding-more>summary{color:var(--link);font-size:12px;cursor:pointer}
.finding-more>summary:hover{text-decoration:underline}
.finding-more[open]>summary{margin-bottom:8px}
.finding-more p{margin:4px 0;font-size:13px;color:var(--text-2);line-height:1.5}
.finding-more p b{color:#fff;font-weight:600}
.finding-more small{color:var(--muted)}
.finding-more .btn{display:inline-flex;align-items:center;gap:8px;margin-top:8px;padding:6px 14px;border-radius:8px;font-size:12.5px;font-weight:600;background:#ffffff0a;border:1px solid var(--line-2);color:#e6e8dc;text-decoration:none}
.finding-more .btn:hover{background:#ffffff14}

/* card-body: flat inner container, no nested panel border */
.card-body{padding:0}.card-body p{margin:4px 0}.card-body .alert{padding-inline:0}.card-body .empty{padding:8px 0}
p,.empty,.panel-note,.lead,.muted{text-wrap:pretty}

/* findings table mobile: hide zone column so status + urgency stay visible */
@media(max-width:700px){.findings.grouped th:nth-child(2),.findings.grouped td:nth-child(2){display:none}.cve-group tr:not(.cve-head) td{padding:6px 8px}}

/* empty-state KPIs */
.kpi-empty .label .chip{display:none}
.kpi-empty .viz{display:none}
.kpi-empty .none{display:block;font:600 22px var(--display);color:var(--muted);margin-top:4px}

/* ---- legibility: text floor 12px, hover contrast, tap targets ---- */
.zone-badge{font-size:12px}
.chip{font-size:12px}
.feed small{font-size:12px}
.case-facts dt{font-size:12px}
.alert-card-meta .alert-urgency{font-size:12px}
a:hover{color:#f3f5e6}
button.primary:hover,.btn.primary:hover,.primary-action:hover,.plus:hover{color:#f3f5e6}
@media(max-width:900px){.chip,.feed a,.steps-next .btn,.card-foot .btn,.row-action .btn,.finding-more>summary,.coverage a,.mini{min-height:44px;display:inline-flex;align-items:center}}

/* ---- reduced motion ---- */
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto!important}.alert-card:hover{transform:none}.alert-card.dragging{transform:none}.alert-board.is-dragging .alert-column{transition:none}}
"""


GLOSSARY = {
    "CVE": "A public ID for one known security flaw, for example CVE-2024-1234.",
    "KEV": "CISA's catalog of vulnerabilities with documented exploitation. Membership raises urgency; it does not establish an attack on this device.",
    "Modbus": "A common industrial protocol that lets controllers read from and write to equipment. Unexpected writes can change how a machine behaves.",
    "Zeek": "A passive network-monitoring tool. Phylax imports its logs.",
    "Urgency score": "A 0 to 12 score built from visible rules: known exploitation, flaw severity, how important the device is, whether the match is confirmed, and its network zone. Every point is listed under 'Why this score'.",
    "Confirmed affected": "The device's vendor, product and version match the flaw's affected list, and the device's identity was verified.",
    "Possibly affected": "Vendor and product match, but the version or the device's identity is not certain. Someone should check.",
    "Needs review": "Not enough information to decide either way.",
    "Not affected": "Checked against this flaw, and it does not apply to this device.",
    "Identity review": "Devices whose make, model or version is not known well enough to check for flaws. Phylax never guesses these from an IP address.",
    "Zone": "IT is the office network, OT is the equipment and control network, and DMZ is the buffer between them.",
    "Intelligence": "Public vulnerability information Phylax has downloaded or loaded: NVD, CISA KEV and CISA ICS advisories.",
    "Remediation plan": "A suggested fix list. It is guidance only: nothing is changed automatically and a person must approve it.",
}

PLAIN_STATUS = {
    "CONFIRMED_MATCH": "Confirmed affected",
    "POTENTIAL_MATCH": "Possibly affected",
    "NEEDS_REVIEW": "Needs review",
    "NO_MATCH_TO_THIS_ADVISORY": "Not affected",
}


ICONS = {
    'grid': '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    'server': '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
    'pulse': '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    'shield': '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    'bell': '<path d="M6 9a6 6 0 0112 0c0 6 2 7 2 7H4s2-1 2-7"/><path d="M10 20a2 2 0 004 0"/>',
    'file': '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/>',
    'gear': '<circle cx="12" cy="12" r="3"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4"/>',
    'arrow': '<path d="M7 17L17 7M9 7h8v8"/>',
    'help': '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 115 0c0 1.5-2.5 2-2.5 3.5M12 17h.01"/>',
    'device': '<rect x="4" y="5" width="16" height="11" rx="2"/><path d="M8 20h8M12 16v4"/>',
    'search': '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
    'check': '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16 9.8"/>',
    'id': '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M5.8 16c.6-1.6 1.8-2.4 3.2-2.4s2.6.8 3.2 2.4M14.5 10h4M14.5 13.5h3"/>',
    'home': '<path d="M4 11l8-6.5 8 6.5"/><path d="M6 10v9h12v-9"/>',
    'download': '<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14"/>',
    'update': '<path d="M4 12a8 8 0 0113.7-5.7L20 8"/><path d="M20 4v4h-4M20 12a8 8 0 01-13.7 5.7L4 16"/><path d="M4 20v-4h4"/>',
}

NAV_ICONS = {'/': 'grid', '/assets': 'server', '/network': 'pulse', '/intelligence': 'shield', '/triage': 'bell', '/reports': 'file', '/settings': 'gear'}


def icon(name: str) -> str:
    return f'<svg viewBox="0 0 24 24" aria-hidden="true">{ICONS.get(name, "")}</svg>'


def kpi(label: str, value, sub: str = "", visual: str = "", chip: str = "", tone: str = "", href: str = "", glyph: str = "", color: str = "olive", empty: str = "") -> str:
    glyph_html = f'<span class="kpi-ico">{icon(glyph)}</span>' if glyph else ""
    if empty:
        inner = (f'<span class="label"><span class="name">{glyph_html}{html.escape(label)}</span></span>'
                 f'<b class="none" aria-hidden="true">&mdash;</b><small>{html.escape(empty)}</small>')
        return f'<a class="kpi kpi-empty k-{color}" href="{html.escape(href, quote=True)}">{inner}</a>' if href else f'<div class="kpi kpi-empty k-{color}">{inner}</div>'
    chip_html = f'<span class="chip {tone}">{html.escape(chip)}</span>' if chip else ""
    inner = (f'<span class="label"><span class="name">{glyph_html}{html.escape(label)}</span>{chip_html}</span><b>{value}</b>'
             f'<small>{html.escape(sub)}</small>' + (f'<span class="viz">{visual}</span>' if visual else ""))
    return f'<a class="kpi k-{color}" href="{html.escape(href, quote=True)}">{inner}</a>' if href else f'<div class="kpi k-{color}">{inner}</div>'


def spark(values, classes=()) -> str:
    peak = max(list(values) + [1])
    return '<span class="spark" aria-hidden="true">' + "".join(
        f'<i class="{classes[i] if i < len(classes) else ""}" style="height:{max(10, round(100 * v / peak))}%"></i>' for i, v in enumerate(values)) + "</span>"


def gauge(value: float, maximum: float, label: str, tone: str = "") -> str:
    share = 0 if maximum <= 0 else max(0.0, min(1.0, value / maximum))
    length = 94.25
    return (f'<svg class="gauge {tone}" viewBox="0 0 74 44" role="img" aria-label="{html.escape(label)}">'
            f'<path class="trk" d="M7 39a30 30 0 0 1 60 0"/>'
            f'<path class="arc" d="M7 39a30 30 0 0 1 60 0" stroke-dasharray="{share * length:.1f} {length}"/></svg>')


def term(key: str, label: str | None = None) -> str:
    tip = GLOSSARY.get(key, "")
    if not tip:return html.escape(label or key)
    return f'<details class="term"><summary>{html.escape(label or key)}</summary><p>{html.escape(tip)}</p></details>'


def glossary_page() -> str:
    items = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(v)}</dd>" for k, v in GLOSSARY.items())
    return layout("Glossary", f'<dl class="gloss">{items}</dl>', "/glossary", lead="Plain-language meanings of the terms used in Phylax.")


def ring(value: float, maximum: float, label: str, tone: str = "none") -> str:
    circumference = 113.1
    filled = 0 if maximum <= 0 else max(0.0, min(1.0, value / maximum)) * circumference
    return (f'<svg class="ring ring-{tone}" viewBox="0 0 44 44" role="img" aria-label="{html.escape(label)}">'
            f'<circle class="trk" cx="22" cy="22" r="18"/><circle class="arc" cx="22" cy="22" r="18" stroke-dasharray="{filled:.1f} {circumference}"/>'
            f'<text x="22" y="22">{html.escape(label)}</text></svg>')


def layout(title: str, body: str, active: str = "", lead: str = "", heading: str | None = None, *, asset_id: str = '',
           crumbs: list | None = None, actions: str = '') -> str:
    parent = next((root for root, (_, items) in SECONDARY_NAV.items()
                   if any(href == active for href, _ in items)), '/network' if active=='/evidence' else active)
    secondary = ""
    if parent in SECONDARY_NAV:
        label, items = SECONDARY_NAV[parent]
        def destination(href):
            if asset_id and href in {'/assets','/processes'}:
                return ('/assets/edit' if href=='/assets' else href)+'?'+urlencode({'asset_id':asset_id})
            return href
        secondary = f'<nav class="secondary-navigation" aria-label="{html.escape(label)}">' + "".join(
            f'<a href="{html.escape(destination(href),quote=True)}"' + (' aria-current="page"' if href == active else '')
            + f'>{html.escape(text)}</a>' for href, text in items) + '</nav>'
    groups = "".join(
        f'<p class="nav-group-label">{html.escape(label)}</p><nav aria-label="{html.escape(label)}">'
        + "".join(f'<a href="{href}"' + (' aria-current="page"' if href == parent else "") + f">{icon(NAV_ICONS.get(href, ''))}{html.escape(text)}</a>" for href, text in items)
        + "</nav>"
        for label, items in NAV
    )
    current = title
    document_title = title
    if title in PAGE_GUIDE:
        heading, plain = PAGE_GUIDE[title]
        lead = html.escape(plain)
        current = heading
        document_title = heading
    lead_html = f'<p class="lead">{lead}</p>' if lead else ""
    section = next(((href, text) for _, items in NAV for href, text in items if href == parent), None)
    if crumbs is None:
        crumbs = []
        if section and section[0] != '/':
            crumbs.append(section)
        if not section or section[1] != (heading or title):
            crumbs.append((None, heading or title))
    trail = f'<a href="/" aria-label="Dashboard">{icon("home")}</a>' + "".join(
        '<span class="sep" aria-hidden="true">›</span>'
        + (f'<a href="{html.escape(href, quote=True)}">{html.escape(text)}</a>' if href else f'<span class="here">{text if text.startswith("<") else html.escape(text)}</span>')
        for href, text in crumbs)
    head = (f'<div class="page-head"><div class="page-title"><nav class="crumbs" aria-label="You are here">{trail}</nav>'
            f'<h1>{html.escape(heading or title)}</h1></div>' + (f'<div class="page-actions">{actions}</div>' if actions else '') + '</div>')
    body = _empty_states(body)
    return (
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Phylax · {html.escape(document_title)}</title><style>{CSS}</style>"
        f'<body><a class="skip-link" href="#main-content">Skip to main content</a><aside><a class="brand" href="/" aria-label="Phylax home"><svg viewBox="0 0 24 24" aria-hidden="true"><path class="shield" d="M12 2.2 20.6 5.6V12c0 4.6-3.6 8-8.6 9.8C7 20 3.4 16.6 3.4 12V5.6Z"/><rect class="eye" x="9.4" y="9.4" width="5.2" height="5.2"/></svg><span><b>Phylax</b><small>OT/IT exposure review</small></span></a>'
        f'<div class="new-row"><a class="primary-action" href="/?import=1#import-data">Add data</a><a class="plus" href="/assets/edit" aria-label="Add asset manually" title="Add asset manually">+</a></div>'
        f'<p class="current-location">Current page: {html.escape(current)}</p><div class="site-navigation desktop-navigation">{groups}</div>'
        f'<details class="site-navigation mobile-navigation"><summary>Navigation</summary><div>{groups}</div></details>'
        f'<div class="aside-foot"><a class="help" href="/glossary">{icon("help")}Help &amp; Docs</a></div></aside>'
        f'<main id="main-content" tabindex="-1">{head}{lead_html}{secondary}{body}</main></body></html>'
    )


def status_marker(status: str) -> str:
    cls = STATUS_CLASS.get(status, "none")
    label = PLAIN_STATUS.get(status)
    # Markers also occur inside linked priority cards; keep them noninteractive.
    inner = html.escape(label or status.replace("_", " ").capitalize())
    return f'<span class="st st-{cls}">{inner}</span>'
