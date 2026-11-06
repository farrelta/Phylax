"""Shared page chrome and stylesheet for every operator page.

Fonts are system stacks on purpose: the app is offline-first and its CSP
(default-src 'self') would block any web font.
"""
from __future__ import annotations
import html
from urllib.parse import urlencode

NAV = (
    ("Workspace", (("/", "Overview"), ("/assets", "Assets"), ("/network", "Monitoring"),
                   ("/intelligence", "Intelligence"), ("/triage", "Triage"),
                   ("/reports", "Reports"), ("/settings", "Settings"))),
)

# Keep bookmarked routes available within their operator task.
SECONDARY_NAV = {
    "/assets": ("Asset tools", (("/assets", "Inventory"), ("/approvals", "Approvals"),
        ("/discovery", "IT discovery"), ("/software", "Software"),
        ("/changes", "Changes"), ("/processes", "Operational context"))),
    "/network": ("Monitoring views", (("/network", "Events"), ("/attack-surface", "Attack surface"))),
    "/intelligence": ("Intelligence views", (("/intelligence", "CVEs"), ("/intelligence/ics", "CISA ICS advisories"))),
    "/triage": ("Triage views", (("/triage", "Alerts"), ("/remediation", "Remediation plans"))),
    "/settings": ("Settings views", (("/settings", "Sources and collectors"),
        ("/policy", "Network policy"), ("/glossary", "Glossary"))),
}


STATUS_CLASS = {
    "CONFIRMED_MATCH": "crit",
    "POTENTIAL_MATCH": "high",
    "NEEDS_REVIEW": "info",
    "NO_MATCH_TO_THIS_ADVISORY": "none",
}

CSS = """
:root{color-scheme:dark;--bg:#0a0d12;--surface:#0f141c;--raised:#141a24;--line:#222b38;--text:#e6e8ec;--muted:#a6b0be;--accent:#e5252b;--link:#8fb2e6;--action:#b82029;--action-hover:#a51a23;--control-line:#65758b;--placeholder:#a6b0be;--control-hover:#2a2e33;
--graph-edge:#7b8797;--graph-node:#1a1c1f;--graph-process:#16202a;--zone-it:#58a272;--zone-ot:#d98a2b;--zone-dmz:#7ba3d9;--zone-unknown:#868d96;
--crit:#ff4d4d;--high:#e8923a;--info:#6aa3e8;--none:#6b727b;--ok:#58a272;
--sans:"IBM Plex Sans","Segoe UI",Helvetica,Arial,sans-serif;--display:"Bahnschrift","Segoe UI Variable Display","Segoe UI",Helvetica,Arial,sans-serif;--mono:"IBM Plex Mono",ui-monospace,Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(900px 420px at 18% -8%,#16223a55,transparent 70%),var(--bg);color:var(--text);font:15px/1.55 var(--sans);display:grid;grid-template-columns:208px minmax(0,1fr);min-height:100vh}
::selection{background:#324969;color:#fff}input,textarea{caret-color:var(--link)}html{scrollbar-color:#516078 var(--bg)}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--link);outline-offset:2px}
aside{border-right:1px solid var(--line);padding:18px 0;position:sticky;top:0;height:100vh;overflow:auto}
.brand{display:flex;align-items:center;gap:10px;padding:0 18px 20px;color:var(--text)}
.brand:hover{text-decoration:none}
.brand svg{flex:none;width:30px;height:30px}
.brand .shield{fill:#e5252b14;stroke:var(--accent);stroke-width:1.7;stroke-linejoin:round}
.brand .eye{fill:var(--accent)}
.brand b{display:block;font:700 17px/1 var(--display);letter-spacing:.2em;text-transform:uppercase}
.brand small{display:block;margin-top:5px;color:var(--muted);font:400 12px/1.4 var(--sans)}
aside .nav-group-label{margin:16px 18px 4px;color:var(--muted);font:600 12px var(--sans);text-transform:uppercase;letter-spacing:.08em}
aside nav a{display:block;padding:6px 18px;color:var(--text);border-left:2px solid transparent}
aside nav a:hover{background:var(--surface);text-decoration:none}
aside nav a[aria-current]{border-left-color:var(--accent);background:linear-gradient(90deg,#e5252b1f,transparent);color:#fff}
.secondary-navigation{display:flex;flex-wrap:wrap;gap:4px 18px;margin:0 0 24px;border-bottom:1px solid var(--line)}
.secondary-navigation a{display:inline-flex;align-items:center;min-height:44px;padding:6px 0;color:var(--muted);border-bottom:2px solid transparent}
.secondary-navigation a[aria-current]{color:var(--text);border-bottom-color:var(--accent)}
main{padding:24px 32px 48px;min-width:0;max-width:1400px;overflow-wrap:anywhere}
h1{font:600 26px/1.15 var(--display);margin:0 0 6px;letter-spacing:.005em}
h2{font:500 12px var(--mono);text-transform:uppercase;letter-spacing:.08em;margin:30px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h2::before{content:"// ";color:var(--accent)}
.lead,.muted,small{color:var(--muted)}.lead{margin:0 0 18px;max-width:78ch}
small{font-size:13px}
.nw{white-space:nowrap}.mono,td code{font-family:var(--mono);font-size:12px}
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
.advisory-preview{margin:0;max-width:65ch}.advisory-content{margin-top:10px}.advisory-text{white-space:pre-wrap;max-height:24rem;overflow:auto;max-width:65ch;margin-top:12px;padding:10px;line-height:1.6;background:var(--bg);border:1px solid var(--line)}
button,.btn{flex-shrink:0;overflow-wrap:normal;word-break:normal;max-width:100%}
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
"""


GLOSSARY = {
    "CVE": "A public ID for one known security flaw, for example CVE-2024-1234.",
    "KEV": "CISA's catalog of vulnerabilities with documented exploitation. Membership raises urgency; it does not establish an attack on this device.",
    "Modbus": "A common industrial protocol that lets controllers read from and write to equipment. Unexpected writes can change how a machine behaves.",
    "Zeek": "A passive network-monitoring tool. Phylax imports its logs; separately approved active IT discovery uses its own bounded probes.",
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


def layout(title: str, body: str, active: str = "", lead: str = "", heading: str | None = None, *, asset_id: str = '') -> str:
    parent = next((root for root, (_, items) in SECONDARY_NAV.items()
                   if any(href == active for href, _ in items)), '/network' if active=='/evidence' else active)
    secondary = ""
    if parent in SECONDARY_NAV:
        label, items = SECONDARY_NAV[parent]
        def destination(href):
            if asset_id and href in {'/assets','/processes','/discovery'}:
                return ('/assets/edit' if href=='/assets' else href)+'?'+urlencode({'asset_id':asset_id})
            return href
        secondary = f'<nav class="secondary-navigation" aria-label="{html.escape(label)}">' + "".join(
            f'<a href="{html.escape(destination(href),quote=True)}"' + (' aria-current="page"' if href == active else '')
            + f'>{html.escape(text)}</a>' for href, text in items) + '</nav>'
    groups = "".join(
        f'<p class="nav-group-label">{html.escape(label)}</p><nav aria-label="{html.escape(label)}">'
        + "".join(f'<a href="{href}"' + (' aria-current="page"' if href == parent else "") + f">{html.escape(text)}</a>" for href, text in items)
        + "</nav>"
        for label, items in NAV
    )
    current = title
    lead_html = f'<p class="lead">{lead}</p>' if lead else ""
    return (
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Phylax · {html.escape(title)}</title><style>{CSS}</style>"
        f'<body><a class="skip-link" href="#main-content">Skip to main content</a><aside><a class="brand" href="/" aria-label="Phylax home"><svg viewBox="0 0 24 24" aria-hidden="true"><path class="shield" d="M12 2.2 20.6 5.6V12c0 4.6-3.6 8-8.6 9.8C7 20 3.4 16.6 3.4 12V5.6Z"/><rect class="eye" x="9.4" y="9.4" width="5.2" height="5.2"/></svg><span><b>Phylax</b><small>OT/IT exposure review</small></span></a>'
        f'<p class="current-location">Current page: {html.escape(current)}</p><div class="site-navigation desktop-navigation">{groups}</div>'
        f'<details class="site-navigation mobile-navigation"><summary>Navigation</summary><div>{groups}</div></details></aside>'
        f'<main id="main-content" tabindex="-1"><h1>{html.escape(heading or title)}</h1>{lead_html}{secondary}{body}</main></body></html>'
    )


def status_marker(status: str) -> str:
    cls = STATUS_CLASS.get(status, "none")
    label = PLAIN_STATUS.get(status)
    # Markers also occur inside linked priority cards; keep them noninteractive.
    inner = html.escape(label or status.replace("_", " ").capitalize())
    return f'<span class="st st-{cls}">{inner}</span>'
