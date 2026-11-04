"""Shared page chrome and stylesheet for every operator page.

Fonts are system stacks on purpose: the app is offline-first and its CSP
(default-src 'self') would block any web font.
"""
from __future__ import annotations
import html

NAV = (
    ("Monitor", (("/", "Overview"), ("/network", "Network events"), ("/attack-surface", "Attack surface"))),
    ("Data", (("/assets", "Inventory"), ("/intelligence", "Intelligence"))),
    ("Act", (("/remediation", "Remediation"), ("/policy", "Network policy"))),
    ("Output", (("/reports", "Reports"), ("/settings", "Sources and settings"), ("/glossary", "Glossary"))),
)

STATUS_CLASS = {
    "CONFIRMED_MATCH": "crit",
    "POTENTIAL_MATCH": "high",
    "NEEDS_REVIEW": "info",
    "NO_MATCH_TO_THIS_ADVISORY": "none",
}

CSS = """
:root{--bg:#0a0d12;--surface:#0f141c;--raised:#141a24;--line:#222b38;--text:#e6e8ec;--muted:#a6b0be;--accent:#e5252b;--link:#8fb2e6;
--crit:#ff4d4d;--high:#e8923a;--info:#6aa3e8;--none:#6b727b;--ok:#58a272;
--sans:"IBM Plex Sans","Segoe UI",Helvetica,Arial,sans-serif;--display:"Bahnschrift","Segoe UI Variable Display","Segoe UI",Helvetica,Arial,sans-serif;--mono:"IBM Plex Mono",ui-monospace,Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(900px 420px at 18% -8%,#16223a55,transparent 70%),var(--bg);color:var(--text);font:15px/1.55 var(--sans);display:grid;grid-template-columns:208px minmax(0,1fr);min-height:100vh}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--link);outline-offset:2px}
aside{border-right:1px solid var(--line);padding:18px 0;position:sticky;top:0;height:100vh;overflow:auto}
.brand{display:flex;align-items:center;gap:10px;padding:0 18px 20px;color:var(--text)}
.brand:hover{text-decoration:none}
.brand svg{flex:none;width:30px;height:30px}
.brand .shield{fill:#e5252b14;stroke:var(--accent);stroke-width:1.7;stroke-linejoin:round}
.brand .eye{fill:var(--accent)}
.brand b{display:block;font:700 17px/1 var(--display);letter-spacing:.2em;text-transform:uppercase}
.brand small{display:block;margin-top:5px;color:var(--muted);font:400 10px/1.2 var(--mono);letter-spacing:.08em;text-transform:uppercase}
aside h6{margin:16px 18px 4px;color:var(--muted);font:600 11px var(--sans);text-transform:uppercase;letter-spacing:.08em}
aside nav a{display:block;padding:6px 18px;color:var(--text);border-left:2px solid transparent}
aside nav a:hover{background:var(--surface);text-decoration:none}
aside nav a[aria-current]{border-left-color:var(--accent);background:linear-gradient(90deg,#e5252b1f,transparent);color:#fff}
main{padding:24px 32px 48px;min-width:0;max-width:1400px}
h1{font:600 26px/1.15 var(--display);margin:0 0 6px;letter-spacing:.005em}
.eyebrow{margin:0 0 6px;color:var(--accent);font:500 12px var(--mono);letter-spacing:.1em;text-transform:uppercase}
h2{font:500 12px var(--mono);text-transform:uppercase;letter-spacing:.08em;margin:30px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h2::before{content:"// ";color:var(--accent)}
.lead,.muted,small{color:var(--muted)}.lead{margin:0 0 18px;max-width:78ch}
small{font-size:13px}
.nw{white-space:nowrap}.mono,td code{font-family:var(--mono);font-size:12px}
.stats{display:flex;flex-wrap:wrap;margin:0 0 20px;padding:0;border:1px solid var(--line);background:var(--surface);box-shadow:0 8px 24px #00000040}
.stats div{padding:10px 18px;border-right:1px solid var(--line);min-width:120px}
.stats div:last-child{border-right:0}
.stats dt{color:var(--muted);font-size:13px}
.stats dd{margin:0;font:500 20px var(--mono)}
.stats .hot dd{color:var(--crit)}
.steps{margin:0 0 22px;padding:0;list-style:none;display:flex;flex-wrap:wrap;gap:12px}
.steps li{flex:1 1 260px;border:1px solid var(--line);background:var(--surface);padding:10px 12px}
.steps b{display:block;font-size:13px;color:var(--muted);font-weight:600;margin-bottom:6px}
.steps form{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:0 0 6px}
button,.btn{font:inherit;background:var(--raised);color:var(--text);border:1px solid #3a4046;border-radius:2px;padding:4px 10px;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,.btn:hover{background:#2a2e33;text-decoration:none}
button.primary,.btn.primary{background:var(--accent);color:#fff;border-color:var(--accent);font-weight:600}
button.primary:hover,.btn.primary:hover{background:#f03a40}
a.link{display:inline-block;margin-right:12px}
input,select,textarea{font:inherit;background:var(--bg);color:var(--text);border:1px solid #3a4046;border-radius:2px;padding:4px 8px;max-width:100%}
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
.split{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:20px;align-items:start}
.alert{display:flex;justify-content:space-between;gap:12px;padding:10px 12px;border-bottom:1px solid var(--line)}
.alert p{margin:3px 0}.alert form{margin:0}
code.block{display:block;margin-top:4px;padding:6px 8px;background:var(--bg);border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;color:var(--muted)}
small .mono{font-size:11px}
.plan p{margin:6px 0}.plan b{color:var(--muted);font-weight:600}.plan ul,.plan ol{margin:4px 0 10px;padding-left:20px}
.plan form{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.plan form input{flex:1 1 200px}
.focus{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin:0 0 22px}
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
.term{border-bottom:1px dotted var(--muted);cursor:help;position:relative}
.term:hover::after,.term:focus::after{content:attr(data-tip);position:absolute;left:0;top:calc(100% + 6px);z-index:5;width:max-content;max-width:280px;padding:8px 10px;background:#1b2330;border:1px solid #3a4658;color:var(--text);font:400 13px/1.4 var(--sans);text-transform:none;letter-spacing:0;white-space:normal;box-shadow:0 8px 24px #000a}
.headline{margin:0 0 22px;padding:14px 18px;border-left:3px solid var(--accent);background:var(--surface);font-size:17px;line-height:1.5;box-shadow:0 8px 24px #00000040}
.headline small{display:block;margin-top:4px;font-size:14px}
.gloss dt{margin-top:16px;font-weight:600}.gloss dd{margin:2px 0 0;color:var(--muted);max-width:75ch}
article.panel{padding:14px 16px;margin-bottom:14px}
.empty{color:var(--muted);padding:18px;text-align:left}
.notice{background:var(--raised);border-left:3px solid var(--high);padding:8px 12px;margin:0 0 14px}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 12px}.controls form{margin:0}
details{margin-top:8px}summary{cursor:pointer;color:var(--link)}
footer{color:var(--muted);font-size:12px;margin-top:28px;max-width:100ch}
.panel>svg{width:100%;min-width:700px;max-height:680px}.legend{color:var(--muted);font-size:12px;padding:0 12px 10px}
@media(max-width:900px){body{grid-template-columns:1fr}aside{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;align-items:center;padding:8px 0}
.brand{padding:0 18px}aside h6{display:none}aside nav{display:flex;flex-wrap:wrap}aside nav a{border-left:0;padding:4px 12px}
.split{grid-template-columns:1fr}main{padding:18px 16px 40px}}
@media(max-width:1250px){.split{grid-template-columns:1fr}}
"""


GLOSSARY = {
    "CVE": "A public ID for one known security flaw, for example CVE-2024-1234.",
    "KEV": "CISA's list of flaws that attackers are known to be using right now. Being on it raises urgency.",
    "Modbus": "A common industrial protocol that lets controllers read from and write to equipment. Unexpected writes can change how a machine behaves.",
    "Zeek": "Free network-monitoring software. Phylax only reads its log files and never sends traffic itself.",
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
    return f'<span class="term" tabindex="0" data-tip="{html.escape(tip, quote=True)}">{html.escape(label or key)}</span>'


def glossary_page() -> str:
    items = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(v)}</dd>" for k, v in GLOSSARY.items())
    return layout("Glossary", f'<dl class="gloss">{items}</dl>', "/glossary", lead="Plain-language meanings of the terms used in Phylax.")


def ring(value: float, maximum: float, label: str, tone: str = "none") -> str:
    circumference = 113.1
    filled = 0 if maximum <= 0 else max(0.0, min(1.0, value / maximum)) * circumference
    return (f'<svg class="ring ring-{tone}" viewBox="0 0 44 44" role="img" aria-label="{html.escape(label)}">'
            f'<circle class="trk" cx="22" cy="22" r="18"/><circle class="arc" cx="22" cy="22" r="18" stroke-dasharray="{filled:.1f} {circumference}"/>'
            f'<text x="22" y="22">{html.escape(label)}</text></svg>')


def layout(title: str, body: str, active: str = "", lead: str = "", heading: str | None = None) -> str:
    groups = "".join(
        f"<h6>{label}</h6><nav>"
        + "".join(f'<a href="{href}"' + (' aria-current="page"' if href == active else "") + f">{html.escape(text)}</a>" for href, text in items)
        + "</nav>"
        for label, items in NAV
    )
    group = next((label for label, items in NAV if any(href == active for href, _ in items)), "phylax")
    lead_html = f'<p class="lead">{lead}</p>' if lead else ""
    return (
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Phylax · {html.escape(title)}</title><style>{CSS}</style>"
        f'<body><aside><a class="brand" href="/" aria-label="Phylax home"><svg viewBox="0 0 24 24" aria-hidden="true"><path class="shield" d="M12 2.2 20.6 5.6V12c0 4.6-3.6 8-8.6 9.8C7 20 3.4 16.6 3.4 12V5.6Z"/><rect class="eye" x="9.4" y="9.4" width="5.2" height="5.2"/></svg><span><b>Phylax</b><small>OT/IT exposure review</small></span></a>{groups}</aside>'
        f'<main><p class="eyebrow">// {html.escape(group.lower())}</p><h1>{html.escape(heading or title)}</h1>{lead_html}{body}</main></body></html>'
    )


def status_marker(status: str) -> str:
    cls = STATUS_CLASS.get(status, "none")
    label = PLAIN_STATUS.get(status)
    inner = term(label) if label else html.escape(status.replace("_", " ").capitalize())
    return f'<span class="st st-{cls}">{inner}</span>'
