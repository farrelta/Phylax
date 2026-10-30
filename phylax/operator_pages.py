"""Local operator configuration and manual inventory forms."""
from __future__ import annotations
import html
import json
from .ai import AIConfig
from .core import Store,ASSET_FIELDS,ASSET_TYPES,ZONES,CRITICALITIES,CONFIDENCES
from .monitoring import active_policy


def shell(title: str, body: str) -> str:
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Phylax · {html.escape(title)}</title>
    <style>body{{background:#0a1118;color:#edf5f7;font:16px/1.5 system-ui;max-width:1050px;margin:32px auto;padding:0 24px}}a{{color:#63e0b4}}input,select,textarea,button{{display:block;margin:8px 0 18px;padding:10px;background:#111d27;color:#edf5f7;border:1px solid #476573;border-radius:6px;max-width:100%;box-sizing:border-box}}textarea{{width:100%}}label{{display:block}}pre{{white-space:pre-wrap}}</style>
    <body><nav><a href="/">Overview</a> · <a href="/assets">Inventory</a> · <a href="/policy">Network policy</a> · <a href="/settings">Settings/sources</a> · <a href="/reports">Reports</a></nav><h1>{html.escape(title)}</h1>{body}</body></html>'''


def inventory_form(store: Store, asset_id: str = '') -> str:
    row=store.connection.execute('SELECT * FROM assets WHERE asset_id=?',(asset_id,)).fetchone() if asset_id else None
    if asset_id and not row:raise ValueError('Asset not found')
    asset=dict(row) if row else {}
    options={'asset_type':ASSET_TYPES,'zone':ZONES,'criticality':CRITICALITIES,'identity_confidence':CONFIDENCES,'verified':{'true','false'}}
    body='<p>Enter operator-supplied identity evidence. Confirmed matches require verified high-confidence identity; an IP address never establishes a model or version.</p><form method="post" action="/assets/save">'
    for name in ASSET_FIELDS:
        value=str(asset.get(name,''))
        if name=='verified':value='true' if asset.get(name) else 'false'
        if name=='identification_source' and not value:value='manual'
        if name=='last_seen' and not value:value=''
        body+=f'<label>{html.escape(name.replace("_"," ").title())}'
        if name in options:
            defaults={'asset_type':'unknown','zone':'unknown','criticality':'medium','identity_confidence':'low','verified':'false'}
            value=value or defaults[name]
            body+=f'<select name="{name}">'+''.join(f'<option value="{html.escape(v)}"'+(' selected' if v==value else '')+f'>{html.escape(v)}</option>' for v in sorted(options[name]))+'</select>'
        else:
            required=' required' if name=='ip_address' else ''
            readonly=' readonly' if name=='asset_id' and asset_id else ''
            body+=f'<input name="{name}" value="{html.escape(value,quote=True)}" maxlength="4000"{required}{readonly}>'
        body+='</label>'
    body+='<button>Save inventory and reassess findings</button></form>'
    return shell('Edit asset' if row else 'Add asset',body)


def policy_page(store: Store) -> str:
    policy=active_policy(store)
    text=json.dumps(policy if policy is not None else {},indent=2)
    body='<p>Policies apply only to stored passive observations. An absent rule is not a deny-all rule. An explicit empty maintenance window list prohibits writes at all times; omit that key if no maintenance restriction is configured. Overnight windows use the start day; end times are exclusive.</p>'
    body+='<p>Keys: protected_assets, allowed_communications, authorized_writers, maintenance_windows_utc. Day numbers: Monday 0 through Sunday 6. Times are UTC.</p>'
    body+=f'<form method="post" action="/policy/apply"><label>Policy JSON<textarea name="policy_json" rows="24" maxlength="100000">{html.escape(text)}</textarea></label><button>Save policy and reevaluate stored events</button></form>'
    rows=store.connection.execute('SELECT policy_id,created_at FROM network_policies ORDER BY created_at DESC LIMIT 20').fetchall()
    body+='<h2>Stored policy versions</h2><ul>'+''.join(f'<li>{r["policy_id"]} · {r["created_at"]}</li>' for r in rows)+'</ul>'
    return shell('Passive network policy',body)


def settings_page(store: Store) -> str:
    config=AIConfig.from_env()
    description=f'Configured: {config.provider} · requested model {config.model} · timeout {config.timeout_seconds} seconds' if config else 'Hosted AI disabled: configure a provider, model and key in the server environment or project .env.'
    body='<h2>Hosted guidance</h2><p>'+html.escape(description)+'</p><p>Only trusted public feed snapshots are eligible for hosted requests. Local inventory, network events, policies and risk evidence stay on this host. Returned guidance remains unverified.</p><h2>Public intelligence sources</h2>'
    body+=(''.join('<p>'+html.escape(f"{r['source']} · {r['health']} · last success {r['last_success_at'] or 'never'} · {r['message']}")+'</p>' for r in store.source_health()) or '<p>No feed synchronization recorded.</p>')
    body+='<p>Source health is based on stored attempts and becomes stale after 24 hours. Opening this page performs no connectivity check.</p>'
    return shell('Settings and data sources',body)


def reports_page(store: Store) -> str:
    return shell('Reports','<p>Exports contain local evidence, uncertainty, source provenance and prioritization factors. Findings do not establish compromise.</p><p><a href="/report.json">JSON report</a> · <a href="/report.csv">CSV report</a> · <a href="/report.md">Markdown report</a> · <a href="/assets.csv">Inventory CSV</a></p>')
