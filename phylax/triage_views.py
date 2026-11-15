"""Decision evidence first; original records remain inspectable separately."""
from urllib.parse import urlencode
from .ui import verbatim, e,field,select,form,hidden,raw_record,evidence_lines,evidence_url
from .triage import ZONE_RULE, triage, zone_pair
from .theme import PLAIN_STATUS
from .topology import alert_topology_url


def details_list(pairs):
    return '<dl class="facts">'+''.join('<div><dt>'+e(label)+'</dt><dd>'+e(value if value not in ('',None) else 'Unknown')+'</dd></div>' for label,value in pairs)+'</dl>'


def policy_lines(policy):
    lines=[]
    if 'source_zone' in policy:
        lines.append('Denied zone pair: '+zone_pair(policy))
        lines.append('Policy version: '+policy['policy_id'])
    if 'configured_authorized_writers' in policy:
        lines.append('Authorized writers: '+(', '.join(policy['configured_authorized_writers']) or 'No writers permitted.'))
    if 'expected_communications' in policy:
        for r in policy['expected_communications']:
            lines.append('Allowed: '+str(r.get('source_ip','unknown'))+' → '+str(r.get('destination_ip','unknown'))+' · '+str(r.get('protocol') or 'any protocol')+' · destination port '+str(r.get('destination_port') if r.get('destination_port') is not None else 'any'))
    for key in ('approved_maintenance_windows_utc','maintenance_windows_utc','configured_windows','approved_windows'):
        if key in policy:
            if not policy[key]:lines.append('No approved maintenance windows in this policy.')
            for window in policy[key]:
                days=['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
                lines.append('Approved UTC window: '+', '.join(days[d] for d in window.get('days',[]) if type(d) is int and 0<=d<7)+' '+str(window.get('start','unknown'))+'–'+str(window.get('end','unknown')))
    return lines or ['Review the policy evidence in the original record.']


BOARD_ICONS = {
    'open': '<circle cx="8" cy="8" r="6"/>',
    'triaged': '<circle cx="8" cy="8" r="6" stroke-dasharray="2.2 2"/>',
    'progress': '<circle cx="8" cy="8" r="6"/><path class="fill" d="M8 2a6 6 0 0 1 0 12z"/>',
    'resolved': '<circle class="disc" cx="8" cy="8" r="7"/><path class="tick" d="M5 8.2l2 2 4-4.2"/>',
}
CALENDAR = ('<svg class="cal" viewBox="0 0 16 16" aria-hidden="true"><rect x="2.5" y="3.5" width="11" height="10" rx="2"/>'
            '<path d="M2.5 6.5h11M5.5 2v3M10.5 2v3"/></svg>')


BOARD_JS = r'''(function () {
  var board = document.querySelector('.alert-board');
  if (!board) return;
  var status = document.getElementById('board-status');
  var dragged = null;
  function say(key) {
    var source = document.querySelector('[data-msg="' + key + '"]');
    if (!source || !status) return;
    status.textContent = source.textContent;
    status.hidden = false;
    clearTimeout(say.timer);
    say.timer = setTimeout(function () { status.hidden = true; }, 7000);
  }
  function verdict(column) {
    if (!dragged) return 'none';
    var from = dragged.getAttribute('data-from'), to = column.getAttribute('data-column');
    if (from === to) return 'same';
    if (from === '0' && to === '1') return 'ok';
    if (from === '2' || from === '3') return 'locked';
    if (to === '0') return 'undo';
    if (to === '2') return 'resolve';
    if (to === '3') return 'plan';
    return 'locked';
  }
  function clear() {
    Array.prototype.forEach.call(board.querySelectorAll('.alert-column'), function (c) {
      c.classList.remove('drop-ok', 'drop-no');
    });
  }
  Array.prototype.forEach.call(board.querySelectorAll('.alert-card[draggable="true"]'), function (card) {
    card.addEventListener('dragstart', function (event) {
      dragged = card;
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', card.getAttribute('data-alert'));
      setTimeout(function () { card.classList.add('dragging'); board.classList.add('is-dragging'); }, 0);
    });
    card.addEventListener('dragend', function () {
      card.classList.remove('dragging');
      board.classList.remove('is-dragging');
      clear();
      dragged = null;
    });
  });
  Array.prototype.forEach.call(board.querySelectorAll('.alert-column'), function (column) {
    column.addEventListener('dragover', function (event) {
      var result = verdict(column);
      if (result === 'none' || result === 'same') return;
      event.preventDefault();
      event.dataTransfer.dropEffect = result === 'ok' ? 'move' : 'none';
      clear();
      column.classList.add(result === 'ok' ? 'drop-ok' : 'drop-no');
    });
    column.addEventListener('dragleave', function (event) {
      if (!column.contains(event.relatedTarget)) column.classList.remove('drop-ok', 'drop-no');
    });
    column.addEventListener('drop', function (event) {
      event.preventDefault();
      var result = verdict(column);
      clear();
      if (result !== 'ok') { if (result !== 'same' && result !== 'none') say(result); return; }
      var token = document.querySelector('input[name="csrf_token"]');
      if (!token) return;
      var form = document.createElement('form');
      form.method = 'post';
      form.action = '/triage/ack';
      form.hidden = true;
      var values = {csrf_token: token.value, category: dragged.getAttribute('data-kind'),
                    alert_id: dragged.getAttribute('data-alert'), view: 'board'};
      values.page = board.getAttribute('data-page');
      if (board.getAttribute('data-search')) values.q = board.getAttribute('data-search');
      Object.keys(values).forEach(function (name) {
        var input = document.createElement('input');
        input.type = 'hidden'; input.name = name; input.value = values[name];
        form.appendChild(input);
      });
      document.body.appendChild(form);
      var slot = column.querySelector('.drop-slot');
      column.insertBefore(dragged, slot);
      dragged.classList.add('saving');
      say('saving');
      form.submit();
    });
  });
})();
'''


def alert_board(rows, filters, page, store=None):
    # Column ids stay stable (0 review, 1 acknowledged, 2 resolved); 3 is added for planned fixes.
    columns = {'Needs review': (0, 'open', []), 'Acknowledged': (1, 'triaged', []),
               'Fix plan recorded': (3, 'progress', []), 'Resolved': (2, 'resolved', [])}
    for row in rows:
        plan = None
        if store and row.get('finding_id') and row['state'] != 'resolved':
            plan = store.get_remediation_plan(row['finding_id'])
        state = 'Resolved' if row['state'] == 'resolved' else (
            'Fix plan recorded' if plan else 'Acknowledged' if row['acknowledged'] else 'Needs review')
        plan_label = ''
        if plan:
            status = 'Plan drafted' if plan['status'] == 'Recommended' else plan['status']
            plan_label = '<span class="card-pair">' + e(status) + '</span>'
        priority = row['urgency']['priority']
        score = row['urgency'].get('score')
        name = row['context'].get('hostname') or row['ip']
        zone = (row['context'].get('zone') or '').upper() or '?'
        title = row.get('cve_id') or row.get('rule_id', '').replace('_', ' ').title() or row['explanation']
        url = '/triage?' + urlencode({'alert': row['alert_id'], 'view': 'board', 'page': page, **filters})
        url += '#alert-' + row['alert_id']
        pair = ''
        if row.get('rule_id') == ZONE_RULE:
            policy = row['evidence']['policy']
            pair = '<span class="card-pair">' + e(zone_pair(policy)) + '</span>'
        detail = verbatim(name) + (' • ' + e(str(score)) if score is not None else '')
        acknowledge_card = ''
        if state == 'Needs review':
            fields = hidden('alert_id', row['alert_id']) + hidden('category', row['category'])
            fields += hidden('view', 'board') + hidden('page', page) + hidden('q', filters.get('q', ''))
            acknowledge_card = '<div class="board-ack">' + form('/triage/ack', fields, 'Acknowledge this alert') + '</div>'
        columns[state][2].append(
            '<a class="alert-card" href="' + e(url) + '" draggable="true" data-alert="' + e(row['alert_id'])
            + '" data-kind="' + e(row['category']) + '" data-from="' + str(columns[state][0]) + '">'
            '<span class="card-top"><strong><i class="sq ' + e(priority) + '" aria-hidden="true"></i>' + e(title) + '</strong>'
            '<span class="dots" aria-hidden="true">›</span></span>'
            '<span class="card-sub">' + detail + '</span>' + pair + plan_label
            + '<span class="alert-card-meta"><span class="when">' + CALENDAR + '<time datetime="' + e(row['timestamp']) + '">'
            + e(row['timestamp'][:10]) + '</time></span>'
            '<span class="alert-urgency ' + e(priority) + '">' + e(priority.replace('_', ' ').title()) + '</span>'
            '<span class="zone-badge zone-' + e(zone.lower()) + '" title="' + e(zone) + ' zone">' + e(zone[:3]) + '</span></span></a>' + acknowledge_card)
    sections = []
    hints = {'open': 'New. Nobody has looked at these yet.', 'triaged': 'Someone has acknowledged the alert.',
             'progress': 'Open a card to review the finding and its saved plan.', 'resolved': 'No longer active.'}
    for label, (index, kind, cards) in columns.items():
        heading = f'alert-column-{index}'
        sections.append(
            f'<section class="alert-column col-{kind}" data-column="{index}" aria-labelledby="{heading}">'
            f'<h2 id="{heading}"><svg class="state" viewBox="0 0 16 16" aria-hidden="true">{BOARD_ICONS[kind]}</svg>'
            f'{e(label)} <span class="alert-count">{len(cards)}</span></h2><p class="col-hint">{e(hints[kind])}</p>'
            + (''.join(cards) or '<p class="muted">No alerts in this column.</p>') + '<div class="drop-slot" aria-hidden="true"></div></section>')
    legend = ('<p class="board-legend"><span><i class="sq critical"></i>Critical</span><span><i class="sq high"></i>High</span>'
              '<span><i class="sq medium"></i>Medium</span><span><i class="sq"></i>Low</span>'
              '<span><b class="zone-badge zone-ot">OT</b>Equipment network</span><span><b class="zone-badge zone-it">IT</b>Office network</span>'
              '<span><b class="zone-badge zone-dmz">DMZ</b>Buffer zone</span><span class="muted">Number after the device = urgency score out of 12</span></p>')
    messages = ('<div class="board-msgs" hidden>'
                '<span data-msg="saving">Marking the alert as acknowledged…</span>'
                '<span data-msg="undo">An acknowledgement cannot be undone. It stays as a record that someone reviewed the alert.</span>'
                '<span data-msg="resolve">Alerts move to Resolved by themselves when the evidence no longer shows the problem, for example after a policy change.</span>'
                '<span data-msg="plan">To draft a fix plan, open the vulnerability finding.</span>'
                '<span data-msg="locked">This card cannot be moved by hand. Open it to see its details.</span></div>')
    tip = ('<p class="board-tip board-tip-drag">Tip: drag a card from Needs review to Acknowledged to mark it as seen. '
           'You can also open a card and use its button.</p>'
           '<p class="board-tip board-tip-touch">Tap Acknowledge this alert to move a card to Acknowledged. '
           'Tap the card to read its details first.</p>')
    return (legend + tip + '<p class="board-status" id="board-status" role="status" hidden></p>' + messages
            + '<div class="alert-board" data-search="' + e(filters.get('q', '')) + '" data-page="' + e(page) + '">' + ''.join(sections) + '</div>'
            + '<script src="/static/board.js" defer></script>')


def triage_page(store,query,offset):
    alert_id=query.get('alert',[''])[0]
    list_keys = ('category', 'priority', 'acknowledged')
    view = query.get('view', [''])[0]
    # Preserve bookmarked list filters and case links from before the board became the default.
    list_request = any(query.get(key, [''])[0] for key in (*list_keys, 'case', 'history'))
    board = not alert_id and (view == 'board' or (view != 'list' and not list_request))
    filters = {'q': query.get('q', [''])[0]}
    if not board:
        filters.update({key: query.get(key, [''])[0] for key in list_keys})
    if alert_id:
        board_context = {'view': 'board'} if view == 'board' else {}
        if board_context:
            board_context.update({key: query[key][0] for key in ('q', 'page') if query.get(key) and query[key][0]})
        back = '/triage' + ('?' + urlencode(board_context) if board_context else '')
        rows,count=triage(store,alert_id=alert_id,history=True)
        body='<p><a href="'+e(back)+'">Back to alerts</a></p>'
        if not rows:
            return body+'<p class="empty">This alert could not be found.</p>',count
    else:
        history = board or query.get('history', [''])[0] == 'yes'
        rows,count=triage(store,limit=50,offset=offset,filters=filters,history=history)
        values = {k: v for k, v in filters.items() if v}
        list_url = '/triage?' + urlencode({**values, 'view': 'list'})
        board_values = {'q': filters['q']} if filters['q'] else {}
        board_url = '/triage?' + urlencode({**board_values, 'view': 'board'})
        view_controls = '<nav class="triage-viewbar" aria-label="Alert views">'
        for label, url, current, glyph in (('List view', list_url, not board, '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 4.5h10M3 8h10M3 11.5h10"/></svg>'), ('Board view', board_url, board, '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="2.5" y="2.5" width="4.5" height="4.5" rx="1"/><rect x="9" y="2.5" width="4.5" height="4.5" rx="1"/><rect x="2.5" y="9" width="4.5" height="4.5" rx="1"/><rect x="9" y="9" width="4.5" height="4.5" rx="1"/></svg>')):
            view_controls += '<a class="view-toggle" href="' + e(url) + '"' + (' aria-current="page"' if current else '') + ' title="' + label + '">' + glyph + '<span class="vh">' + label + '</span></a>'
        view_controls += '</nav>'
        if board:
            intro = 'Open a card to inspect the alert. Column counts apply to this page.'
        elif history:
            intro = 'Showing alert history. Acknowledgement records review.'
        else:
            intro = f'{count} active alert(s)' + (' matching your filters.' if any(filters.values()) else '.')
            intro += ' Acknowledgement records review; it does not resolve a finding, approve a device or grant scan permission.'
        body = '<div class="triage-toolbar"><p class="muted">' + intro + '</p>' + view_controls + '</div>'
        mode = {'view': 'board' if board else 'list'}
        if not board and history:
            mode['history'] = 'yes'
        clear_url = '/triage?' + urlencode(mode)
        body += '<form method="get" class="filter-bar">' + ''.join(hidden(k, v) for k, v in mode.items()) + field('q','Search asset, address, CVE or explanation',filters['q'])
        if board:
            body += '<button>Search</button></form>'
            if filters['q']:
                body += ('<div class="filter-chips"><span class="filter-chip">Search <span class="muted">is</span> <b>' + e(filters['q'])
                         + '</b><a href="' + e(clear_url) + '" aria-label="Clear search">×</a></span></div>')
            return body + alert_board(rows, values, query.get('page', ['1'])[0], store), count
        body+=select('category','Category',[('','All categories'),('exposure','Vulnerability exposure'),('network','Network policy'),('endpoint','Device management')],filters['category'])
        body+=select('priority','Urgency',[('','All urgency levels')]+[(v,v.replace('_',' ').title()) for v in ('critical','high','medium','low','not_applicable')],filters['priority'])
        body+=select('acknowledged','Review state',[('','All review states'),('no','Unacknowledged'),('yes','Acknowledged')],filters['acknowledged'])
        body+='<button>Filter alerts</button><a href="' + e(clear_url) + '">Clear filters</a></form>'
        if not rows:
            return body+('<p class="empty">No alerts match these filters. <a href="' + e(clear_url) + '">Clear filters</a>.</p>' if any(filters.values()) else '<p class="empty">No active alerts in stored data. <a href="/network">Inspect imported events</a> or <a href="/settings">check source and collector health</a>. No alerts does not establish safety.</p>'),count
    for row in rows:
        asset=row['context'];ctx=asset.get('operational_context',{});urgency=row['urgency'];ev=row['evidence']
        name=asset.get('hostname') or row['ip'];category={'exposure':'Vulnerability exposure','network':'Network policy','endpoint':'Device management'}[row['category']]
        applicability=PLAIN_STATUS.get(row['applicability'],'Not assessed (network / management alert)')
        priority=urgency['priority'].replace('_',' ').title()
        rule=row.get('rule_id','').replace('_',' ').title()
        title=row.get('cve_id') or rule or row['explanation']
        review='Acknowledged' if row['acknowledged'] else 'Unacknowledged'
        missing=len(row.get('missing_evidence') or [])
        cue=(str(missing)+' missing evidence item'+('' if missing==1 else 's') if missing else 'No missing evidence recorded') if row['category']=='exposure' else ('Observed policy event' if row['category']=='network' else 'Identity evidence needs review')
        zone_violation=row.get('rule_id')==ZONE_RULE
        expanded=alert_id or query.get('case',[''])[0]==row['alert_id']
        body+='<details class="triage-case" id="alert-'+e(row['alert_id'])+'"'+(' open' if expanded else '')+'><summary>'
        address=' <span class="mono">'+e(row['ip'])+'</span>' if name!=row['ip'] else ''
        body+='<span class="case-title">'+verbatim(name)+address+'</span><span class="case-subject">'+e(title)+'</span>'
        body+='<span class="case-state">'+e(priority)+' urgency · '+e(category)+' · '+e(review)+'</span><span class="case-meta">'+e(row['timestamp'])+' UTC · '+e(cue)+'</span><span class="case-inspect">Inspect alert</span></summary><div class="case-detail triage-record">'
        back_values={k:v for k,v in filters.items() if v}
        if not alert_id and history:
            back_values['history'] = 'yes'
        back_values.update(view='list',page=query.get('page',['1'])[0],case=row['alert_id'])
        case_values = {'alert': alert_id, **board_context} if alert_id else back_values
        return_to = '/triage?' + urlencode(case_values) + '#alert-' + row['alert_id']
        if row['state']=='resolved' and row['category']=='network':
            body+='<p class="notice">This policy alert was resolved after reevaluation.</p>'
        elif row['state']=='resolved':
            body+='<p class="notice">This device management alert was resolved.</p>'
        if zone_violation:
            obs=row['observed'];policy=ev['policy']
            body+='<h3>Observed connection</h3><p class="mono">'+e(obs['source_ip']+' → '+obs['destination_ip'])+'</p>'
            body+='<p>'+e(row['explanation'])+'</p><ul>'+''.join('<li>'+e(line)+'</li>' for line in policy_lines(policy))+'</ul>'
            body+='<div class="record-actions"><a class="btn" href="'+e(evidence_url(ev['event_ref'],return_to))+'">Original event</a>'
            body+='<a href="'+e(alert_topology_url(row['alert_id']))+'">Show on topology</a></div>'
            body+=details_list([('Event / update time UTC',row['timestamp']),('Protocol',obs['protocol']),
                                ('Destination port',obs['destination_port']),('Severity',row['severity']),
                                ('Evidence confidence',row['evidence_confidence'])])
        else:
            body+='<p class="muted">Owner: '+(verbatim(ctx['owner']) if ctx.get('owner') else e('Unknown'))+' · Supports: '+(verbatim(', '.join(p['name'] for p in asset['processes'])) if asset.get('processes') else e('No confirmed process relationships'))+'</p>'
            body+='<p>'+e(row['explanation'])+'</p>'
            body+=details_list([('Address',row['ip']),('Event / update time UTC',row['timestamp']),('Severity',row['severity']),('Applicability',applicability),('Evidence confidence',row['evidence_confidence']),('Review state',review)])
            body+='<h3>Observed evidence</h3>'
        if row['category']=='network' and not zone_violation:
            obs=row['observed']
            body+=details_list([('Source',obs['source_ip']),('Destination',obs['destination_ip']),('Destination port',obs['destination_port']),('Protocol',obs['protocol']),('Operation',obs['operation']),('Rule',row['rule_id'].replace('_',' ').title())])
            body+='<h3>Configured policy</h3><ul>'+''.join('<li>'+e(line)+'</li>' for line in policy_lines(ev.get('policy',{})))+'</ul>'
        elif row['category']=='exposure':
            body+=evidence_lines(ev)
            body+='<h3>Missing evidence</h3><ul>'+''.join('<li>'+e(v)+'</li>' for v in (row.get('missing_evidence') or ['None recorded for this assessment.']))+'</ul>'
        elif row['category']=='endpoint':
            body+=details_list([('Monitored subnet',ev.get('subnet','Unknown')),('Observed MAC',ev.get('mac') or 'Unknown; no reliable MAC evidence'),('Management state',ev.get('status','unknown').replace('_',' ').title())])
            observations=ev.get('evidence',[])
            if observations:body+='<p>Latest identity evidence: '+e(observations[0].get('observed_at','Unknown'))+' · '+e(observations[0].get('source_file','Unknown source'))+'</p>'
        body+='<h3>Operational context</h3>'+details_list([('Location',' / '.join(v for v in (ctx.get('site'),ctx.get('location')) if v)),('Asset criticality',asset.get('criticality','unknown'))])
        if zone_violation and (ctx.get('owner') or asset.get('processes')):
            body+=details_list([('Owner',ctx.get('owner')),('Supports',', '.join(p['name'] for p in asset['processes']))])
        score=urgency['score']
        body+='<details class="score-details"><summary>Why '+e(priority.lower())+' urgency'+(' · score '+e(score) if score is not None else '')+'</summary><p>Rule '+e(urgency['rule_version'])+'. Severity, applicability and urgency are separate.</p><ul>'
        for factor in urgency['factors']:
            value=factor['value']
            if isinstance(value,bool):value='Yes' if value else 'No'
            else:value=PLAIN_STATUS.get(str(value),str(value))
            body+='<li>'+e(factor['input'])+': '+e(value)+' · +'+e(factor['points'])+'</li>'
        body+='</ul>'+''.join('<p class="muted">'+e(v)+'</p>' for v in urgency.get('uncertainty',[]))+'</details>'
        links=[]
        if asset.get('asset_id') and not row.get('finding_id') and row['category'] != 'endpoint':
            links.append('<a href="/assets/edit?'+e(urlencode({'asset_id':asset['asset_id']}))+'">Review device identity</a>')
        if row.get('finding_id'):links.append('<a href="/?'+e(urlencode({'finding_id':row['finding_id']}))+'#finding-'+e(row['finding_id'])+'">Open vulnerability finding</a>')
        if row['category']=='network':
            if not zone_violation:
                links.append('<a href="'+e(evidence_url(ev.get('event_ref',''),return_to))+'">Original event</a>')
            links.append('<a href="/policy">Review network policy</a>')
        if row['category']=='endpoint':links.append('<a href="/approvals?'+e(urlencode({'ip':row['ip']}))+'">Review management approval</a>')
        body+='<div class="record-actions">'+' '.join(links)
        if not row['acknowledged'] and row['state']=='active':
            fields=hidden('category',row['category'])+hidden('alert_id',row['alert_id'])
            if alert_id:
                fields += hidden('alert', alert_id) + ''.join(hidden(k, v) for k, v in board_context.items())
            else:
                fields += hidden('view', 'list') + hidden('case', row['alert_id'])
                if history:
                    fields += hidden('history', 'yes')
                fields+=''.join(hidden('filter_category' if k=='category' else k,v) for k,v in filters.items())+hidden('page',query.get('page',['1'])[0])
            body+=form('/triage/ack',fields,'Acknowledge this alert')
        body+='</div>'+raw_record(row)+'</div></details>'
    return body,count
