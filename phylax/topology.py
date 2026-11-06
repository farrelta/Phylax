"""Bounded, server-rendered topology from stored evidence; no inferred paths."""
from collections import defaultdict
from unicodedata import east_asian_width
from urllib.parse import urlencode

from .ui import e, hidden, field, select, evidence_url

NODE_LIMIT = 24
LINK_LIMIT = 60
PROCESS_LIMIT = 12
NODE_WIDTH = 264
NODE_HEIGHT = 96
MANAGEMENT = {
    'approved': 'Approved', 'unmanaged': 'Unmanaged — needs review',
    'unauthorized': 'Unauthorized — explicitly blocked',
    'needs_identity_review': 'Identity needs review', 'unmonitored': 'Not monitored',
}
QUERY_KEYS = {'subnet','zone','criticality','management_status','since','until','node',
              'page','selected','q','zoom','processes'}


def values(query):
    return {key: str(value[0]) for key,value in query.items() if key in QUERY_KEYS and value}


def url(query, *, anchor="surface-details", **changes):
    params = {**query, **changes}
    return '/attack-surface?' + urlencode({k:v for k,v in params.items() if v not in ('',None)}) + '#'+anchor


def short(text, length):
    text = str(text)
    units=0
    for index,char in enumerate(text):
        units += 2 if east_asian_width(char) in {'W','F'} else 1
        if units > length:return text[:max(0,index-1)]+'…'
    return text


def icon(kind):
    if kind in {'PLC','RTU'}:
        return '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M7 8h3m4 0h3M7 12h3m4 0h3M7 16h3m4 0h3"/>'
    if kind in {'server','HMI','engineering workstation'}:
        return '<rect x="3" y="4" width="18" height="13" rx="1"/><path d="M9 21h6m-3-4v4"/>'
    if kind in {'network device','gateway'}:
        return '<rect x="2" y="6" width="20" height="12" rx="1"/><path d="M6 11v2m4-2v2m4-2v2m4-2v2"/>'
    return '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 2-3 4m0 3h.01"/>'


def label_bounds(label, x, y):
    units=sum(2 if east_asian_width(c) in {'W','F'} else 1 for c in label)
    return (x-3,y-13,x+units*7+5,y+5)


def overlaps(a,b):
    return a[0]<b[2] and a[2]>b[0] and a[1]<b[3] and a[3]>b[1]


def diagram(data, query):
    """Return graph markup and actual displayed totals with explicit limits."""
    observed = [n for n in data['nodes'] if n['observed']]
    search = query.get('q','').strip().casefold()
    selected = query.get('selected') or query.get('node','')
    degree = defaultdict(int)
    for edge in data['edges']:
        degree[edge['source_ip']] += 1
        degree[edge['destination_ip']] += 1
    def matches(n):return search in (n['identity']+' '+n['ip_address']).casefold()
    known_matches = [n for n in data['nodes'] if matches(n)] if search else []
    if not selected:
        candidates = known_matches if search else observed or data['nodes']
        if candidates:selected=candidates[0]['ip_address']
    ranked = sorted(observed,key=lambda n:(n['ip_address']!=selected, not matches(n) if search else False,
                                          -degree[n['ip_address']], n['ip_address']))
    nodes = ranked[:NODE_LIMIT]
    groups = defaultdict(list)
    for node in nodes:groups[node['zone']].append(node)
    zones = [z for z in ('unknown','IT','DMZ','OT') if z in groups]
    zones += sorted(set(groups)-set(zones))
    max_rows = max((len(group) for group in groups.values()),default=1)
    width = max(700,32+330*len(zones))
    bottom = 110+(max_rows-1)*164+NODE_HEIGHT+24
    position = {}; frames=[]; plates=[]
    for column,zone in enumerate(zones):
        x=(width-330*len(zones))/2+12+column*330
        frames.append(f'<rect class="topology-zone" x="{x}" y="24" width="304" height="{bottom-24}" rx="4"/>'
                      f'<text class="topology-zone-name" x="{x+18}" y="49">{e(zone.upper() if zone!="unknown" else "Unknown")} zone</text>'
                      f'<text class="topology-meta" x="{x+18}" y="68">'+('Zone not established' if zone=='unknown' else 'Grouping from inventory')+'</text>')
        offset=(max_rows-len(groups[zone]))*82
        for row,node in enumerate(groups[zone]):
            nx=x+20;ny=110+offset+row*164;ip=node['ip_address'];position[ip]=(nx,ny)
            current=(' is-selected' if ip==selected else '')+(' is-search-match' if search and matches(node) else '')
            state=MANAGEMENT.get(node['management_status'],'Unknown management state')
            plates.append(f'<a class="topology-node{current}" href="{e(url(query,selected=ip))}" aria-label="{e("Inspect "+node["identity"]+", "+ip)}"'+(' aria-current="true"' if ip==selected else '')+'>'
                          f'<title>{e(node["identity"])} · {e(ip)} · {e(node["asset_type"])} · {e(state)}</title>'
                          f'<g transform="translate({nx} {ny})"><rect class="topology-plate" width="264" height="96" rx="4"/>'
                          f'<svg x="14" y="15" width="24" height="24" viewBox="0 0 24 24" class="topology-icon" aria-hidden="true">{icon(node["asset_type"])}</svg>'
                          f'<text class="topology-name" x="48" y="31">{e(short(node["identity"],24))}</text>'
                          f'<text class="topology-ip" x="48" y="51">{e(ip)}</text>'
                          f'<text class="topology-state" x="15" y="79">{e(short(state,34))}</text></g></a>')
    pairs=defaultdict(list)
    for edge in data['edges']:
        if edge['source_ip'] in position and edge['destination_ip'] in position:
            pairs[(edge['source_ip'],edge['destination_ip'])].append(edge)
    paths=[];labels_omitted=0
    occupied=[(x-4,y-4,x+NODE_WIDTH+4,y+NODE_HEIGHT+4) for x,y in position.values()]
    for (source,destination),records in list(pairs.items())[:LINK_LIMIT]:
        sx,sy=position[source];dx,dy=position[destination]
        if source==destination:
            path=f'M {sx+NODE_WIDTH} {sy+30} h 14 v 36 h -14';lx=sx+NODE_WIDTH+2;ly=sy+20
        elif sx==dx and abs(sy-dy)<=164:
            start=sy if sy>dy else sy+NODE_HEIGHT;end=dy+NODE_HEIGHT if sy>dy else dy
            path=f'M {sx+132} {start} V {end}';lx=sx+144;ly=(start+end)/2-6
        elif sx==dx:
            gutter=sx+NODE_WIDTH+12
            path=f'M {sx+NODE_WIDTH} {sy+48} H {gutter} V {dy+48} H {dx+NODE_WIDTH}'
            lx=sx+8;ly=sy+NODE_HEIGHT+20
        else:
            start=sx+NODE_WIDTH if sx<dx else sx;end=dx if sx<dx else dx+NODE_WIDTH
            middle=(start+end)/2
            path=f'M {start} {sy+48} H {middle} V {dy+48} H {end}'
            lx=min(start,end)+5;ly=min(sy,dy)+36
        labels=sorted({(' '.join(filter(None,[(r['protocol'] or '').upper(),str(r['destination_port']) if r['destination_port'] is not None else '']))) or 'Metadata unknown' for r in records})
        label=labels[0]+(f' +{len(labels)-1}' if len(labels)>1 else '')
        title=source+' → '+destination+' · '+', '.join(labels)+' · '+str(sum(r['event_count'] for r in records))+' event(s)'
        label=short(label,22)
        bounds=label_bounds(label,lx,ly)
        label_markup=''
        if any(overlaps(bounds,box) for box in occupied):
            labels_omitted+=1
        else:
            occupied.append(bounds)
            label_markup=f'<text class="topology-link-label" x="{lx}" y="{ly}">{e(label)}</text>'
        paths.append(f'<a class="topology-edge" href="{e(evidence_url(records[0]["sample_event_ref"],url(query)))}" aria-label="{e("Inspect observed communication: "+title)}"><title>{e(title)}</title><path d="{path}" marker-end="url(#topology-arrow)"/>{label_markup}</a>')
    process_links=[p for p in data['process_links'] if p['ip_address'] in position]
    processes={p['process_id']:p for p in process_links}
    process_shapes=[];process_paths=[];shown_processes={}
    if query.get('processes')!='hide':
        process_rows=defaultdict(int)
        for index,(pid,process) in enumerate(list(processes.items())[:PROCESS_LIMIT]):
            x=position[process['ip_address']][0];y=bottom+78+process_rows[x]*84;process_rows[x]+=1;shown_processes[pid]=(x,y)
            process_shapes.append(f'<a class="topology-process" href="/processes?{e(urlencode({"asset_id":process["asset_id"]}))}" aria-label="{e("Review confirmed process support: "+process["name"])}"><title>{e(process["name"])}</title><rect x="{x}" y="{y}" width="264" height="56" rx="3"/><text x="{x+14}" y="{y+23}">{e(short(process["name"],31))}</text><text class="topology-meta" x="{x+14}" y="{y+42}">Operator-confirmed process</text></a>')
        for index,link in enumerate(process_links):
            if link['process_id'] not in shown_processes:continue
            sx,sy=position[link['ip_address']];dx,dy=shown_processes[link['process_id']]
            gutter=sx+NODE_WIDTH+18+(index%3)*3
            process_paths.append(f'<path class="topology-support" d="M {sx+NODE_WIDTH} {sy+72} H {gutter} V {dy+28} H {dx+NODE_WIDTH}"><title>{e("Operator-confirmed support: "+link["note"])}</title></path>')
    height=max([bottom+24]+[y+80 for x,y in shown_processes.values()])
    if nodes:
        graph=(f'<svg class="topology-svg" viewBox="0 0 {width} {height}" role="group" aria-label="Observed communication and confirmed process support">'
               '<defs><marker id="topology-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto"><path d="M1 1 7 4 1 7"/></marker></defs>'
               +''.join(frames+paths+process_paths+plates+process_shapes)+'</svg>')
    else:
        filtered=any(query.get(k) for k in ('subnet','zone','criticality','management_status','since','until','node'))
        recovery=('<a href="'+e(url({k:v for k,v in query.items() if k in {'q','selected','zoom','processes'}}))+'">Clear surface filters</a>') if filtered else '<a href="/assets">Import inventory</a> · <a href="/network">Import Zeek logs</a>'
        graph='<div class="topology-empty"><p>No endpoints observed in this view.</p><p class="muted">Import Zeek logs or widen the filters. Inventory without observed traffic is listed below; silence does not establish removal.</p><p>'+recovery+'</p></div>'
    return graph,{'selected':selected,'nodes':len(nodes),'observed':len(observed),'links':min(len(pairs),LINK_LIMIT),
                  'omitted_links':len({(r['source_ip'],r['destination_ip']) for r in data['edges']})-min(len(pairs),LINK_LIMIT),'processes':len(shown_processes),
                  'omitted_processes':max(0,len(processes)-len(shown_processes)) if query.get('processes')!='hide' else 0,
                  'width':width,'omitted_labels':labels_omitted,'matches':len(known_matches) if search else None}


def observed_time(timestamp):
    if 'T' not in timestamp:return e(timestamp)
    # Keep full source precision in the machine-readable timestamp.
    return '<time datetime="'+e(timestamp)+'" title="'+e(timestamp)+'">'+e(timestamp[:10]+' '+timestamp[11:19]+' UTC')+'</time>'


def asset_details(store,data,selected,query):
    node=next((n for n in data['nodes'] if n['ip_address']==selected),None)
    if not node:
        return '<section id="surface-details" class="topology-detail" aria-label="Selected asset details"><h3>Asset details</h3><p class="muted">'+('The selected endpoint is outside these asset filters. Clear filters to inspect it.' if selected else 'No matching endpoint selected. Find an asset or peer, or import inventory and Zeek logs to begin.')+'</p></section>'
    records=[r for r in data['edges'] if selected in (r['source_ip'],r['destination_ip'])]
    first=node.get('first_observed') or min((r['first_seen'] for r in records),default='Not available in this view')
    last=node.get('last_observed') or max((r['last_seen'] for r in records),default='Not available in this view')
    facts=[('Type',node['asset_type']),('Zone',node['zone']),('Criticality',node['criticality']),
           ('Management',MANAGEMENT.get(node['management_status'],'Unknown')),('Identity confidence',node['identity_confidence'])]
    body=f'<section id="surface-details" class="topology-detail" aria-label="Selected asset details"><h3>{e(node["identity"])}</h3><p class="mono">{e(selected)}</p><p class="muted">'+('Verified inventory identity' if node['verified'] else 'Identity unverified')+'</p>'
    body+='<dl>'+''.join('<div><dt>'+e(k)+'</dt><dd>'+e(v)+'</dd></div>' for k,v in facts)+'</dl>'
    body+='<h4>Observed evidence</h4><p>'+e(node['visibility'])+'</p><dl class="topology-times"><div><dt>First communication</dt><dd>'+observed_time(first)+'</dd></div><div><dt>Last communication</dt><dd>'+observed_time(last)+'</dd></div></dl>'
    if records:
        body+='<details><summary>Communication evidence · '+str(len(records))+' listed relationships</summary><ul>'
        for row in records[:20]:
            metadata=(row['protocol'] or 'Protocol unknown')+' · destination port '+str(row['destination_port'] if row['destination_port'] is not None else 'unknown')
            body+='<li><a href="'+e(evidence_url(row['sample_event_ref'],url(query,selected=selected)))+'">'+e(metadata)+'</a><br><small>'+e(row['source_ip']+' → '+row['destination_ip'])+'</small></li>'
        body+='</ul>'+(f'<p>Showing 20 of {len(records)}. Review the communication table below for more.</p>' if len(records)>20 else '')+'</details>'
    if node['observed']:
        body+='<p><a href="'+e(url(query,node=selected,selected=selected,page=None))+'">Show this endpoint’s communication</a></p>'
        if not records:body+='<p class="muted">Traffic is stored for this endpoint; its relationships are outside the current bounded listing or asset filters.</p>'
    body+='<h4>Vulnerability applicability</h4>'
    if node['asset_id']:
        counts=store.connection.execute('SELECT status,COUNT(*) AS n FROM findings WHERE asset_id=? GROUP BY status',(node['asset_id'],)).fetchall()
        labels={'CONFIRMED_MATCH':'Confirmed affected','POTENTIAL_MATCH':'Possibly affected','NEEDS_REVIEW':'Needs review','NO_MATCH_TO_THIS_ADVISORY':'Not affected by assessed advisory'}
        body+=('<ul>'+''.join('<li>'+e(labels.get(r['status'],r['status']))+': '+str(r['n'])+'</li>' for r in counts)+'</ul>') if counts else '<p>No stored vulnerability assessments.</p>'
        body+='<p><a href="'+e('/assets/edit?'+urlencode({'asset_id':node['asset_id']}))+'">Review inventory identity</a></p>'
        finding=store.connection.execute('SELECT finding_id,cve_id FROM findings WHERE asset_id=? ORDER BY updated_at DESC,finding_id LIMIT 1',(node['asset_id'],)).fetchone()
        if finding:body+='<p><a href="'+e('/?'+urlencode({'finding_id':finding['finding_id']}))+'#finding-'+e(finding['finding_id'])+'">Review latest assessment: '+e(finding['cve_id'])+'</a></p>'
    else:body+='<p>Unknown peer; inventory identity and installed versions are not established.</p>'
    return body+'<p class="muted">A vulnerability finding does not establish compromise. Missing assessments do not establish safety.</p></section>'


def render_topology(store,data,query):
    params=values(query);params['q']=params.get('q','')[:128].strip()
    if 'previous_q' in query and query['previous_q'][0] != params['q']:
        params.pop('selected',None)
    try:zoom=float(params.get('zoom','1'))
    except ValueError:zoom=1
    if zoom not in (.75,1,1.25,1.5):zoom=1
    params['zoom']=str(zoom)
    graph,stats=diagram(data,params)
    keep=''.join(hidden(k,v) for k,v in params.items() if k not in {'q','processes'})
    keep+=hidden('previous_q',params['q'])
    toolbar='<div class="topology-toolbar"><form method="get" action="/attack-surface#topology">'+keep
    toolbar+=field('q','Find asset or peer',params.get('q',''),maxlength=128)+select('processes','Process support',[('show','Shown'),('hide','Hidden')],params.get('processes','show'))+'<button>Apply view</button></form><div class="topology-zoom" aria-label="Graph zoom">'
    for value,label in ((max(.75,zoom-.25),'Zoom out'),(1,'Reset zoom'),(min(1.5,zoom+.25),'Zoom in')):
        toolbar+='<a class="btn" href="'+e(url(params,anchor='topology',zoom=value))+'">'+label+'</a>'
    toolbar+='</div></div>'
    status=(f'<p class="topology-caption" role="status">{stats["matches"]} known assets or peers match '+e(params['q'])+'.</p>') if stats['matches'] is not None else ''
    if params['q']:
        results=[n for n in data['nodes'] if params['q'].strip().casefold() in (n['identity']+' '+n['ip_address']).casefold()]
        status+='<ul class="topology-results">'+''.join('<li><a href="'+e(url(params,selected=n['ip_address']))+'">'+e(n['identity']+' · '+n['ip_address'])+'</a> · '+e(n['visibility'])+'</li>' for n in results[:20])+'</ul>' if results else '<p>No known assets or peers match this search. Refine the name or IP, or clear Find.</p>'
        if len(results)>20:status+='<p>Showing 20 results; refine Find to locate another endpoint.</p>'
        status+='<p><a href="'+e(url(params,q=None,selected=None))+'">Clear Find</a></p>'
    toolbar+='<p class="muted">Find searches all known inventory and imported peers within the asset filters. The graph retains observed communication as context.</p>'
    detail=asset_details(store,data,stats['selected'],params)
    caption=f'Showing {stats["nodes"]} of {stats["observed"]} observed endpoints · {stats["links"]} diagram connections'
    caption+=f' · {stats["observed"]-stats["nodes"]} endpoints omitted' if stats['observed']>stats['nodes'] else ''
    if stats['omitted_links']:caption+=f' · {stats["omitted_links"]} diagram connections omitted from the listed relationships'
    if stats['omitted_processes']:caption+=f' · {stats["omitted_processes"]} process nodes omitted'
    if stats['omitted_labels']:caption+=f' · {stats["omitted_labels"]} port/protocol labels omitted to prevent overlap; inspect connections for details'
    legend='<div class="topology-legend"><span>Observed communication →</span><span class="support-key">Confirmed process support</span></div>'
    guidance='. Scroll within the diagram to explore. Zone membership comes from inventory; no trust boundaries are inferred.' if stats['nodes'] else '. No diagram is drawn for this observation view.'
    if not stats['nodes']:legend=''
    canvas=('<div class="topology-scale" style="width:'+f'{stats["width"]*zoom:g}'+'px">'+graph+'</div>') if stats['nodes'] else graph
    return ('<h2 id="topology">Topology overview</h2>'+toolbar+status+'<div class="topology-workspace">'+detail+'<div class="topology-canvas"><div class="topology-scroll" tabindex="0" role="region" aria-label="Topology diagram; scroll to explore">'
            +canvas+'</div><p class="topology-caption">'+e(caption+guidance)+'</p>'+legend+'</div></div>')
