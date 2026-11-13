"""Observed connections and explicitly confirmed process links; no inferred paths."""
import ipaddress
from .asset_intelligence import management_status
from .validation import utc_timestamp


EDGE_LIMIT = 1000


def _endpoints(store, sql='', params=()):
    """Endpoint existence is independent of the bounded relationship listing."""
    query = ('SELECT source_ip AS ip FROM network_events' + sql +
             ' UNION SELECT destination_ip AS ip FROM network_events' + sql)
    return {row['ip'] for row in store.connection.execute(query, tuple(params) * 2) if row['ip']}


def _observed_times(store, sql, params):
    query = (
        'SELECT ip,MIN(first_observed) AS first_observed,MAX(last_observed) AS last_observed FROM ('
        'SELECT source_ip AS ip,MIN(timestamp) AS first_observed,MAX(timestamp) AS last_observed '
        'FROM network_events' + sql + ' GROUP BY source_ip UNION ALL '
        'SELECT destination_ip AS ip,MIN(timestamp) AS first_observed,MAX(timestamp) AS last_observed '
        'FROM network_events' + sql + ' GROUP BY destination_ip) GROUP BY ip')
    return {row['ip']: row for row in store.connection.execute(query, tuple(params) * 2) if row['ip']}


def surface(store, filters=None):
    filters = filters or {}
    where = []
    params = []
    for key, op in (('since', '>='), ('until', '<=')):
        if filters.get(key):
            where.append('timestamp' + op + '?')
            params.append(utc_timestamp(filters[key]))
    sql = (' WHERE ' + ' AND '.join(where)) if where else ''
    observation_times = _observed_times(store, sql, params)
    observed = set(observation_times)
    ever_observed = _endpoints(store) if where else observed
    by_ip = {}
    for asset in store.assets():
        old = by_ip.get(asset['ip_address'])
        if not old or (asset['verified'], asset['identity_confidence'] == 'high') > (old['verified'], old['identity_confidence'] == 'high'):
            by_ip[asset['ip_address']] = asset

    nodes = []
    subnet = ipaddress.ip_network(filters['subnet']) if filters.get('subnet') else None
    for ip in sorted(set(by_ip) | ever_observed):
        a = by_ip.get(ip, {})
        management = management_status(store, ip)
        if ip in observed:
            visibility = 'Observed in imported logs in the selected period' if where else 'Observed in imported logs'
        elif ip in ever_observed:
            visibility = 'Previously observed; no imported traffic in the selected period'
        else:
            visibility = 'Inventory only; no imported traffic observed'
        node = {
            'ip_address': ip, 'asset_id': a.get('asset_id', ''),
            'identity': a.get('hostname') or ' '.join(filter(None, [a.get('vendor'), a.get('product')])) or 'Unknown peer',
            **{k: a.get(k, 'unknown') for k in ('asset_type', 'zone', 'criticality', 'vendor', 'product', 'version', 'identity_confidence')},
            'verified': bool(a.get('verified')), 'last_seen': a.get('last_seen', ''),
            'observed': ip in observed, 'ever_observed': ip in ever_observed,
            'first_observed': observation_times[ip]['first_observed'] if ip in observed else '',
            'last_observed': observation_times[ip]['last_observed'] if ip in observed else '',
            'management_status': management['status'], 'visibility': visibility,
        }
        if subnet and ipaddress.ip_address(ip) not in subnet:
            continue
        if any(filters.get(k) and filters[k] != node[k] for k in ('zone', 'criticality', 'management_status')):
            continue
        nodes.append(node)

    visible = {n['ip_address'] for n in nodes}
    edges = []
    relationship_count = 0
    # Iterate all eligible groups, retaining only the bounded display records.
    # Asset/focus filtering precedes this cap, so older matching relationships
    # remain accessible even when unrelated recent traffic fills the global view.
    grouped = store.connection.execute(
        'SELECT source_ip,destination_ip,destination_port,protocol,operation,event_type,'
        'MIN(event_id) AS sample_id,MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen,'
        'COUNT(*) AS event_count,COUNT(DISTINCT source_port) AS source_port_count,'
        'MIN(source_port) AS source_port FROM network_events' + sql +
        ' GROUP BY source_ip,destination_ip,destination_port,protocol,operation,event_type'
        ' ORDER BY last_seen DESC,source_ip,destination_ip,destination_port,protocol,operation,event_type', params)
    for row in grouped:
        if row['source_ip'] not in visible or row['destination_ip'] not in visible:
            continue
        if filters.get('node') and filters['node'] not in (row['source_ip'], row['destination_ip']):
            continue
        relationship_count += 1
        if len(edges) < EDGE_LIMIT:
            edges.append(dict(row))

    # Batch provenance reads within conservative SQLite parameter limits.
    samples = {}
    sample_ids = list({r['sample_id'] for r in edges})
    for start in range(0, len(sample_ids), 500):
        chunk = sample_ids[start:start + 500]
        placeholders = ','.join('?' for _ in chunk)
        for sample in store.connection.execute(
                'SELECT event_id,event_ref,source_file FROM network_events WHERE event_id IN (' + placeholders + ')', chunk):
            samples[sample['event_id']] = sample
    for row in edges:
        sample = samples[row['sample_id']]
        row.update(
            sample_event_ref=sample['event_ref'], source_file=sample['source_file'],
            relationship_type='observed_communication',
            source_identity=by_ip.get(row['source_ip'], {}).get('hostname') or 'Unknown peer',
            destination_identity=by_ip.get(row['destination_ip'], {}).get('hostname') or 'Unknown peer')
        if row['source_port_count'] > 1:
            row['source_port'] = 'multiple'

    processes = [dict(r) for r in store.connection.execute(
        'SELECT l.*,p.name,p.description,a.ip_address FROM process_links l '
        'JOIN processes p USING(process_id) JOIN assets a USING(asset_id)') if r['ip_address'] in visible]
    return {
        'nodes': nodes, 'edges': edges, 'process_links': processes, 'edge_limit': EDGE_LIMIT,
        'relationship_count': relationship_count,
        'relationships_truncated': relationship_count > EDGE_LIMIT,
        # Stored event count is time-scoped; asset/focus filters scope relationships.
        'event_count': store.connection.execute('SELECT COUNT(*) FROM network_events' + sql, params).fetchone()[0],
    }
