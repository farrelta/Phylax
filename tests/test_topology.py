"""Offline checks for the minimalist topology's data, limits and local links."""
import io
import unittest
from html.parser import HTMLParser
from phylax.core import Store
from phylax.asset_intelligence import save_process
from phylax.topology import diagram, render_topology, short, label_bounds, overlaps
from phylax.web import attack_surface_page


class Nodes(HTMLParser):
    def __init__(self,markup):
        super().__init__();self.links=[];self.feed(markup)
    def handle_starttag(self,tag,attrs):
        if tag=='a':self.links.append(dict(attrs))


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:')
        self.store.import_csv(io.StringIO('asset_id,ip_address,hostname,asset_type,zone,criticality,identity_confidence,verified\nplc,192.0.2.10,Test controller,PLC,OT,critical,high,true\nreader,192.0.2.30,Test engineering,engineering workstation,OT,high,high,true\nserver,192.0.2.40,Inventory server,server,IT,medium,medium,false\n'))
        self.event('a','192.0.2.99','192.0.2.10',502,'tcp')
        self.event('b','192.0.2.30','192.0.2.10',502,'tcp')
        save_process(self.store,'Test cooling','SYNTHETIC support','plc','Test reviewer','TEST confirmed support')
    def tearDown(self):self.store.close()
    def event(self,uid,source,destination,port,protocol):
        self.store.connection.execute('INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            (uid,'ref-'+uid,'2026-11-06T06:00:00Z',source,None,destination,port,protocol,'','conn','synthetic-test.log','{}'))
        self.store.connection.commit()

    def test_observed_nodes_and_inventory_without_traffic_are_distinct(self):
        data=self.store.attack_surface();graph,stats=diagram(data,{})
        self.assertEqual(stats['nodes'],3);self.assertEqual(stats['observed'],3)
        self.assertNotIn('Inventory server',graph)
        self.assertIn('Unknown peer',graph);self.assertIn('Unknown zone',graph)
        self.assertIn('Grouping from inventory',graph)
        self.assertIn('topology-plate',graph);self.assertNotIn('<circle',graph)
        page=attack_surface_page(self.store)
        self.assertIn('Inventory without observed traffic · 1 assets',page)
        self.assertIn('Inventory server',page)
        self.assertIn('no trust boundaries are inferred',page)

    def test_node_and_edge_links_preserve_filters_and_reference_original_evidence(self):
        graph,stats=diagram(self.store.attack_surface(),{'zone':'OT','since':'2026-11-01T00:00:00Z','q':'Test'})
        links=Nodes(graph).links
        nodes=[a for a in links if a.get('class','').startswith('topology-node')]
        self.assertEqual(len(nodes),3)
        for node in nodes:
            self.assertIn('zone=OT',node['href']);self.assertIn('since=',node['href']);self.assertIn('selected=',node['href'])
            self.assertTrue(node['aria-label'].startswith('Inspect '))
        edges=[a for a in links if a.get('class')=='topology-edge']
        self.assertEqual(len(edges),2)
        self.assertTrue(all(a['href'].startswith('/evidence?event_ref=ref-') for a in edges))
        self.assertIn('marker-end="url(#topology-arrow)"',graph)

    def test_unknown_peer_details_retain_missing_identity_and_port(self):
        self.event('c','192.0.2.99','192.0.2.10',None,'')
        html=render_topology(self.store,self.store.attack_surface(),{'selected':['192.0.2.99']})
        self.assertIn('Unknown peer; inventory identity and installed versions are not established.',html)
        self.assertIn('Identity unverified',html)
        self.assertIn('Protocol unknown · destination port unknown',html)
        self.assertIn('2026-11-06T06:00:00Z',html)
        self.assertNotIn('No vulnerabilities',html)

    def test_process_support_is_distinct_and_can_be_hidden(self):
        data=self.store.attack_surface()
        graph,stats=diagram(data,{})
        self.assertIn('topology-support',graph);self.assertIn('Operator-confirmed process',graph)
        self.assertEqual(stats['processes'],1)
        hidden,stats=diagram(data,{'processes':'hide'})
        self.assertNotIn('topology-support',hidden);self.assertNotIn('Operator-confirmed process',hidden)
        html=attack_surface_page(self.store,{'processes':['hide']})
        self.assertIn('TEST confirmed support',html)

    def test_search_highlights_matches_and_selects_matching_node(self):
        graph,stats=diagram(self.store.attack_surface(),{'q':'192.0.2.99'})
        self.assertEqual(stats['matches'],1);self.assertEqual(stats['selected'],'192.0.2.99')
        self.assertIn('is-search-match',graph)
        html=render_topology(self.store,self.store.attack_surface(),{'q':['no such endpoint']})
        self.assertIn('0 known assets or peers match',html)
        self.assertNotIn('No devices on network',html)

    def test_selected_inventory_only_asset_can_be_inspected(self):
        html=render_topology(self.store,self.store.attack_surface(),{'selected':['192.0.2.40']})
        self.assertIn('<h3>Inventory server</h3>',html)
        self.assertIn('Inventory only; no imported traffic observed',html)
        self.assertIn('No stored vulnerability assessments.',html)

    def test_empty_graph_keeps_inventory_and_useful_recovery(self):
        self.store.connection.execute('DELETE FROM network_events');self.store.connection.commit()
        html=attack_surface_page(self.store)
        self.assertIn('No endpoints observed in this view.',html)
        self.assertIn('Import Zeek logs or widen the filters.',html)
        self.assertIn('Inventory without observed traffic · 3 assets',html)
        self.assertNotIn('topology-svg"',html.split('</style>')[-1])

    def test_metadata_and_query_values_are_escaped(self):
        data=self.store.attack_surface()
        data['nodes'][0]['identity']='<script>alert(1)</script>'
        data['process_links'][0]['name']='<img onerror=evil>'
        html=render_topology(self.store,data,{'q':['"><script>evil</script>'],'selected':['192.0.2.10']})
        self.assertNotIn('<script>',html);self.assertNotIn('<img',html)
        self.assertIn('&lt;',html);self.assertNotIn('javascript:',html)
        self.assertNotIn('<script',attack_surface_page(self.store))

    def test_graph_limits_are_explicit_and_selected_endpoint_is_retained(self):
        for index in range(30):self.event(str(index),'198.51.100.'+str(index+1),'192.0.2.10',80,'tcp')
        graph,stats=diagram(self.store.attack_surface(),{'selected':'198.51.100.30'})
        self.assertEqual(stats['nodes'],24);self.assertEqual(stats['observed'],33)
        self.assertIn('Inspect Unknown peer, 198.51.100.30',graph)
        html=render_topology(self.store,self.store.attack_surface(),{})
        self.assertIn('9 endpoints omitted',html)

    def test_zoom_is_bounded_and_controls_are_local_get_requests(self):
        data=self.store.attack_surface()
        for zoom in ('nan','inf','999','bad'):
            html=render_topology(self.store,data,{'zoom':[zoom]})
            self.assertIn('style="width:700px"',html)
        html=render_topology(self.store,data,{'zoom':['1.5'],'zone':['OT']})
        self.assertIn('style="width:1050px"',html)
        self.assertIn('method="get"',html);self.assertIn('name="zone" value="OT"',html)
        self.assertNotIn('method="post"',html)

    def test_long_and_wide_names_have_bounded_labels_and_full_accessible_names(self):
        name='控制器'*30
        self.assertLess(len(short(name,24)),len(name))
        data=self.store.attack_surface();node=next(n for n in data['nodes'] if n['ip_address']=='192.0.2.10');node['identity']=name
        graph,stats=diagram(data,{})
        self.assertIn('aria-label="Inspect '+name,graph)
        self.assertIn('…',graph)

    def test_dense_relationship_and_process_limits_remain_explicit(self):
        base=self.store.attack_surface();template=base['nodes'][0];record=base['edges'][0]
        nodes=[{**template,'ip_address':'198.51.100.'+str(i+1),'observed':True} for i in range(24)]
        edges=[{**record,'source_ip':a['ip_address'],'destination_ip':b['ip_address'],'protocol':None}
               for a in nodes for b in nodes if a!=b]
        process=base['process_links'][0]
        processes=[{**process,'process_id':str(i),'ip_address':nodes[0]['ip_address']} for i in range(13)]
        data={**base,'nodes':nodes,'edges':edges,'process_links':processes}
        graph,stats=diagram(data,{})
        self.assertEqual(stats['links'],60);self.assertEqual(stats['omitted_links'],len(edges)-60)
        self.assertEqual(stats['processes'],12);self.assertEqual(stats['omitted_processes'],1)
        self.assertEqual(graph.count('class="topology-edge"'),60)
        self.assertEqual(graph.count('class="topology-process"'),12)
        html=render_topology(self.store,data,{})
        self.assertIn('diagram connections omitted',html);self.assertIn('1 process nodes omitted',html)

    def test_fanout_labels_never_overlap_nodes_or_each_other(self):
        import xml.etree.ElementTree as ET
        base=self.store.attack_surface();template=base['nodes'][0];record=base['edges'][0]
        nodes=[{**template,'ip_address':'192.0.2.'+str(i),'zone':'OT','observed':True} for i in range(1,5)]
        edges=[{**record,'source_ip':'192.0.2.1','destination_ip':'192.0.2.'+str(i),'destination_port':500+i} for i in range(2,5)]
        data={**base,'nodes':nodes,'edges':edges,'process_links':[]}
        graph,stats=diagram(data,{})
        root=ET.fromstring(graph);labels=[];plates=[]
        for group in root.findall('.//g'):
            if group.find('rect[@class="topology-plate"]') is None:continue
            x,y=map(float,group.attrib['transform'][10:-1].split())
            plates.append((x-4,y-4,x+268,y+100))
        for label in root.findall('.//text[@class="topology-link-label"]'):
            bounds=label_bounds(label.text,float(label.attrib['x']),float(label.attrib['y']))
            self.assertFalse(any(overlaps(bounds,previous) for previous in labels))
            self.assertFalse(any(overlaps(bounds,plate) for plate in plates))
            labels.append(bounds)
        self.assertLess(len(labels),3)
        self.assertEqual(len(labels)+stats['omitted_labels'],3)
        for port in (502,503,504):self.assertIn('TCP '+str(port),graph)
        html=render_topology(self.store,data,{})
        self.assertIn('labels omitted to prevent overlap',html)
        self.assertEqual(graph.count('class="topology-edge"'),3)

    def test_find_inventory_only_and_zero_results_have_honest_selection(self):
        data=self.store.attack_surface()
        html=render_topology(self.store,data,{'q':['Inventory server']})
        self.assertIn('1 known assets or peers match',html)
        self.assertIn('<h3>Inventory server</h3>',html)
        graph,stats=diagram(data,{'q':'absent'})
        self.assertEqual(stats['selected'],'')
        html=render_topology(self.store,data,{'q':['absent']})
        self.assertNotIn('<h3>Test controller</h3>',html)
        self.assertIn('Clear Find',html)

    def test_details_precede_canvas_and_empty_graph_has_no_forced_width(self):
        html=render_topology(self.store,self.store.attack_surface(),{})
        self.assertLess(html.index('id="surface-details"'),html.index('class="topology-canvas"'))
        self.store.connection.execute('DELETE FROM network_events')
        html=render_topology(self.store,self.store.attack_surface(),{})
        self.assertNotIn('class="topology-scale"',html)
        self.assertNotIn('Scroll within the diagram',html)
        self.assertNotIn('class="topology-legend"',html)
        self.assertIn('<h3>Test controller</h3>',html)

    def test_natural_graph_width_and_omissions_include_excluded_nodes(self):
        data=self.store.attack_surface()
        template=data['nodes'][0];record=data['edges'][0]
        data['nodes']=[{**template,'ip_address':'198.51.100.'+str(i+1),'zone':('IT','OT','DMZ','unknown')[i%4],'observed':True} for i in range(25)]
        data['edges']=[{**record,'source_ip':n['ip_address'],'destination_ip':data['nodes'][0]['ip_address']} for n in data['nodes'][1:]]
        graph,stats=diagram(data,{})
        self.assertEqual(stats['width'],1352)
        self.assertEqual(stats['omitted_links'],1)
        self.assertIn('style="width:1352px"',render_topology(self.store,data,{}))

    def test_each_relationship_links_evidence_and_preserves_view_state(self):
        html=attack_surface_page(self.store,{'selected':['192.0.2.99'],'q':['Unknown'],'zoom':['1.5'],'processes':['hide'],'since':['2026-11-01T00:00:00Z']})
        self.assertEqual(html.count('>Inspect evidence</a>'),2)
        self.assertNotIn('Selected evidence',html)
        self.assertIn('stored events in the selected time window, before asset and endpoint filters',html)
        self.assertIn('name="selected" value="192.0.2.99"',html)
        self.assertIn('return_to=%2Fattack-surface',html)
        self.assertIn('Operator-confirmed support',html)

    def test_filtered_empty_state_does_not_claim_global_absence(self):
        html=attack_surface_page(self.store,{'subnet':['203.0.113.0/24']})
        self.assertIn('No endpoints match these surface filters',html)
        self.assertIn('No communication relationships match these filters',html)
        self.assertNotIn('No inventory assets or imported network observations yet',html)

    def test_toolbar_preserves_selection_until_find_changes(self):
        data=self.store.attack_surface()
        query={'q':['Inventory'],'selected':['192.0.2.40'],'processes':['hide'],'previous_q':['Inventory']}
        html=render_topology(self.store,data,query)
        self.assertIn('<h3>Inventory server</h3>',html)
        self.assertIn('name="selected" value="192.0.2.40"',html)
        query['q']=['192.0.2.99']
        html=render_topology(self.store,data,query)
        self.assertNotIn('<h3>Inventory server</h3>',html)
        self.assertIn('<h3>Unknown peer</h3>',html)
        html=render_topology(self.store,data,{'q':['   ']})
        self.assertNotIn('topology-results',html)
        self.assertNotIn('known assets or peers match',html)
