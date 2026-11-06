"""Offline release acceptance. All active probes are mocked or isolated lab-only."""
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from phylax.core import Store
from phylax.asset_intelligence import add_subnet,endpoint_decision,revoke_decision,management_status,save_context,save_process
from phylax.monitoring import ingest_file
from phylax.observations import review_component,map_software
from phylax.discovery import save_target,enqueue,worker_once,schedule,cancel,parse_result,Cancelled
from phylax.watcher import LogWatcher


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.s=Store(self.root/'test.db')
        self.s.import_csv(io.StringIO('asset_id,ip_address,asset_type,zone,criticality\nserver,192.0.2.10,server,IT,critical\nplc,192.0.2.20,PLC,OT,critical\n'))

    def tearDown(self):self.s.close();self.temp.cleanup()

    def log(self,kind,rows):
        path=self.root/(kind+'.log');path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
        return ingest_file(self.s,path,kind=kind)

    def conn(self,ip='192.0.2.99'):
        return {'ts':1793246400,'uid':'lab','id.orig_h':ip,'id.resp_h':'192.0.2.20','id.orig_p':40000,'id.resp_p':502,'proto':'tcp'}

    def vuln(self):
        self.s.ingest_fixture({'vulnerabilities':[{'cve_id':'CVE-2024-12345','summary':'Synthetic software acceptance','synthetic':True,'affected_products':[{'vendor':'apache','product':'http_server','versions':['2.4.41']}]}]})

    def xml(self,ip='192.0.2.10'):
        return f'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><address addr="{ip}" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port></ports></host></nmaprun>'.encode()

    def runner(self,args,**kwargs):
        self.commands.append(args)
        self.assertLessEqual(kwargs['timeout'],30)
        return b'Nmap version test' if '--version' in args else self.xml()

    def test_migration_backup_and_idempotence(self):
        self.assertTrue(Path(str(self.s.path)+'.pre-asset-intelligence.sqlite').exists())
        self.s.close();self.s=Store(self.root/'test.db')
        self.assertEqual(len(self.s.assets()),2)
        self.assertEqual(self.s.connection.execute('PRAGMA integrity_check').fetchone()[0],'ok')
        self.assertFalse(self.s.connection.execute('PRAGMA foreign_key_check').fetchall())

    def test_approval_is_separate_and_alert_resolves_without_scanning_permission(self):
        sid=add_subnet(self.s,'Synthetic site','192.0.2.0/24')
        self.log('conn',[self.conn()]);self.log('conn',[self.conn()])
        self.assertEqual(management_status(self.s,'192.0.2.99')['status'],'unmanaged')
        self.assertEqual(self.s.connection.execute("SELECT COUNT(*) FROM endpoint_alerts WHERE ip='192.0.2.99'").fetchone()[0],1)
        did=endpoint_decision(self.s,sid,ip='192.0.2.99',actor='operator',note='lab approval')
        self.assertEqual(management_status(self.s,'192.0.2.99')['status'],'approved')
        self.assertEqual(self.s.connection.execute("SELECT state FROM endpoint_alerts WHERE ip='192.0.2.99'").fetchone()[0],'resolved')
        self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM scan_targets').fetchone()[0],0)
        revoke_decision(self.s,did,'operator','expired')
        self.assertEqual(management_status(self.s,'192.0.2.99')['status'],'unmanaged')

    def test_no_subnet_no_unmanaged_alerts_and_overlap_rejected(self):
        self.log('conn',[self.conn()]);self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM endpoint_alerts').fetchone()[0],0)
        add_subnet(self.s,'lab','192.0.2.0/24')
        with self.assertRaises(ValueError):add_subnet(self.s,'overlap','192.0.2.0/25')

    def test_multicast_and_subnet_broadcast_do_not_become_managed_endpoints(self):
        add_subnet(self.s,'lab','192.0.2.0/24')
        self.log('conn',[dict(self.conn(),**{'id.resp_h':'192.0.2.255'}),dict(self.conn(),uid='multicast',**{'id.resp_h':'224.0.0.1'})])
        self.assertFalse(self.s.connection.execute("SELECT 1 FROM assets WHERE ip_address IN ('192.0.2.255','224.0.0.1')").fetchone())
        self.assertTrue(self.s.attack_surface()['edges'])

    def test_dhcp_requested_address_missing_mac_conflict_and_block(self):
        sid=add_subnet(self.s,'lab','192.0.2.0/24')
        endpoint_decision(self.s,sid,ip='192.0.2.99',mac='02:00:00:00:00:01',actor='operator',note='MAC-bound')
        self.log('conn',[self.conn()])
        self.assertEqual(management_status(self.s,'192.0.2.99')['status'],'needs_identity_review')
        result=self.log('dhcp',[{'ts':1793246401,'requested_addr':'192.0.2.98','mac':'02:00:00:00:00:01'}])
        self.assertEqual(result['events_inserted'],0)
        self.log('dhcp',[{'ts':1793246401,'assigned_addr':'192.0.2.99','mac':'02:00:00:00:00:01'}])
        self.assertEqual(management_status(self.s,'192.0.2.99')['status'],'approved')
        self.log('dhcp',[{'ts':1793246402,'client_addr':'192.0.2.99','mac':'02:00:00:00:00:02'}])
        self.assertTrue(self.s.connection.execute("SELECT 1 FROM asset_changes WHERE kind='ip_mac_changed'").fetchone())
        endpoint_decision(self.s,sid,mac='02:00:00:00:00:02',decision='blocked',actor='operator',note='explicit test block')
        self.assertEqual(management_status(self.s,'192.0.2.99')['status'],'unauthorized')

    def test_dhcp_out_of_order_does_not_replace_latest(self):
        add_subnet(self.s,'lab','192.0.2.0/24')
        self.log('dhcp',[{'ts':20,'assigned_addr':'192.0.2.99','mac':'02:00:00:00:00:02'},{'ts':10,'assigned_addr':'192.0.2.99','mac':'02:00:00:00:00:01'}])
        self.assertEqual(management_status(self.s,'192.0.2.99')['mac'],'02:00:00:00:00:02')

    def test_software_observed_verified_changed_and_retired(self):
        self.vuln()
        row={'ts':1793246400,'host':'192.0.2.10','name':'Apache','version.major':2,'version.minor':4,'version.minor2':41}
        self.log('software',[row])
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'POTENTIAL_MATCH')
        cid=self.s.connection.execute('SELECT component_id FROM software_components').fetchone()[0]
        review_component(self.s,cid,verified=True,actor='operator',note='checked lab installation')
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'CONFIRMED_MATCH')
        self.log('software',[dict(row,ts=1793246401,**{'version.minor2':42})])
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'NEEDS_REVIEW')
        review_component(self.s,cid,active=False,actor='operator',note='replaced')
        latest=self.s.connection.execute("SELECT component_id FROM software_components WHERE active=1").fetchone()[0]
        review_component(self.s,latest,verified=True,actor='operator',note='verified patched lab')
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'NO_MATCH_TO_THIS_ADVISORY')

    def test_unknown_software_mapping_and_malformed_import_atomic(self):
        self.vuln();row={'ts':10,'host':'192.0.2.10','name':'custom-http','version.major':2,'version.minor':4,'version.minor2':41}
        self.log('software',[row]);self.assertFalse(self.s.dashboard()['findings'])
        map_software(self.s,'custom-http','apache','http_server','operator','exact lab evidence')
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'POTENTIAL_MATCH')
        before=self.s.connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0]
        with self.assertRaises(ValueError):self.log('software',[dict(row,ts=11),dict(row,host=['bad'])])
        self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0],before)

    def test_watcher_stability_dedup_restart_and_changed_failure(self):
        directory=self.root/'finalized';directory.mkdir();path=directory/'conn.log';path.write_text(json.dumps(self.conn())+'\n')
        watcher=LogWatcher(self.s,directory)
        self.assertEqual(watcher.poll()['imported'],0);self.assertEqual(watcher.poll()['imported'],1)
        self.assertEqual(watcher.poll()['imported'],0)
        watcher=LogWatcher(self.s,directory);watcher.poll();self.assertEqual(watcher.poll()['imported'],0)
        path.write_text('{bad');watcher.poll();self.assertEqual(watcher.poll()['failed'],1)
        self.assertEqual(watcher.poll()['failed'],0)
        path.write_text(json.dumps(dict(self.conn(),uid='next'))+'\n');watcher.poll();self.assertEqual(watcher.poll()['imported'],1)
        link=directory/'software.log';link.symlink_to(path)
        self.assertEqual(watcher.poll()['imported'],0)

    def test_watcher_changed_file_rolls_back_and_unchanged_files_are_not_rehashed(self):
        directory=self.root/'finalized';directory.mkdir();path=directory/'conn.log';path.write_text(json.dumps(self.conn())+'\n')
        watcher=LogWatcher(self.s,directory);watcher.poll()
        def changing(*args,**kwargs):
            result=ingest_file(*args,**kwargs)
            path.write_text(path.read_text()+'\n')
            return result
        with patch('phylax.watcher.ingest_file',side_effect=changing):self.assertEqual(watcher.poll()['failed'],1)
        self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0],0)
        watcher.poll();self.assertEqual(watcher.poll()['imported'],1)
        with patch('phylax.watcher.os.open',side_effect=AssertionError('Unchanged file rehashed')):watcher.poll()

    def test_release_demo_has_four_states_and_explicit_disabled_scan_permission(self):
        from scripts.prepare_release_demo import prepare
        result=prepare(self.root/'fixture')
        self.assertEqual(set(result['applicability']),{'CONFIRMED_MATCH','POTENTIAL_MATCH','NO_MATCH_TO_THIS_ADVISORY','NEEDS_REVIEW'})
        self.assertFalse(result['scan_permission'])
        with self.assertRaises(FileExistsError):prepare(self.root/'fixture')

    def test_active_target_boundaries(self):
        with self.assertRaises(ValueError):save_target(self.s,'plc',[502],permission=True,actor='operator',note='rejected')
        for ports,identify in ((list(range(1,34)),{}),([80],{'80':'ssh'}),([True],{}),([9100],{'9100':'http'})):
            with self.assertRaises(ValueError):save_target(self.s,'server',ports,identify=identify,permission=True,actor='operator',note='test')
        tid=save_target(self.s,'server',[80],actor='operator',note='configuration only')
        with self.assertRaises(ValueError):enqueue(self.s,tid)

    def test_fixed_scan_args_evidence_and_unverified_software(self):
        self.commands=[];self.vuln()
        tid=save_target(self.s,'server',[80],identify={'80':'http'},permission=True,actor='operator',note='isolated lab')
        rid=enqueue(self.s,tid);self.assertEqual(enqueue(self.s,tid),rid)
        with patch('phylax.discovery.shutil.which',return_value='/usr/bin/nmap'):
            result=worker_once(self.s,runner=self.runner,identifier_fn=lambda *args:{'server':'Apache/2.4.41'})
        self.assertEqual(result['status'],'success')
        self.assertEqual(result['result']['reachability'],'responded')
        command=self.commands[-1]
        self.assertIn('--unprivileged',command);self.assertIn('-sT',command);self.assertIn('-Pn',command);self.assertIn('-n',command)
        self.assertNotIn('-sV',command);self.assertNotIn('--script',command)
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'POTENTIAL_MATCH')
        self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM network_events').fetchone()[0],0)
        self.assertEqual(self.s.connection.execute('SELECT kind FROM observations').fetchone()[0],'active_probe')

    def test_revocation_cancels_queue_and_schedule_bounds(self):
        tid=save_target(self.s,'server',[80],permission=True,actor='operator',note='lab')
        rid=enqueue(self.s,tid)
        with self.assertRaises(ValueError):schedule(self.s,tid,14)
        schedule(self.s,tid,15)
        save_target(self.s,'server',[80],permission=False,actor='operator',note='revoked')
        self.assertEqual(self.s.connection.execute('SELECT status FROM scan_runs WHERE run_id=?',(rid,)).fetchone()[0],'cancelled')

    def test_worker_lease_expiry_cancel_timeout_and_bad_xml(self):
        tid=save_target(self.s,'server',[80],permission=True,actor='operator',note='lab')
        rid=enqueue(self.s,tid);cancel(self.s,rid)
        self.assertEqual(self.s.connection.execute('SELECT status FROM scan_runs WHERE run_id=?',(rid,)).fetchone()[0],'cancelled')
        self.s.connection.execute("INSERT INTO worker_lease VALUES('scanner','other',?)",(time.time()+300,));self.s.connection.commit()
        self.assertTrue(worker_once(self.s)['busy'])
        self.s.connection.execute('DELETE FROM worker_lease');self.s.connection.commit();enqueue(self.s,tid)
        with patch('phylax.discovery.shutil.which',return_value='/usr/bin/nmap'):
            result=worker_once(self.s,runner=lambda *a,**kw:(_ for _ in ()).throw(TimeoutError('test')))
        self.assertEqual(result['status'],'failed')
        for body in (b'<bad',self.xml('192.0.2.99'),b'<!DOCTYPE x [<!ENTITY a "b">]><x/>'):
            with self.assertRaises(ValueError):parse_result(body,'192.0.2.10',[80])
        collapsed=b'<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><extraports state="closed" count="1"><extrareasons reason="conn-refused" count="1"/></extraports></ports></host></nmaprun>'
        result=parse_result(collapsed,'192.0.2.10',[80])
        self.assertEqual(result['ports'][0]['state'],'closed');self.assertEqual(result['reachability'],'responded')

    def test_process_context_does_not_change_criticality(self):
        save_context(self.s,'server',owner='Lab operator',tags=['logistics'],criticality_rationale='fictional support service')
        save_process(self.s,'Cooling','Simulated utility support','plc','operator','confirmed lab dependency')
        self.assertEqual(self.s.connection.execute("SELECT criticality FROM assets WHERE asset_id='plc'").fetchone()[0],'critical')

    def test_schedule_skips_missed_intervals_and_recovers_expired_run(self):
        tid=save_target(self.s,'server',[80],permission=True,actor='operator',note='lab')
        schedule(self.s,tid,15);now=time.time()
        self.s.connection.execute('UPDATE scan_schedules SET next_due=?',(now-9000,));self.s.connection.commit()
        self.commands=[]
        with patch('phylax.discovery.shutil.which',return_value='/usr/bin/nmap'):
            result=worker_once(self.s,runner=self.runner,now=now)
        self.assertEqual(result['status'],'success')
        self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM scan_runs').fetchone()[0],1)
        self.assertEqual(self.s.connection.execute('SELECT next_due FROM scan_schedules').fetchone()[0],now+900)
        rid=enqueue(self.s,tid)
        self.s.connection.execute("UPDATE scan_runs SET status='running' WHERE run_id=?",(rid,));self.s.connection.commit()
        self.assertTrue(worker_once(self.s)['idle'])
        self.assertEqual(self.s.connection.execute('SELECT status FROM scan_runs WHERE run_id=?',(rid,)).fetchone()[0],'interrupted')

    def test_permission_revoked_during_run_and_stale_inventory_rejected(self):
        tid=save_target(self.s,'server',[80],permission=True,actor='operator',note='lab');rid=enqueue(self.s,tid)
        def runner(args,**kw):
            self.s.connection.execute('UPDATE scan_targets SET permission=0,revision=revision+1');self.s.connection.commit()
            if kw['cancelled']():raise Cancelled('revoked')
            return self.xml()
        with patch('phylax.discovery.shutil.which',return_value='/usr/bin/nmap'):
            result=worker_once(self.s,runner=runner)
        self.assertEqual(result['status'],'cancelled')
        self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0],0)
        save_target(self.s,'server',[80],permission=True,actor='operator',note='new consent')
        self.s.connection.execute("UPDATE assets SET asset_type='HMI' WHERE asset_id='server'");self.s.connection.commit()
        with self.assertRaises(ValueError):enqueue(self.s,tid)
        save_target(self.s,'server',[80],permission=False,actor='operator',note='revoke after recategorization')

    def test_csaf_exact_fixed_status_cache_and_conflicts(self):
        from phylax.csaf import configure,sync_csaf,normalize,official_url
        url='https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/2024/lab.json'
        def product(pid,version):return {'product_id':pid,'name':'synthetic product','product_identification_helper':{'cpe':f'cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*'}}
        doc={'document':{'csaf_version':'2.0','title':'TEST ONLY','tracking':{'id':'synthetic-test'}},
             'product_tree':{'full_product_names':[product('affected','2.4.41'),product('fixed','2.4.42')]},
             'vulnerabilities':[{'cve':'CVE-2024-12345','notes':[{'text':'Synthetic advisory'}],'product_status':{'known_affected':['affected'],'fixed':['fixed']}}]}
        configure(self.s,url)
        result=sync_csaf(self.s,fetcher=lambda u,tag:(200,json.dumps(doc).encode(),'test-etag'))
        self.assertTrue(result['CISA CSAF']['ok'])
        result=sync_csaf(self.s,fetcher=lambda u,tag:(304,b'',tag));self.assertTrue(result['CISA CSAF']['ok'])
        products=json.loads(self.s.connection.execute('SELECT affected_products FROM vulnerabilities').fetchone()[0])
        self.assertEqual(products[0]['excluded_versions'],['2.4.42'])
        self.log('software',[{'ts':10,'host':'192.0.2.10','name':'Apache','version.major':2,'version.minor':4,'version.minor2':42}])
        cid=self.s.connection.execute('SELECT component_id FROM software_components').fetchone()[0]
        review_component(self.s,cid,verified=True,actor='operator',note='checked')
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'NO_MATCH_TO_THIS_ADVISORY')
        self.s.ingest_normalized([{'cve_id':'CVE-2024-12345','summary':'Conflicting synthetic source','source':'offline-conflict','synthetic':True,'affected_products':[{'vendor':'apache','product':'http_server','versions':['2.4.42']}]}])
        self.assertEqual(self.s.dashboard()['findings'][0]['status'],'NEEDS_REVIEW')
        for invalid in ('http://www.cisa.gov/sites/default/files/csaf/x.json','https://example.com/x.json','https://raw.githubusercontent.com/other/repo/a.json','https://www.cisa.gov/sites/default/files/csaf/../x.json'):
            with self.assertRaises(ValueError):official_url(invalid)
        self.assertFalse(sync_csaf(self.s,fetcher=lambda *args:(200,b'{bad',''))['CISA CSAF']['ok'])
        self.assertEqual(self.s.connection.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],1)

    def test_csaf_unsupported_ranges_and_advisory_only(self):
        from phylax.csaf import normalize
        doc={'document':{'csaf_version':'2.0','title':'TEST ONLY','tracking':{'id':'test'}},'product_tree':{},'vulnerabilities':[]}
        records,advisories=normalize(doc,'https://www.cisa.gov/sites/default/files/csaf/test.json','2026-11-04T00:00:00Z')
        self.assertFalse(records);self.assertEqual(len(advisories),1)
        doc['product_tree']={'branches':[{'category':'product_version_range','name':'all before 2','product':{'product_id':'range','name':'Test','product_identification_helper':{'cpe':'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'}}}]}
        doc['vulnerabilities']=[{'cve':'CVE-2024-12345','product_status':{'known_affected':['range']}}]
        records,_=normalize(doc,'https://www.cisa.gov/sites/default/files/csaf/test.json','2026-11-04T00:00:00Z')
        self.assertTrue(records[0]['affected_products'][0]['conditions_unresolved'])

    def test_frozen_real_csaf_range_is_reviewed_without_inventing_bounds(self):
        from phylax.csaf import normalize
        fixture=Path(__file__).parent/'fixtures/public_cisa_icsa_24_004_01.json'
        records,advisories=normalize(json.loads(fixture.read_text()),'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2024/icsa-24-004-01.json','2026-11-04T00:00:00Z')
        self.assertEqual(len(records),2)
        for record in records:
            self.assertTrue(record['affected_products'][0]['conditions_unresolved'])
            self.assertFalse(record['affected_products'][0]['version_ranges'])
        self.s.ingest_normalized(records)
        self.s.import_csv(io.StringIO('asset_id,ip_address,vendor,product,version,identity_confidence,verified\nreal-source-test,192.0.2.55,Rockwell Automation,Factory Talk Activation Manager,3.0,high,true\n'))
        self.assertTrue(all(r['status']=='NEEDS_REVIEW' for r in self.s.dashboard()['findings']))

    def test_network_priority_thresholds_ack_and_reports(self):
        from phylax.prioritization import network_priority
        from phylax.triage import triage,acknowledge
        for severity,criticality,protected,expected in [('low','unknown',False,'low'),('medium','medium',False,'medium'),('high','high',False,'high'),('high','critical',True,'critical')]:
            self.assertEqual(network_priority(severity,criticality,protected)['priority'],expected)
        add_subnet(self.s,'lab','192.0.2.0/24');self.log('conn',[self.conn()])
        rows,count=triage(self.s);self.assertGreater(count,0)
        row=rows[0];acknowledge(self.s,row['category'],row['alert_id'])
        self.assertTrue(next(r for r in triage(self.s)[0] if r['alert_id']==row['alert_id'])['acknowledged'])
        for format in ('json','csv','markdown'):
            report=self.s.report(format);self.assertIn('asset',report.lower())
        report=json.loads(self.s.report('json'));extension=report['asset_intelligence']
        self.assertTrue(extension['management'])
        self.assertTrue({'scan_targets','scan_schedules','ingestion_files','monitored_subnets'} <= extension.keys())
        self.assertTrue({r['ip_address'] for r in self.s.assets()} <= {r['ip'] for r in extension['management']})

    def test_surface_aggregates_ephemeral_ports_filters_and_process_links(self):
        self.log('conn',[self.conn(),dict(self.conn(),uid='other',**{'id.orig_p':40001})])
        save_process(self.s,'Cooling','Synthetic support','plc','operator','confirmed')
        view=self.s.attack_surface();self.assertEqual(len(view['edges']),1)
        self.assertEqual(view['edges'][0]['event_count'],2);self.assertEqual(view['edges'][0]['source_port'],'multiple')
        self.assertEqual(view['process_links'][0]['name'],'Cooling')
        self.assertFalse(self.s.attack_surface({'since':'2027-01-01T00:00:00Z'})['edges'])
        self.assertEqual(self.s.attack_surface({'zone':'OT'})['nodes'][0]['ip_address'],'192.0.2.20')

    def test_new_pages_and_posts_reuse_http_protection(self):
        from test_review_regressions import HTTPAndGuidanceRegressionTests
        from phylax.release_web import PAGES
        helper=HTTPAndGuidanceRegressionTests();helper.setUp()
        try:
            for route in PAGES:
                h=helper.handler(route);h.do_GET();self.assertEqual(h.response_status,200,route)
            h=helper.handler('/approvals/subnet','name=lab&cidr=192.0.2.0%2F24');h.do_POST();self.assertEqual(h.response_status,403)
            h=helper.handler('/approvals/subnet','csrf_token='+helper.Handler.csrf_token+'&name=lab&cidr=192.0.2.0%2F24');h.do_POST();self.assertEqual(h.response_status,303)
        finally:helper.tearDown()


if __name__=='__main__':unittest.main()
