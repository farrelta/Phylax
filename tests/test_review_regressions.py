"""Regression coverage for the MVP evaluation's reproduced defects."""
from __future__ import annotations
import csv
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, mock_open
from phylax.core import Store
from phylax.feeds import normalize_nvd
from phylax.ai import AIConfig


class CorrelationRegressionTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.asset('1.5')

    def tearDown(self):
        self.store.close()

    def asset(self, version):
        return self.store.import_csv(io.StringIO('asset_id,ip_address,vendor,product,version,operating_system,zone,identity_confidence,verified\na,192.0.2.1,acme,controller,'+version+',Linux,IT,high,true\n'))

    def record(self):
        return {'cve_id':'CVE-2024-12345','summary':'TEST ONLY: regression fixture', 'synthetic':True,'source':'offline-test',
                'affected_products':[{'vendor':'acme','product':'controller','versions':['1.0'],'version_ranges':[{'start_including':'1.0','end_excluding':'2.0'}]}]}

    def status(self):
        return self.store.connection.execute('SELECT status FROM findings').fetchone()[0]

    def test_offline_ranges_and_automatic_reevaluation(self):
        self.store.ingest_fixture({'vulnerabilities':[self.record()]})
        self.assertEqual(self.status(),'CONFIRMED_MATCH')
        self.asset('2.0')
        self.assertEqual(self.status(),'NO_MATCH_TO_THIS_ADVISORY')
        self.asset('')
        self.assertEqual(self.status(),'POTENTIAL_MATCH')

    def test_cpe_constraints_are_retained_and_not_confirmed(self):
        self.asset('1.0')
        for slot,value in ((6,'sp1'),(7,'enterprise'),(10,'windows'),(11,'x86')):
            parts=['cpe','2.3','a','acme','controller','1.0']+['*']*7
            parts[slot]=value
            raw={'cve':{'id':'CVE-2024-12345','descriptions':[{'lang':'en','value':'TEST ONLY'}], 'configurations':[{'nodes':[{'cpeMatch':[{'vulnerable':True,'criteria':':'.join(parts)}]}]}]}}
            normalized=normalize_nvd(raw,'2026-10-31T00:00:00Z')
            self.store.ingest_normalized([normalized])
            self.assertEqual(self.status(),'NEEDS_REVIEW')
            self.assertIn(':'.join(parts),normalized['affected_products'][0]['cpe_names'])

    def test_import_fails_atomically_for_second_bad_record(self):
        with self.assertRaises(ValueError):
            self.store.ingest_fixture({'vulnerabilities':[self.record(),{'cve_id':'bad','summary':'bad'}]})
        self.store.set_source_health('test','healthy')
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],0)
        for malformed in ([6],None,'wrong'):
            r=self.record();r['affected_products']=malformed
            with self.assertRaises(ValueError):self.store.ingest_fixture({'vulnerabilities':[r]})

    def test_source_snapshots_do_not_label_kev_action_as_vendor_fix(self):
        r=self.record();r['source']='NVD API 2.0';r['synthetic']=False
        self.store.ingest_normalized([r],trusted_public=True)
        kev={**r,'source':'CISA KEV','kev':True,'mitigation':'CISA required action','affected_products':[]}
        self.store.ingest_normalized([kev],trusted_public=True)
        fid=self.store.connection.execute('SELECT finding_id FROM findings').fetchone()[0]
        public=self.store.public_vulnerability_for_finding(fid)
        self.assertTrue(public['public_trusted'])
        self.assertEqual(public.get('mitigation',''),'')
        self.assertEqual(public['cisa_required_action'],'CISA required action')
        self.assertEqual(len(self.store.vulnerability_provenance(r['cve_id'])),2)

    def test_local_record_cannot_replace_outbound_public_text(self):
        r=self.record();r.update(source='NVD API 2.0',synthetic=False)
        self.store.ingest_normalized([r],trusted_public=True)
        self.store.ingest_fixture({'synthetic':False,'vulnerabilities':[{**r,'source':'local','summary':'private operator note'}]})
        fid=self.store.connection.execute('SELECT finding_id FROM findings').fetchone()[0]
        self.assertNotIn('private',self.store.public_vulnerability_for_finding(fid)['summary'])

    def test_inventory_rejects_bad_mac_and_naive_timestamp(self):
        for header,value in (('mac_address','not-a-mac'),('last_seen','2026-10-31T12:00:00')):
            result=self.store.import_csv(io.StringIO(f'ip_address,{header}\n192.0.2.5,{value}\n'))
            self.assertEqual(result['imported'],0)
            self.assertEqual(len(result['errors']),1)


class PolicyRegressionTests(unittest.TestCase):
    def event(self, **kw):
        from phylax.monitoring import NetworkEvent
        return NetworkEvent(**({'timestamp':'2026-10-31T00:00:00Z','source_ip':'192.0.2.2','destination_ip':'192.0.2.1','operation':'6','event_type':'modbus'} | kw))

    def test_absent_policy_and_missing_metadata_are_diagnostic(self):
        from phylax.monitoring import evaluate
        detections,notes=evaluate(self.event(),{})
        self.assertFalse(detections)
        self.assertTrue(any('no maintenance policy' in n for n in notes))
        detections,notes=evaluate(self.event(event_type='connection',operation=''),{'protected_assets':['192.0.2.1'],'allowed_communications':[{'source_ip':'192.0.2.2','destination_ip':'192.0.2.1','protocol':'tcp','destination_port':502}]})
        self.assertFalse(detections)
        self.assertTrue(notes)

    def test_overnight_window_and_boundaries(self):
        from phylax.monitoring import _is_maintenance
        windows=[{'days':[0],'start':'23:00','end':'01:00'}]
        for timestamp,expected in [('2026-10-26T22:59:59Z',False),('2026-10-26T23:00:00Z',True),('2026-10-27T00:30:00Z',True),('2026-10-27T01:00:00Z',False),('2026-10-28T00:30:00Z',False)]:
            self.assertEqual(_is_maintenance(timestamp,windows),expected)

    def test_numeric_write_file_and_unknown_operation(self):
        from phylax.monitoring import is_modbus_write
        for op in ('21','0x15','write_file_record'):
            self.assertTrue(is_modbus_write(self.event(operation=op)))
        self.assertIsNone(is_modbus_write(self.event(operation='vendor_custom_unknown')))

    def test_policy_replay_resolves_alert_and_persists_diagnostics(self):
        from phylax.monitoring import ingest_file,reevaluate_events
        with tempfile.TemporaryDirectory() as temp:
            s=Store(Path(temp)/'db');p=Path(temp)/'modbus.log'
            p.write_text(json.dumps({'ts':'2026-10-31T00:00:00Z','uid':'R','source_ip':'192.0.2.2','destination_ip':'192.0.2.1','func':6})+'\n')
            ingest_file(s,p,policy=None)
            deny={'authorized_writers':{'192.0.2.1':[]}}
            result=ingest_file(s,p,policy=deny)
            self.assertEqual(result['alerts_created'],1)
            self.assertEqual(result['duplicates_skipped'],1)
            self.assertEqual(s.connection.execute('SELECT COUNT(*) FROM event_evaluations').fetchone()[0],1)
            reevaluate_events(s,{'authorized_writers':{'192.0.2.1':['192.0.2.2']}})
            self.assertEqual(s.connection.execute('SELECT state FROM network_alert_lifecycle').fetchone()[0],'resolved')
            self.assertEqual(s.connection.execute('SELECT COUNT(*) FROM network_policies').fetchone()[0],2)
            self.assertEqual(len(s.dashboard()['network_alerts']),0)
            self.assertEqual(json.loads(s.report('json'))['network_alerts'][0]['lifecycle_state'],'resolved')
            s.close()

    def test_malformed_log_field_is_validation_error(self):
        from phylax.monitoring import parse_zeek
        for value in ([6],{},True):
            with self.assertRaises(ValueError):
                list(parse_zeek(io.StringIO(json.dumps({'ts':'2026-10-31T00:00:00Z','operation':value})+'\n'),kind='modbus'))


class AIConfigurationRegressionTests(unittest.TestCase):
    def test_timeout_is_read_from_dotenv(self):
        text='PHYLAX_AI_PROVIDER=openrouter\nOPENROUTER_API_KEY=fake\nPHYLAX_AI_TIMEOUT_SECONDS=120\n'
        with patch.dict(os.environ,{},clear=True),patch('builtins.open',mock_open(read_data=text)):
            self.assertEqual(AIConfig.from_env().timeout_seconds,120)


class HTTPAndGuidanceRegressionTests(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace
        from phylax.web import Handler
        self.store=Store(':memory:')
        self.store.import_csv(io.StringIO('asset_id,ip_address,hostname,vendor,product,version,identity_confidence,verified\na,192.0.2.1,private-inventory-host,acme,controller,1.0,high,true\n'))
        self.store.ingest_normalized([{'cve_id':'CVE-2024-12345','summary':'Public test record','source':'NVD API 2.0','synthetic':False,'affected_products':[{'vendor':'acme','product':'controller','versions':['1.0']}],'references':['https://vendor.example/advisory']}],trusted_public=True)
        self.fid=self.store.connection.execute('SELECT finding_id FROM findings').fetchone()[0]
        self.Handler=Handler
        store=self.store
        class InlineJobs:
            def submit(self,label,work):
                self.message=work(store,lambda message:None)
                return 'testjob'
        self.jobs=InlineJobs()
        self.server=SimpleNamespace(server_address=('127.0.0.1',8765),jobs=self.jobs)

    def tearDown(self):self.store.close()

    def handler(self,path,body='',origin='http://127.0.0.1:8765',host='127.0.0.1:8765'):
        from email.message import Message
        h=object.__new__(self.Handler);h.store=self.store;h.server=self.server;h.path=path
        h.headers=Message();h.headers['Host']=host;h.headers['Origin']=origin
        h.headers['Content-Type']='application/x-www-form-urlencoded';h.headers['Content-Length']=str(len(body.encode()))
        h.rfile=io.BytesIO(body.encode());h.wfile=io.BytesIO();h.response_headers={}
        h.send_response=lambda status:setattr(h,'response_status',status)
        h.send_header=lambda key,value:h.response_headers.update({key:value});h.end_headers=lambda:None
        return h

    def test_post_requires_host_origin_and_form_token(self):
        for origin,host,body in [('https://untrusted.example','127.0.0.1:8765',''),('http://untrusted.example','untrusted.example',''),('http://127.0.0.1:8765','127.0.0.1:8765','')]:
            h=self.handler('/correlate',body,origin,host);h.do_POST();self.assertEqual(h.response_status,403)
        h=self.handler('/correlate','csrf_token='+self.Handler.csrf_token);h.do_POST();self.assertEqual(h.response_status,303)

    def test_rendered_forms_contain_token_and_header_csp(self):
        h=self.handler('/');h.do_GET()
        self.assertEqual(h.response_status,200)
        self.assertIn(b'name="csrf_token"',h.wfile.getvalue())
        self.assertIn("frame-ancestors 'none'",h.response_headers['Content-Security-Policy'])

    def test_current_http_plan_flow_stores_model_and_keeps_authority(self):
        from phylax.ai import generate_guidance
        from phylax.remediation import HostedModelProvider
        config=AIConfig('https://provider.example/v1','router/free','fake','openrouter')
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps({'model':'actual/provider-model','choices':[{'message':{'content':json.dumps({'summary':'Review sources','steps':['Check vendor guidance'],'validation':'Verify with vendor','source_urls':['https://vendor.example/advisory']})}}]}).encode()
        sent=[]
        def opener(req,timeout):sent.append(json.loads(req.data));return Response()
        before=dict(self.store.connection.execute('SELECT status,priority FROM findings').fetchone())
        with patch('phylax.remediation_service.AIConfig.from_env',return_value=config),patch('phylax.remediation.generate_guidance',side_effect=lambda r,c:generate_guidance(r,c,opener=opener)):
            h=self.handler('/remediation/create','csrf_token='+self.Handler.csrf_token+'&finding_id='+self.fid);h.do_POST()
        self.assertEqual(h.response_status,303)
        self.assertEqual(h.response_headers['Location'],'/jobs/testjob')
        self.assertNotIn('private-inventory-host',json.dumps(sent))
        self.assertNotIn('192.0.2.1',json.dumps(sent))
        saved=self.store.get_remediation_plan(self.fid)
        self.assertEqual(saved['model'],'actual/provider-model')
        self.assertEqual(saved['plan']['requested_model'],'router/free')
        self.assertEqual(before,dict(self.store.connection.execute('SELECT status,priority FROM findings').fetchone()))
        with patch('phylax.remediation_service.AIConfig.from_env',return_value=config),patch.object(HostedModelProvider,'generate',side_effect=RuntimeError('timeout')):
            h=self.handler('/remediation/create','csrf_token='+self.Handler.csrf_token+'&finding_id='+self.fid);h.do_POST()
        self.assertIn('previous hosted plan was kept',self.jobs.message)
        self.assertEqual(saved,self.store.get_remediation_plan(self.fid))
        report=json.loads(self.store.report('json'))
        self.assertEqual(report['remediation_plans'][0]['model'],'actual/provider-model')
        self.assertIsInstance(report['findings'][0]['evidence'],list)

    def test_csv_contains_context_and_neutralizes_formulas(self):
        self.store.connection.execute("UPDATE assets SET hostname='=1+1'");self.store.connection.commit()
        rows=list(csv.DictReader(io.StringIO(self.store.report('csv'))))
        finding=next(r for r in rows if r['record_type']=='vulnerability_finding')
        self.assertTrue(finding['generated_at'])
        self.assertEqual(finding['identity_confidence'],'high')
        self.assertTrue(finding['priority_factors'])
        self.assertTrue(finding['known_limitations'])
        self.assertTrue(finding['hostname'].startswith("'="))
        self.assertIn('# Phylax',self.store.report('markdown'))


class OfflinePCAPRegressionTests(unittest.TestCase):
    def test_generated_capture_is_analyzed_only_by_fixed_offline_command(self):
        from types import SimpleNamespace
        from phylax.pcap import analyze_pcap
        from scripts.generate_passive_demo import generate
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);generate(root/'captures');s=Store(root/'db')
            seen=[]
            def runner(command,**kwargs):
                seen.append(command)
                self.assertNotIn('-i',command)
                self.assertEqual(kwargs['timeout'],60)
                self.assertNotIn('GEMINI_API_KEY',kwargs['env'])
                output=Path(kwargs['cwd'])
                (output/'modbus.log').write_text(json.dumps({'ts':'2026-10-29T04:00:00Z','uid':'pcap-test','id.orig_h':'192.0.2.99','id.resp_h':'192.0.2.10','func':6})+'\n')
                return SimpleNamespace(returncode=0)
            with patch('phylax.pcap.shutil.which',return_value='/usr/bin/docker'):
                result=analyze_pcap(s,root/'captures/synthetic-unauthorized-write.pcap',policy={'authorized_writers':{'192.0.2.10':[]}},docker_image='zeek/zeek:test-pinned',runner=runner)
            self.assertIn('--network=none',seen[0]);self.assertIn('--pull=never',seen[0]);self.assertIn('--read-only',seen[0])
            self.assertEqual(result['logs'][0]['alerts_created'],1)
            self.assertIn(result['capture_sha256'],s.connection.execute('SELECT source_file FROM network_events').fetchone()[0])
            self.assertTrue(s.connection.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0])
            with patch('phylax.pcap.shutil.which',return_value='/usr/bin/docker'):
                replay=analyze_pcap(s,root/'captures/synthetic-unauthorized-write.pcap',docker_image='zeek/zeek:test-pinned',runner=runner)
            self.assertTrue(replay['already_analyzed']);self.assertEqual(len(seen),1)
            s.close()

    def test_missing_tool_and_malformed_capture_have_diagnostics(self):
        from phylax.pcap import analyze_pcap
        from scripts.generate_passive_demo import generate
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);generate(root/'captures');s=Store(root/'db')
            with patch('phylax.pcap.shutil.which',return_value=None):
                with self.assertRaisesRegex(RuntimeError,'not installed'):
                    analyze_pcap(s,root/'captures/synthetic-benign-read.pcap')
            bad=root/'bad.pcap';bad.write_bytes(b'garbage'*10)
            with self.assertRaises(ValueError):analyze_pcap(s,bad)
            s.close()


class PersistenceAndExtensionRegressionTests(unittest.TestCase):
    def test_existing_database_migration_backs_up_and_reviews_legacy_cpe(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'old.db';s=Store(path)
            s.import_csv(io.StringIO('asset_id,ip_address,vendor,product,version,identity_confidence,verified\na,192.0.2.1,acme,p,1.0,high,true\n'))
            s.ingest_normalized([{'cve_id':'CVE-2024-12345','summary':'Legacy test','source':'NVD API 2.0','affected_products':[{'vendor':'acme','product':'p','versions':['1.0']}]}])
            s.connection.execute("DELETE FROM schema_meta WHERE key='product_index_v2'");s.connection.commit();s.close()
            reopened=Store(path)
            self.assertTrue(Path(str(path)+'.pre-hardening.sqlite').exists())
            self.assertEqual(reopened.connection.execute('SELECT status FROM findings').fetchone()[0],'NEEDS_REVIEW')
            reopened.close()

    def test_inventory_reconciles_an_unknown_passive_peer_only(self):
        s=Store(':memory:');s.observe_ip('192.0.2.1','2026-10-31T00:00:00.000000Z');s.connection.commit()
        s.import_csv(io.StringIO('asset_id,ip_address,vendor,product,version\nmanual,192.0.2.1,acme,controller,1.0\n'))
        self.assertEqual(len(s.assets()),1);self.assertEqual(s.assets()[0]['asset_id'],'manual')
        self.assertEqual(s.assets()[0]['last_seen'],'2026-10-31T00:00:00.000000Z');s.close()

    def test_new_adapter_needs_no_correlation_change(self):
        from phylax.adapters import IntelligenceBatch
        from phylax.feeds import sync_store,KEV_URL,ICS_RSS_URL
        class Adapter:
            name='review-adapter';trusted_public=False
            def collect(self,fetcher,retrieved_at):
                return IntelligenceBatch(vulnerabilities=[{'cve_id':'CVE-2024-55555','summary':'TEST ONLY extension','source':self.name,'synthetic':True,'affected_products':[]}])
        def fetcher(url):
            if url==KEV_URL:return b'{"vulnerabilities":[]}'
            if url==ICS_RSS_URL:return b'<rss><channel/></rss>'
            return b'{"vulnerabilities":[],"totalResults":0}'
        s=Store(':memory:');result=sync_store(s,fetcher=fetcher,additional_adapters=(Adapter(),))
        self.assertTrue(result['review-adapter']['ok'])
        self.assertEqual(s.connection.execute('SELECT COUNT(*) FROM synchronization_runs').fetchone()[0],4)
        s.close()

    def test_malformed_source_envelopes_are_not_healthy_empty_feeds(self):
        from phylax.feeds import sync_store
        s=Store(':memory:');results=sync_store(s,fetcher=lambda url:b'{"error":"bad feed"}')
        self.assertTrue(all(not x['ok'] for x in results.values()));s.close()

    def test_changed_evidence_archives_plan_and_requires_review(self):
        from phylax.remediation import compose_plan
        s=Store(':memory:');s.import_csv(io.StringIO('asset_id,ip_address,vendor,product,version,identity_confidence,verified\na,192.0.2.1,acme,p,1.0,high,true\n'))
        r={'cve_id':'CVE-2024-12345','summary':'TEST ONLY','synthetic':True,'affected_products':[{'vendor':'acme','product':'p','versions':['1.0']}]}
        s.ingest_normalized([r]);f=s.dashboard()['findings'][0];f['evidence']=json.loads(f['evidence']);f['missing_evidence']=[];f['references']=[]
        s.create_remediation_plan(f['finding_id'],'template-fallback','',compose_plan(f,r),[])
        s.ingest_normalized([{**r,'summary':'Changed TEST ONLY source guidance'}])
        self.assertEqual(s.get_remediation_plan(f['finding_id'])['status'],'Needs More Evidence')
        self.assertEqual(s.connection.execute('SELECT COUNT(*) FROM archived_plans').fetchone()[0],1)
        s.close()


class JobAndPaginationRegressionTests(unittest.TestCase):
    def test_job_owns_connection_and_reader_remains_available(self):
        from phylax.jobs import Jobs
        import threading
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'db';reader=Store(path);jobs=Jobs(str(path))
            started=threading.Event();release=threading.Event()
            def work(store,update):
                update('Working');started.set()
                if not release.wait(5):raise RuntimeError('test synchronization timed out')
                store.audit('job_test','test',{});store.connection.commit();return 'Done'
            key=jobs.submit('test-job',work)
            try:
                self.assertTrue(started.wait(5))
                self.assertEqual(jobs.get(key)['status'],'running')
                self.assertEqual(reader.dashboard()['assets'],0)
                release.set();jobs.executor.submit(lambda:None).result(timeout=5)
                self.assertEqual(jobs.get(key)['status'],'complete')
                self.assertEqual(reader.connection.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0],1)
            finally:release.set();jobs.close();reader.close()

    def test_dashboard_paginates_rows_but_keeps_actual_counts(self):
        s=Store(':memory:')
        for i in range(3):s.import_csv(io.StringIO(f'ip_address\n192.0.2.{i+1}\n'))
        data=s.dashboard(limit=1,offset=1)
        self.assertEqual(data['assets'],3)
        self.assertEqual(data['assets_needing_identity_review'],3)
        self.assertEqual(len(data['identity_review_assets']),1);s.close()


class ImportAndModelBoundaryTests(unittest.TestCase):
    def test_duplicate_products_and_wildcard_versions_remain_conservative(self):
        s=Store(':memory:');s.import_csv(io.StringIO('ip_address,vendor,product,version,identity_confidence,verified\n192.0.2.1,acme,p,2.0,high,true\n'))
        r={'cve_id':'CVE-2024-12345','summary':'TEST ONLY','synthetic':True,'affected_products':[{'vendor':'acme','product':'p','versions':['1.0']},{'vendor':'acme','product':'p','versions':['2.0']}]}
        s.ingest_fixture({'vulnerabilities':[r]});self.assertEqual(s.dashboard()['findings'][0]['status'],'CONFIRMED_MATCH')
        r['affected_products']=[{'vendor':'acme','product':'p','versions':['2.*']}]
        s.ingest_fixture({'vulnerabilities':[r]});self.assertEqual(s.dashboard()['findings'][0]['status'],'NEEDS_REVIEW');s.close()

    def test_csv_parse_errors_are_reported(self):
        s=Store(':memory:')
        for text in ('ip_address,ip_address\n192.0.2.1,192.0.2.2\n','ip_address\n192.0.2.1,extra\n','ip_address,hostname\n192.0.2.1,"unterminated'):
            self.assertTrue(s.import_csv(io.StringIO(text))['errors'])
        s.close()

    def test_command_output_is_rejected_and_secrets_are_redacted(self):
        from phylax.ai import generate_guidance
        import urllib.error
        key='test-long-private-token'
        config=AIConfig('https://provider.example','m',key)
        record={'cve_id':'CVE-2024-12345','summary':'Public','references':['https://vendor.example/a'],'synthetic':False}
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps({'choices':[{'message':{'content':json.dumps({'summary':'Review','steps':['sudo reboot'],'validation':'Review','source_urls':['https://vendor.example/a']})}}]}).encode()
        with self.assertRaisesRegex(ValueError,'command syntax'):
            generate_guidance(record,config,opener=lambda *a,**k:Response())
        def error(*args,**kwargs):raise urllib.error.HTTPError('https://provider.example',400,'Bad Request',{},io.BytesIO(json.dumps({'error':{'message':'Invalid '+key}}).encode()))
        with self.assertRaises(RuntimeError) as caught:generate_guidance(record,config,opener=error)
        self.assertNotIn(key,str(caught.exception));self.assertIn('[redacted]',str(caught.exception))
