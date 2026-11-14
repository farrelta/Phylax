"""Language changes cover every route without changing the underlying workflows."""
import io
import json
import re
import tempfile
import unittest
import html
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from phylax.core import Store
from phylax.i18n import (catalog, local_destination, request_language,
                         translate_html, translate_text)
from phylax.remediation import compose_plan
from phylax.web import Handler
from scripts.prepare_release_demo import prepare


class Markup(HTMLParser):
    def __init__(self, markup):
        super().__init__(); self.wire=[]; self.text=[]; self.feed(markup)

    def handle_starttag(self, tag, attrs):
        # These attributes drive behavior; labels and tooltips are presentation.
        values={k:v for k,v in attrs if k not in {'lang','title','aria-label','placeholder'}}
        if tag=='option' and values.get('value') in {'en','id'}:
            values.pop('selected',None)
        self.wire.append((tag,values))

    def handle_data(self, text):
        self.text.append(text)


class LanguageTests(unittest.TestCase):
    def test_preference_and_browser_fallback(self):
        for headers, expected in [({},'en'),({'Accept-Language':'id-ID,id;q=0.9,en;q=0.8'},'id'),
                ({'Cookie':'phylax_language=en','Accept-Language':'id'},'en'),
                ({'Cookie':'phylax_language=id','Accept-Language':'en'},'id'),
                ({'Cookie':'phylax_language=unknown','Accept-Language':'id'},'id'),
                ({'Accept-Language':'id;q=0,en;q=0.1'},'en'),
                ({'Accept-Language':'id;q=invalid,en;q=0.5'},'en'),
                ({'Accept-Language':'en;q=0.8,id;q=0.8'},'en')]:
            with self.subTest(headers=headers):self.assertEqual(request_language(headers),expected)

    def test_redirect_is_local_and_preserves_investigation(self):
        for value in ('https://example.com','//example.com','/\\example.com','/\r\nHost: evil','/language','',None):
            self.assertEqual(local_destination(value),'/')
        self.assertEqual(local_destination('/triage?q=PLC&page=2#alert-a'),'/triage?q=PLC&page=2#alert-a')

    def test_catalog_templates_keep_every_placeholder(self):
        for source,target in catalog().items():
            with self.subTest(source=source):
                self.assertTrue(target.strip())
                self.assertEqual(sorted(re.findall(r'\{\d+\}',source)),sorted(re.findall(r'\{\d+\}',target)))

    def test_dynamic_application_messages(self):
        cases={
            'Imported 7 asset rows; 2 row errors.':'7 baris aset diimpor; 2 baris bermasalah.',
            'Page 3 · 124 records':'Halaman 3 · 124 catatan',
            'Invalid remediation transition: Recommended → Verified':'Peralihan status remediasi tidak valid: Direkomendasikan → Terverifikasi',
            'Configured: openrouter · requested model test/model · timeout 30 seconds':'Dikonfigurasi: openrouter · model diminta test/model · batas waktu 30 detik',
            'Saved page 3; 50 records on this page, 150/200 fetched in this window.':'Halaman 3 disimpan; 50 catatan pada halaman ini, 150/200 diambil dalam jendela ini.',
            'ip_address must be a valid IPv4 or IPv6 address':'ip_address harus berupa alamat IPv4 atau IPv6 yang valid',
            'Modbus write operation from 192.0.2.1 to 192.0.2.2 is not in the configured authorized-writer policy.':'Operasi penulisan Modbus dari 192.0.2.1 ke 192.0.2.2 tidak tercantum dalam kebijakan pengirim berizin yang dikonfigurasi.'}
        for source,target in cases.items():
            with self.subTest(source=source):self.assertEqual(translate_text(source,'id'),target)

    def test_html_entities_escaping_raw_records_and_accessible_labels(self):
        source='<html lang="en"><style>.high{color:red}</style><p>Changes were not saved</p><p>'+html.escape("CISA's catalog of vulnerabilities with documented exploitation. Membership raises urgency; it does not establish an attack on this device.")+'</p><p translate="no">High &lt;script&gt; &amp; Overview</p><pre>{"status":"Approved"}</pre><textarea name="owner">High &lt;script&gt;</textarea><input name="q" value="High" placeholder="Search assets" aria-label="Search assets"><div class="advisory-text" aria-label="Full advisory text">No records yet.</div></html>'
        body=translate_html(source,'id')
        self.assertIn('lang="id"',body);self.assertIn('Perubahan belum disimpan',body)
        self.assertIn('Katalog CISA berisi kerentanan',body)
        self.assertIn('High &lt;script&gt; &amp; Overview',body)
        self.assertIn('{"status":"Approved"}',body)
        self.assertIn('>High &lt;script&gt;</textarea>',body)
        self.assertIn('value="High" placeholder="Cari aset" aria-label="Cari aset"',body)
        self.assertIn('aria-label="Teks advisori lengkap">No records yet.',body)
        self.assertIn('.high{color:red}',body);self.assertNotIn('<script>',body)
        self.assertEqual(translate_html(source,'en'),source)

    def test_composite_captions_and_inline_machine_evidence(self):
        caption='Showing 2 of 4 observed endpoints · 1 diagram connections · 2 endpoints omitted. Scroll within the diagram to explore. Zone membership comes from inventory; no trust boundaries are inferred.'
        translated=translate_text(caption,'id')
        self.assertIn('Menampilkan 2 dari 4 perangkat teramati',translated)
        self.assertIn('2 perangkat tidak ditampilkan',translated)
        self.assertNotIn('Scroll within',translated)
        payload='{"verified": false, "priority": "high", "versions": ["1.0"]}'
        self.assertEqual(translate_text('Matched source condition: '+payload,'id'),'Kondisi sumber yang cocok: '+payload)
        ref='event:2026-11-12T01:00:00Z:WRITE_SINGLE_REGISTER:hash'
        self.assertEqual(translate_text(ref,'id'),ref)


class LocalizedHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();root=Path(cls.temp.name)
        cls.database=prepare(root/'demo')['database']

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def setUp(self):
        self.store=Store(':memory:')
        source=Store(self.database);source.connection.backup(self.store.connection);source.close()
        self.server=SimpleNamespace(server_address=('127.0.0.1',8765))
        self.fid=self.store.connection.execute('SELECT finding_id FROM findings LIMIT 1').fetchone()[0]
        finding=self.store.finding(self.fid)
        for key in ('evidence','missing_evidence'):finding[key]=json.loads(finding[key])
        plan=compose_plan(finding,self.store.public_vulnerability_for_finding(self.fid))
        self.store.create_remediation_plan(self.fid,'template-fallback','',plan,plan['source_references'])

    def tearDown(self):self.store.close()

    def handler(self,path,values=None,language='id'):
        body=urlencode({'csrf_token':Handler.csrf_token,**values}) if values is not None else ''
        handler=object.__new__(Handler);handler.store=self.store;handler.server=self.server;handler.path=path
        handler.headers={'Host':'127.0.0.1:8765','Origin':'http://127.0.0.1:8765',
                         'Content-Type':'application/x-www-form-urlencoded','Content-Length':str(len(body.encode())),
                         'Cookie':'phylax_language='+language}
        handler.rfile=io.BytesIO(body.encode());handler.wfile=io.BytesIO();handler.response_headers={}
        handler.send_response=lambda status:setattr(handler,'response_status',status)
        handler.send_header=lambda key,value:handler.response_headers.update({key:value})
        handler.end_headers=lambda:None
        return handler

    def get(self,path,language='id'):
        handler=self.handler(path,language=language);handler.do_GET()
        return handler,handler.wfile.getvalue().decode()

    def test_all_pages_localize_and_keep_functional_markup(self):
        routes={
            '/':'Ringkasan keamanan','/assets':'Perangkat','/assets/edit':'Tambahkan aset',
            '/assets/edit?asset_id=lab-plc':'Edit aset','/network':'Aktivitas jaringan',
            '/attack-surface':'Peta jaringan','/intelligence':'Kerentanan yang diketahui',
            '/intelligence/ics':'Advisori industri','/triage':'Peringatan',
            '/reports':'Laporan','/settings':'Pengaturan','/policy':'Aturan jaringan',
            '/glossary':'Glosarium','/remediation':'Rencana perbaikan','/approvals':'Persetujuan perangkat',
            '/changes':'Perubahan perangkat',
            '/software':'Perangkat lunak di perangkat','/processes':'Pemilik dan penggunaan',
            '/evidence?event_ref=missing':'Catatan asli','/?finding_id='+self.fid:'Temuan kerentanan'}
        for route,title in routes.items():
            with self.subTest(route=route):
                handler,body=self.get(route);_,english=self.get(route,'en')
                self.assertEqual(handler.response_status,200)
                self.assertEqual(re.search(r'<h1>(.*?)</h1>',body)[1],title)
                self.assertIn('lang="id"',body)
                self.assertIn('name="language"',body);self.assertIn('name="csrf_token"',body)
                self.assertIn('value="id" selected',body)
                self.assertEqual(handler.response_headers['Content-Language'],'id')
                self.assertEqual(handler.response_headers['Content-Length'],str(len(body.encode())))
                self.assertEqual(Markup(body).wire,Markup(english).wire)

    def test_empty_pages_also_localize(self):
        self.store.close();self.store=Store(':memory:')
        for path,expected in [('/','Mulai dengan inventaris aset Anda'),('/assets','Aset tidak ditemukan.'),
                ('/triage','Tidak ada peringatan di kolom ini.'),('/triage?view=list','Tidak ada peringatan aktif'),('/software','Belum ada bukti perangkat lunak'),
                ('/remediation','Belum ada rencana remediasi'),
                ('/intelligence','Catatan intelijen tidak ditemukan')]:
            with self.subTest(path=path):
                handler,body=self.get(path);self.assertEqual(handler.response_status,200);self.assertIn(expected,body)

    def test_language_switch_persists_and_preserves_filter_destination(self):
        path='/triage?category=network&page=2#alert-test'
        handler=self.handler('/language',{'language':'id','next':path},language='en');handler.do_POST()
        self.assertEqual(handler.response_status,303);self.assertEqual(handler.response_headers['Location'],path)
        self.assertEqual(handler.response_headers['Set-Cookie'],'phylax_language=id; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax')
        handler=self.handler('/language',{'language':'en','next':'/assets?q=LAB'});handler.do_POST()
        self.assertIn('phylax_language=en;',handler.response_headers['Set-Cookie'])
        _,body=self.get('/assets','en');self.assertIn('<html lang="en">',body);self.assertIn('<h1>Devices</h1>',body)

    def test_switch_retains_host_origin_csrf_and_redirect_protections(self):
        for key,value in [('csrf_token','bad'),('language','fr')]:
            handler=self.handler('/language',{'language':'id','next':'/',key:value});handler.do_POST()
            self.assertIn(handler.response_status,{400,403});self.assertNotIn('Set-Cookie',handler.response_headers)
        handler=self.handler('/language',{'language':'id','next':'https://example.com'});handler.do_POST()
        self.assertEqual(handler.response_headers['Location'],'/')
        for header,value in [('Host','evil.example'),('Origin','https://evil.example')]:
            handler=self.handler('/language',{'language':'id'});handler.headers[header]=value;handler.do_POST()
            self.assertEqual(handler.response_status,403);self.assertNotIn('Set-Cookie',handler.response_headers)

    def test_inventory_error_localizes_and_preserves_draft(self):
        handler=self.handler('/assets/save',{'asset_id':'lab-plc','ip_address':'invalid','hostname':'High <script>draft</script>','verified':'false'})
        handler.do_POST();body=handler.wfile.getvalue().decode()
        self.assertEqual(handler.response_status,400);self.assertIn('Perubahan belum disimpan',body)
        self.assertIn('Alamat IP harus berupa alamat IPv4 atau IPv6 yang valid',body)
        self.assertIn('value="High &lt;script&gt;draft&lt;/script&gt;"',body)
        self.assertNotIn('<script>draft',body);self.assertIn('value="false" selected',body)
        self.assertNotEqual(self.store.assets()[0]['ip_address'],'invalid')
        self.assertIn('name="next" value="/assets/edit"',body)

    def test_policy_json_error_is_translated_without_applying_draft(self):
        handler=self.handler('/policy/apply',{'policy_json':'{bad json'})
        before=list(self.store.connection.execute('SELECT * FROM network_policies'))
        handler.do_POST();body=handler.wfile.getvalue().decode()
        self.assertEqual(handler.response_status,400)
        self.assertIn('Nama properti JSON harus diapit tanda petik ganda',body)
        self.assertIn('>{bad json</textarea>',body)
        self.assertEqual(before,list(self.store.connection.execute('SELECT * FROM network_policies')))
        self.assertIn('name="next" value="/policy"',body)

    def test_context_save_uses_canonical_lifecycle_and_translates_redirect_notice(self):
        from phylax.asset_intelligence import context_revision
        handler=self.handler('/processes/context',{'asset_id':'lab-it','context_revision':context_revision(self.store,'lab-it'),
                                                 'owner':'Indonesian operator','lifecycle':'maintenance'})
        handler.do_POST();self.assertEqual(handler.response_status,303)
        saved=self.store.connection.execute("SELECT owner,lifecycle FROM asset_context WHERE asset_id='lab-it'").fetchone()
        self.assertEqual(tuple(saved),('Indonesian operator','maintenance'))
        _,body=self.get(handler.response_headers['Location']);self.assertIn('Konteks aset disimpan.',body)
        self.assertIn('value="maintenance" selected',body)

    def test_remediation_rejects_invalid_transition_in_indonesian(self):
        before=self.store.get_remediation_plan(self.fid)
        handler=self.handler('/remediation/update',{'finding_id':self.fid,'status':'Verified','reviewer':'operator'})
        handler.do_POST();body=handler.wfile.getvalue().decode()
        self.assertEqual(handler.response_status,400);self.assertIn('Peralihan status remediasi tidak valid',body)
        self.assertEqual(before,self.store.get_remediation_plan(self.fid))
        self.assertIn('value="Verified"',body)

    def test_background_jobs_localize_per_viewer(self):
        self.server.jobs=SimpleNamespace(get=lambda key:{'label':'Sync public sources','message':'Saved page 3; 50 records on this page, 150/200 fetched in this window.',
                                                       'status':'running','updated_at':'2026-11-12T00:00:00Z'})
        _,body=self.get('/jobs/test');self.assertIn('Halaman 3 disimpan;',body);self.assertIn('<dd>berjalan</dd>',body)
        self.assertIn('http-equiv="refresh" content="2"',body)
        _,english=self.get('/jobs/test','en');self.assertIn('Saved page 3;',english);self.assertIn('<dd>running</dd>',english)

    def test_reports_translate_readable_text_and_preserve_data_exports(self):
        _,markdown=self.get('/report.md');self.assertIn('# Laporan investigasi Phylax',markdown)
        self.assertIn('## Penilaian kerentanan',markdown);self.assertIn('## Batasan yang diketahui',markdown)
        self.assertIn('CVE-2099-99999',markdown)
        for path in ('/report.json','/report.csv','/assets.csv'):
            _,indonesian=self.get(path);_,english=self.get(path,'en')
            if path.endswith('.json'):
                a,b=json.loads(indonesian),json.loads(english);a.pop('generated_at');b.pop('generated_at')
                self.assertEqual(a,b)
            else:
                # Metadata timestamps can differ; schemas and canonical statuses cannot.
                self.assertEqual(indonesian.splitlines()[0],english.splitlines()[0])
            self.assertNotIn('TERKONFIRMASI TERDAMPAK',indonesian)

    def test_external_text_and_raw_evidence_stay_in_source_language(self):
        self.store.connection.execute("UPDATE assets SET hostname='Overview',notes='High <script>operator</script>' WHERE asset_id='lab-plc'")
        self.store.connection.execute("UPDATE vulnerabilities SET summary='No records yet.',mitigation='High'")
        self.store.connection.commit()
        _,body=self.get('/assets');self.assertIn('<span translate="no">Overview</span>',body)
        self.assertIn('<span translate="no">High &lt;script&gt;operator&lt;/script&gt;</span>',body)
        _,body=self.get('/intelligence');self.assertIn('<span translate="no">No records yet.</span>',body)
        self.assertIn('<span translate="no">High</span>',body)
        self.assertIn('<h1>Kerentanan yang diketahui</h1>',body)


if __name__=='__main__':unittest.main()
