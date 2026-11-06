"""Real loopback HTTP smoke test using a new synthetic database and no providers."""
import json
import queue
import re
import secrets
import sys
import tempfile
import threading
from http.server import HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request,urlopen
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.prepare_release_demo import prepare
from phylax.core import Store
from phylax.web import Handler
from phylax.jobs import Jobs


def verify():
    with tempfile.TemporaryDirectory(prefix='phylax-http-release-') as temp:
        prepared=prepare(Path(temp)/'site');ready=queue.Queue()
        def serve():
            store=Store(prepared['database']);Handler.store=store;Handler.csrf_token=secrets.token_urlsafe(32)
            server=HTTPServer(('127.0.0.1',0),Handler);server.jobs=Jobs(prepared['database']);ready.put(server)
            try:server.serve_forever(poll_interval=.05)
            finally:server.server_close();server.jobs.close();store.close()
        thread=threading.Thread(target=serve);thread.start();server=ready.get(timeout=10)
        base=f'http://127.0.0.1:{server.server_address[1]}';results={}
        try:
            paths=('/', '/assets','/intelligence','/network','/attack-surface','/remediation','/policy','/settings','/reports','/glossary',
                   '/discovery','/approvals','/changes','/software','/processes','/triage','/evidence','/report.json','/report.csv','/report.md')
            for path in paths:
                with urlopen(base+path,timeout=10) as response:
                    body=response.read();results[path]=response.status
                    if response.status!=200 or not response.headers.get('Content-Security-Policy'):raise RuntimeError('Route/header check failed: '+path)
                    if response.headers['Content-Type'].startswith('text/html') and b'SYNTHETIC fictional' not in body:raise RuntimeError('Missing dataset label: '+path)
            def post(path,values,capture=False,origin=None):
                req=Request(base+path,data=urlencode(values).encode(),headers={'Content-Type':'application/x-www-form-urlencoded','Origin':origin or base})
                try:
                    with urlopen(req,timeout=10) as response:
                        body=response.read();return (response.status,body) if capture else response.status
                except HTTPError as exc:
                    body=exc.read();return (exc.code,body) if capture else exc.code
            results['bad_csrf']=post('/approvals/subnet',{'name':'denied','cidr':'192.0.2.0/24'})
            results['good_csrf']=post('/approvals/subnet',{'csrf_token':Handler.csrf_token,'name':'Additional lab subnet','cidr':'192.0.2.0/24'})
            results['control_target_rejected']=post('/discovery/save',{'csrf_token':Handler.csrf_token,'asset_id':'lab-plc','ports':'502','permission':'true','actor':'Verifier','note':'Must reject'})
            results['disabled_it_target_saved']=post('/discovery/save',{'csrf_token':Handler.csrf_token,'asset_id':'lab-it','ports':'8080','permission':'false','actor':'Verifier','note':'No execution'})
            if (results['bad_csrf'],results['good_csrf'],results['control_target_rejected'],results['disabled_it_target_saved'])!=(403,200,400,200):raise RuntimeError('HTTP mutation boundary checks failed')
            with urlopen(base+'/processes?asset_id=lab-plc',timeout=10) as response:context_form=response.read().decode()
            revision=re.search(r'name="context_revision" value="([a-f0-9]+)"',context_form).group(1)
            context_values={'csrf_token':Handler.csrf_token,'asset_id':'lab-plc','context_revision':revision,'owner':'SYNTHETIC HTTP review owner'}
            results['context_saved']=post('/processes/context',context_values)
            results['stale_context_rejected']=post('/processes/context',{**context_values,'owner':'Must not overwrite'})
            results['opaque_origin_rejected']=post('/processes/context',context_values,origin='null')
            check=Store(prepared['database'])
            try:
                context=dict(check.connection.execute("SELECT * FROM asset_context WHERE asset_id='lab-plc'").fetchone())
                if context['owner']!='SYNTHETIC HTTP review owner' or context['location']!='Simulated cooling room' or context['lifecycle']!='commissioned':raise RuntimeError('Partial context edit lost existing values')
                with urlopen(base+'/processes?asset_id=lab-plc',timeout=10) as response:
                    revision=re.search(r'name="context_revision" value="([a-f0-9]+)"',response.read().decode()).group(1)
                status,body=post('/processes/context',{**context_values,'context_revision':revision,'owner':'Typed retry value','lifecycle':'invalid'},capture=True)
                results['context_error_retains_input']=status
                if b'Typed retry value' not in body or b'role="alert"' not in body or b'name="csrf_token"' not in body:raise RuntimeError('Context validation lost input or form protection')
                from phylax.remediation import compose_plan
                finding=next(f for f in check.dashboard()['findings'] if f['status']=='CONFIRMED_MATCH')
                fid=finding['finding_id']
                for key in ('evidence','missing_evidence'):finding[key]=json.loads(finding[key])
                plan=compose_plan(finding,check.public_vulnerability_for_finding(fid))
                check.create_remediation_plan(fid,'template-fallback','',plan,plan['source_references'])
                with urlopen(base+'/remediation?'+urlencode({'finding_id':fid,'page':99}),timeout=10) as response:
                    results['focused_plan']=response.status
                    if ('id="plan-'+fid+'"').encode() not in response.read():raise RuntimeError('Focused plan lost outside first page')
                results['plan_review_saved']=post('/remediation/update',{'csrf_token':Handler.csrf_token,'finding_id':fid,'status':'Under Review'})
                if check.get_remediation_plan(fid)['status']!='Under Review':raise RuntimeError('Plan review was not saved')
                try:
                    with urlopen(base+'/remediation?finding_id=missing',timeout=10) as response:results['missing_plan']=response.status
                except HTTPError as exc:
                    results['missing_plan']=exc.code;exc.close()
                from phylax.triage import triage
                alert=triage(check)[0][0]
                results['retired_ack']=post('/ack',{'csrf_token':Handler.csrf_token,'alert_id':alert['alert_id']})
                if next(r for r in triage(check)[0] if r['alert_id']==alert['alert_id'])['acknowledged']:raise RuntimeError('Retired route changed acknowledgement')
                results['triage_ack_saved']=post('/triage/ack',{'csrf_token':Handler.csrf_token,'category':alert['category'],'alert_id':alert['alert_id'],'filter_category':'exposure','acknowledged':'no'})
                if not next(r for r in triage(check)[0] if r['alert_id']==alert['alert_id'])['acknowledged']:raise RuntimeError('Triage acknowledgement did not persist')
            finally:check.close()
            if tuple(results[k] for k in ('context_saved','stale_context_rejected','opaque_origin_rejected','context_error_retains_input','triage_ack_saved'))!=(200,400,403,400,200):raise RuntimeError('Operator workflow HTTP checks failed')
            if tuple(results[k] for k in ('focused_plan','plan_review_saved','missing_plan','retired_ack'))!=(200,200,404,404):raise RuntimeError('Consolidated workflow checks failed')
            return {'routes_checked':len(paths),'results':results,'external_provider_calls':0,'active_scans':0}
        finally:server.shutdown();thread.join(timeout=10)


if __name__=='__main__':print(json.dumps(verify(),indent=2))
