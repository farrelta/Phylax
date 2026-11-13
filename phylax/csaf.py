"""Narrow official CSAF 2.0 ingestion: exact CPEs, explicit status, no prose ranges."""
from __future__ import annotations
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from .core import utc_now
from .asset_intelligence import text
from .identifiers import cpe_parts
from .validation import vulnerability


def official_url(url):
    url=text(url,2048);p=urllib.parse.urlsplit(url)
    allowed=(p.hostname=='raw.githubusercontent.com' and re.fullmatch(r'/cisagov/CSAF/(?:develop|main)/csaf_files/[A-Za-z0-9_./+-]+\.json',p.path)) or (p.hostname=='www.cisa.gov' and p.path.startswith('/sites/default/files/csaf/') and p.path.endswith('.json'))
    if p.scheme!='https' or p.port not in {None,443} or p.username or p.password or p.query or p.fragment or '%' in p.path or '..' in p.path or not allowed:
        raise ValueError('Use an official CISA CSAF document HTTPS URL')
    return url


def configure(store,url,enabled=True):
    url=official_url(url)
    if store.connection.execute('SELECT COUNT(*) FROM csaf_documents').fetchone()[0]>=25 and not store.connection.execute('SELECT 1 FROM csaf_documents WHERE url=?',(url,)).fetchone():raise ValueError('At most 25 advisory URLs are supported')
    store.connection.execute('INSERT INTO csaf_documents(url,enabled) VALUES(?,?) ON CONFLICT(url) DO UPDATE SET enabled=excluded.enabled',(url,int(enabled)))
    store.audit('csaf_source_configured',url,{'enabled':enabled});store.connection.commit()


def normalize(document,url,retrieved_at):
    if not isinstance(document,dict) or document.get('document',{}).get('csaf_version')!='2.0':raise ValueError('Expected a CSAF 2.0 document')
    meta=document['document'];tracking=meta.get('tracking',{})
    advisory_id=text(tracking.get('id',''),300)
    if not advisory_id:raise ValueError('CSAF tracking ID is required')
    products={};tree=document.get('product_tree',{})
    if not isinstance(tree,dict):raise ValueError('Invalid product tree')
    def walk(branch,depth=0,unresolved=False,vendor='',name='',version=''):
        if depth>32 or len(products)>10000:raise ValueError('CSAF product tree exceeds bounds')
        if not isinstance(branch,dict):raise ValueError('Invalid CSAF product branch')
        category=branch.get('category','')
        unresolved=unresolved or category=='product_version_range' or category not in {'','vendor','product_family','product_name','product_version'}
        if category=='vendor':vendor=text(branch.get('name',''),500)
        if category=='product_name':name=text(branch.get('name',''),500)
        if category=='product_version':version=text(branch.get('name',''),200)
        product=branch.get('product')
        if product:
            if not isinstance(product,dict) or not isinstance(product.get('product_id'),str):raise ValueError('Invalid CSAF product ID')
            products[product['product_id']]=(product,unresolved,vendor,name,version)
        for child in branch.get('branches',[]):walk(child,depth+1,unresolved,vendor,name,version)
    for product in tree.get('full_product_names',[]):walk({'product':product})
    walk(tree)
    records=[];vulns=document.get('vulnerabilities',[])
    if not isinstance(vulns,list) or len(vulns)>10000:raise ValueError('Invalid vulnerability list')
    for v in vulns:
        if not isinstance(v,dict):raise ValueError('Invalid CSAF vulnerability')
        if not v.get('cve'):continue
        affected=[];statuses=v.get('product_status',{})
        if not isinstance(statuses,dict):raise ValueError('Invalid CSAF product status')
        for status,ids in statuses.items():
            if not isinstance(ids,list) or any(not isinstance(i,str) for i in ids):raise ValueError('Invalid CSAF product IDs')
            if status=='recommended':continue # recommendation does not mean fixed
            for pid in ids:
                if pid not in products:continue # retained in raw document for review
                product,unresolved,branch_vendor,branch_name,branch_version=products[pid]
                cpe=product.get('product_identification_helper',{}).get('cpe','')
                parts=cpe_parts(cpe)
                if parts and not any(x in {'*','-',''} for x in parts[3:5]):
                    vendor,name,version=parts[3:6]
                elif branch_vendor and branch_name:
                    vendor,name,version=branch_vendor,branch_name,branch_version
                else:continue
                item={'vendor':vendor,'product':name,'versions':[],'excluded_versions':[],'cpe_names':[cpe] if parts else [],
                      'version_semantics_unknown':True} # Unlisted versions are not established safe.
                exact=version not in {'*','-',''} and not any(c in version for c in '*?')
                if status=='known_affected' and exact:item['versions']=[version]
                elif status in {'fixed','known_not_affected'} and exact:item['excluded_versions']=[version]
                else:unresolved=True
                item['conditions_unresolved']=bool(unresolved or tree.get('relationships'))
                affected.append(item)
        notes=v.get('notes',[])
        summary='\n'.join(n.get('text','') for n in notes if isinstance(n,dict) and isinstance(n.get('text'),str)) or v.get('title') or meta.get('title') or advisory_id
        mitigations='\n'.join(n.get('details','') for n in v.get('remediations',[]) if isinstance(n,dict) and isinstance(n.get('details'),str))
        refs=[url]+[r['url'] for r in meta.get('references',[])+v.get('references',[]) if isinstance(r,dict) and isinstance(r.get('url'),str) and r['url'].startswith('https://')]
        record={'cve_id':v['cve'],'summary':summary,'source':'CISA CSAF: '+advisory_id,'source_url':url,
                'synthetic':False,'published':tracking.get('initial_release_date',''),'modified':tracking.get('current_release_date',''),
                'retrieved_at':retrieved_at,'affected_products':affected,'references':list(dict.fromkeys(refs)),
                'mitigation':mitigations,'severity':'','cvss':None}
        # Product-specific multiple scores must not silently become a universal score.
        scores=v.get('scores',[])
        if len(scores)==1:
            score=scores[0].get('cvss_v3',scores[0].get('cvss_v4',{}))
            record['severity']=str(score.get('baseSeverity','')).lower();record['cvss']=score.get('baseScore')
        records.append(vulnerability(record))
    advisory={'advisory_id':advisory_id,'title':meta.get('title',advisory_id),'link':url,'published':tracking.get('initial_release_date',''),
              'summary':'CSAF document retained with complete product statuses; unsupported expressions require review.','source':'CISA CSAF','retrieved_at':retrieved_at}
    return records,[advisory]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def retrieve(url,etag):
    request=urllib.request.Request(official_url(url),headers={'User-Agent':'Phylax/0.2',**({'If-None-Match':etag} if etag else {})})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request,timeout=10) as response:
            body=response.read(2_000_001)
            if len(body)>2_000_000:raise ValueError('CSAF document exceeds 2 MB')
            return response.status,body,response.headers.get('ETag','')[:200]
    except urllib.error.HTTPError as exc:
        if exc.code==304:return 304,b'',etag
        raise


def sync_csaf(store,*,fetcher=retrieve,progress=None):
    rows=store.connection.execute('SELECT * FROM csaf_documents WHERE enabled=1').fetchall()
    if not rows:return {}
    results={};count=0;failures=[]
    for row in rows:
        url=row['url']
        try:
            if progress:progress('CISA CSAF','progress','Retrieving configured advisory '+url)
            status,body,etag=fetcher(url,row['etag'])
            if status==304:
                if not row['body_json']:raise ValueError('Provider returned 304 without a local cache')
                results[url]={'ok':True,'cached':True};continue
            if status!=200:raise ValueError('Unexpected CSAF response status')
            if len(body)>2_000_000:raise ValueError('CSAF document exceeds 2 MB')
            document=json.loads(body);when=utc_now();records,advisories=normalize(document,url,when)
            if records:store.ingest_normalized(records,trusted_public=True)
            store.save_ics_advisories(advisories)
            store.connection.execute('UPDATE csaf_documents SET etag=?,body_json=?,retrieved_at=? WHERE url=?',(etag,json.dumps(document),when,url));store.connection.commit()
            count+=len(records)+len(advisories);results[url]={'ok':True,'records':len(records)}
        except Exception as exc:
            failures.append(f'{type(exc).__name__}: {exc}');results[url]={'ok':False,'error':str(exc)}
    store.set_source_health('CISA CSAF','unavailable' if failures else 'healthy',records=count,message='; '.join(failures) or f'{len(rows)} configured advisories checked; cached records retained')
    return {'CISA CSAF':{'ok':not failures,'records':count,'documents':results}}
