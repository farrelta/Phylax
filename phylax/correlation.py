"""Conservative component assessments aggregated into stable asset/CVE findings."""
import hashlib
import json
import uuid
from .core import _normalized,_version_applicability,utc_now

ORDER={'CONFIRMED_MATCH':0,'POTENTIAL_MATCH':1,'NEEDS_REVIEW':2,'NO_MATCH_TO_THIS_ADVISORY':3}


def assess(identity,product):
    base=[f"Exact vendor/product match: {product['vendor']} {product['product']}"]
    if product.get('conditions_unresolved'):return 'NEEDS_REVIEW',base,['source configuration prerequisites are not evaluated by this matcher']
    if identity.get('identity_confidence')=='low':return 'NEEDS_REVIEW',base,['asset identity confidence is low; verify vendor and product']
    if not identity['version']:return 'POTENTIAL_MATCH',base,['asset version; source version applicability cannot be evaluated']
    result=_version_applicability(identity['version'],product)
    if result is None:return 'NEEDS_REVIEW',base,['source version semantics cannot be compared safely with '+identity['version']]
    confirmed=identity.get('identity_confidence')=='high' and identity.get('verified')
    if result:
        return ('CONFIRMED_MATCH' if confirmed else 'POTENTIAL_MATCH',base+[f"Asset version {identity['version']} matches source-defined affected-version data"],[] if confirmed else ['asset identity has not been confirmed at high confidence'])
    if not confirmed:return 'NEEDS_REVIEW',base,['asset identity must be confirmed before excluding applicability']
    return 'NO_MATCH_TO_THIS_ADVISORY',base+[f"Asset version {identity['version']} is outside source-defined affected versions"],[]


def correlate(store,asset_ids=None,cve_ids=None,commit=True):
    db=store.connection;counts={};scope=set(cve_ids) if cve_ids is not None else None
    assets=store.assets() if asset_ids is None else [dict(r) for aid in set(asset_ids) if (r:=db.execute('SELECT * FROM assets WHERE asset_id=?',(aid,)).fetchone())]
    for asset in assets:
        identities=[dict(asset,component_id='inventory')]
        for component in db.execute('SELECT * FROM software_components WHERE asset_id=? AND active=1',(asset['asset_id'],)):
            identities.append(dict(component,identity_confidence='high' if component['verified'] else 'medium'))
        candidates={}
        for identity in identities:
            if identity['vendor'] and identity['product']:
                for r in db.execute('SELECT v.* FROM vulnerabilities v JOIN affected_product_index i USING(cve_id) WHERE i.vendor=? AND i.product=?',(_normalized(identity['vendor']),_normalized(identity['product']))):
                    if scope is None or r['cve_id'] in scope:candidates[r['cve_id']]=dict(r)
        for old in db.execute('SELECT finding_id,cve_id FROM findings WHERE asset_id=?',(asset['asset_id'],)).fetchall():
            if old['cve_id'] not in candidates and (scope is None or old['cve_id'] in scope):
                store._archive_plan(old['finding_id'],'Asset/product applicability changed');db.execute('DELETE FROM findings WHERE finding_id=?',(old['finding_id'],))
        for cve,vuln in candidates.items():
            documents=[json.loads(vuln['affected_products'])]
            documents += [json.loads(r[0]).get('affected_products',[]) for r in db.execute('SELECT record_json FROM vulnerability_sources WHERE cve_id=?',(cve,))]
            results=[]
            for identity in identities:
                matches={json.dumps(p,sort_keys=True):p for products in documents for p in products if _normalized(p['vendor'])==_normalized(identity['vendor']) and _normalized(p['product'])==_normalized(identity['product'])}
                if not matches:continue
                assessments=[assess(identity,p) for p in matches.values()]
                statuses={a[0] for a in assessments}
                # Confirmed affected/excluded contradictions must not be hidden by precedence.
                if 'NO_MATCH_TO_THIS_ADVISORY' in statuses and statuses & {'CONFIRMED_MATCH','POTENTIAL_MATCH'}:
                    status='NEEDS_REVIEW';missing=['conflicting source product/version applicability']
                else:
                    status='NEEDS_REVIEW' if 'NEEDS_REVIEW' in statuses else min(statuses,key=ORDER.get)
                    missing=sorted({m for s,e,ms in assessments for m in ms})
                evidence=[f"Component {identity['component_id']}"]+[e for s,es,ms in assessments for e in es]
                evidence+=['Matched source condition: '+p for p in sorted(matches)]
                results.append({'component_id':identity['component_id'],'status':status,'evidence':evidence,'missing':missing})
            if not results:continue
            # Competing actively observed versions of one software identity invalidate certainty.
            software=[i for i in identities if i['component_id']!='inventory' and i['vendor'] and i['product']]
            conflicts={i['raw_name'] for i in software if len({j['version'] for j in software if j['raw_name']==i['raw_name']})>1}
            for result in results:
                identity=next(i for i in identities if i['component_id']==result['component_id'])
                if identity.get('raw_name') in conflicts:
                    result['status']='NEEDS_REVIEW';result['missing'].append('competing active software versions; retire obsolete evidence or verify installation scope')
            status=min((r['status'] for r in results),key=ORDER.get)
            evidence=[e for r in results for e in r['evidence']]
            evidence.append('Advisory content fingerprint: '+hashlib.sha256(json.dumps({k:vuln[k] for k in ('summary','mitigation','modified','references_json')},sort_keys=True).encode()).hexdigest()[:16])
            missing=sorted({m for r in results for m in r['missing']})
            priority=store._priority(asset,vuln,status)
            fid=str(uuid.uuid5(uuid.NAMESPACE_URL,f"{asset['asset_id']}:{cve}"))
            current=db.execute('SELECT * FROM findings WHERE asset_id=? AND cve_id=?',(asset['asset_id'],cve)).fetchone()
            if current:fid=current['finding_id']
            if current and (current['status']!=status or json.loads(current['evidence'])!=evidence or current['priority']!=priority):
                plan=store.get_remediation_plan(fid)
                if plan:
                    store._archive_plan(fid,'Supporting finding evidence changed')
                    db.execute("UPDATE remediation_plans SET status='Needs More Evidence',reviewer='',verification_evidence='',updated_at=? WHERE finding_id=?",(utc_now(),fid))
                    db.execute('INSERT INTO remediation_plan_events VALUES(?,?,?,?,?,?,?)',(str(uuid.uuid4()),plan['plan_id'],plan['status'],'Needs More Evidence','system','Supporting finding evidence changed; review required',utc_now()))
            db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,cve_id) DO UPDATE SET status=excluded.status,evidence=excluded.evidence,missing_evidence=excluded.missing_evidence,priority=excluded.priority,updated_at=excluded.updated_at',
                       (fid,asset['asset_id'],cve,status,json.dumps(evidence),json.dumps(missing),priority,utc_now()))
            db.execute('DELETE FROM component_assessments WHERE finding_id=?',(fid,))
            db.executemany('INSERT INTO component_assessments VALUES(?,?,?,?)',[(fid,r['component_id'],r['status'],json.dumps(r)) for r in results])
            counts[status]=counts.get(status,0)+1
            if status in {'CONFIRMED_MATCH','POTENTIAL_MATCH'}:
                explanation=f"{status}: {cve}; {evidence[0]}. KEV membership: {'yes' if vuln['kev'] else 'no'} (catalog status does not indicate this asset is under attack)."
                db.execute('INSERT INTO alerts VALUES(?,?,?,?,0,?,?) ON CONFLICT(finding_id) DO UPDATE SET severity=excluded.severity,explanation=excluded.explanation,updated_at=excluded.updated_at',
                           (str(uuid.uuid5(uuid.NAMESPACE_URL,fid)),fid,vuln['severity'] or 'Unknown',explanation,utc_now(),utc_now()))
            else:db.execute('DELETE FROM alerts WHERE finding_id=?',(fid,))
    if commit:db.commit()
    return counts
