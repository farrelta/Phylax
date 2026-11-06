"""Prepare an isolated fictional TNI AD support-site demonstration, without probes."""
import argparse
import io
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from phylax.core import Store
from phylax.asset_intelligence import add_subnet,endpoint_decision,save_context,save_process
from phylax.discovery import save_target
from phylax.monitoring import reevaluate_events
from scripts.generate_passive_demo import generate


def prepare(directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    store=Store(directory/'phylax-demo.db')
    try:
        store.connection.execute("INSERT OR REPLACE INTO schema_meta VALUES('dataset_label','SYNTHETIC fictional TNI AD support-site lab. No real TNI assets, topology, incidents, or endorsement.')");store.connection.commit()
        rows='asset_id,ip_address,hostname,asset_type,vendor,product,version,zone,criticality,identity_confidence,verified,notes\n'
        for aid,ip,host,kind,version,confidence in (
            ('lab-plc','172.30.77.10','LAB-Cooling-PLC','PLC','1.0','high'),
            ('lab-fixed','172.30.77.11','LAB-Excluded-Version','PLC','2.0','high'),
            ('lab-potential','172.30.77.12','LAB-Version-Unknown','PLC','','high'),
            ('lab-review','172.30.77.13','LAB-Identity-Unknown','PLC','1.0','low')):
            rows+=f'{aid},{ip},{host},{kind},PhylaxLab,CoolingController,{version},OT,critical,{confidence},true,SYNTHETIC fixture only; not a real TNI asset\n'
        rows+='lab-it,172.30.77.40,LAB-Logistics-IT,server,,,,IT,high,high,true,SYNTHETIC Docker supporting IT service\n'
        rows+='lab-reader,172.30.77.30,LAB-Engineering,engineering workstation,,,,OT,high,high,true,SYNTHETIC authorized simulator client\n'
        store.import_csv(io.StringIO(rows))
        sid=add_subnet(store,'Fictional support facility','172.30.77.0/24')
        for ip in ('172.30.77.10','172.30.77.30','172.30.77.40'):
            endpoint_decision(store,sid,ip=ip,actor='Lab fixture operator',note='Explicit management approval for isolated synthetic demonstration')
        save_context(store,'lab-plc',owner='Fictional facility maintainer',site='SIMULATED support site',location='Simulated cooling room',lifecycle='commissioned',tags=['SYNTHETIC','utility-support'],criticality_rationale='Operator-assigned lab criticality for a simulated supporting process')
        save_process(store,'Simulated facility cooling','Fictional operational-support process; no real mission or equipment','lab-plc','Lab fixture operator','Explicit synthetic relationship for demonstrating context')
        tid=save_target(store,'lab-it',[8080],identify={'8080':'http'},permission=False,actor='Lab fixture operator',note='Disabled initially; grant only after verifying the Compose lab is running')
        policy={'protected_assets':['172.30.77.10'],'authorized_writers':{'172.30.77.10':['172.30.77.30']},
                'allowed_communications':[{'source_ip':'172.30.77.30','destination_ip':'172.30.77.10','destination_port':502,'protocol':'tcp'}],
                'maintenance_windows_utc':[]}
        reevaluate_events(store,policy)
        fixture={'synthetic':True,'vulnerabilities':[{'cve_id':'CVE-2099-99999','summary':'SYNTHETIC TEST ONLY: CoolingController applicability demonstration; not a public CVE or incident',
                    'source':'synthetic-release-demo','synthetic':True,'severity':'high','kev':False,
                    'affected_products':[{'vendor':'PhylaxLab','product':'CoolingController','versions':['1.0']}],
                    'references':[],'mitigation':'Synthetic test case; no vendor mitigation is asserted.'}]}
        store.ingest_fixture(fixture)
        (directory/'synthetic-advisory.json').write_text(json.dumps(fixture,indent=2))
        (directory/'policy.json').write_text(json.dumps(policy,indent=2))
        (directory/'README.txt').write_text('SYNTHETIC FICTIONAL TNI AD SUPPORT FACILITY. No real TNI assets, topology, incidents, or endorsement. Active scan permission is initially disabled. Public AI guidance requires a separately refreshed real advisory.\n')
        generate(directory/'replay-captures',controller='172.30.77.10',reader='172.30.77.30',writer='172.30.77.99')
        return {'database':str(directory/'phylax-demo.db'),'scan_target_id':tid,'scan_permission':False,'synthetic':True,'applicability':store.correlate()}
    finally:store.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output-dir',type=Path,required=True)
    print(json.dumps(prepare(parser.parse_args().output_dir),indent=2))
