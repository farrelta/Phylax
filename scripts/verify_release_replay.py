"""Offline end-to-end release rehearsal using the locally installed Zeek image."""
import argparse
import json
import platform
import resource
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.prepare_release_demo import prepare
from phylax.core import Store,utc_now
from phylax.pcap import analyze_pcap
from phylax.triage import triage,acknowledge


def verify(directory,image):
    initial=prepare(directory);store=Store(initial['database']);started=time.perf_counter()
    try:
        policy=json.loads((directory/'policy.json').read_text())
        results=[]
        for label,count in (('benign-read',0),('unauthorized-write',3)):
            result=analyze_pcap(store,directory/'replay-captures'/f'synthetic-{label}.pcap',policy=policy,docker_image=image)
            actual=store.connection.execute('SELECT COUNT(*) FROM network_alerts').fetchone()[0]
            if actual!=count:raise RuntimeError(f'{label}: expected {count} network alerts, got {actual}')
            results.append(result)
        before=store.connection.execute('SELECT COUNT(*) FROM network_events').fetchone()[0]
        again=analyze_pcap(store,directory/'replay-captures/synthetic-unauthorized-write.pcap',policy=policy,docker_image=image)
        if not again.get('already_analyzed') or store.connection.execute('SELECT COUNT(*) FROM network_events').fetchone()[0]!=before:raise RuntimeError('Duplicate replay was not deduplicated')
        rows,_=triage(store)
        unmanaged=[r for r in rows if r['category']=='endpoint' and r['ip']=='172.30.77.99']
        if len(unmanaged)!=1:raise RuntimeError('Unmanaged writer was not found')
        acknowledge(store,'endpoint',unmanaged[0]['alert_id'])
        if not next(r for r in triage(store)[0] if r['alert_id']==unmanaged[0]['alert_id'])['acknowledged']:raise RuntimeError('Acknowledgement did not persist')
        for format,suffix in (('json','json'),('csv','csv'),('markdown','md')):
            (directory/f'report.{suffix}').write_text(store.report(format),encoding='utf-8')
        summary={'generated_at':utc_now(),'synthetic':True,'scope':'Fictional support facility; no network packets sent by the PCAP runner',
                 'image':image,'python':platform.python_version(),'platform':platform.platform(),
                 'elapsed_seconds':round(time.perf_counter()-started,6),'peak_rss_mib':round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,2),
                 'states':initial['applicability'],'network_alerts':3,'unmanaged_writer_alerts':1,'events':before,
                 'deduplicated':True,'acknowledgement_persisted':True,'reports':['json','csv','markdown'],'captures':results}
        (directory/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
        return summary
    finally:store.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output-dir',required=True,type=Path);parser.add_argument('--docker-image',required=True)
    args=parser.parse_args();print(json.dumps(verify(args.output_dir,args.docker_image),indent=2))
