"""Optional release command families; all scan execution goes through the worker."""
import json
from .core import Store
from .discovery import save_target,enqueue,worker,schedule,cancel,IDENTIFICATION
from .watcher import watch
from .asset_intelligence import add_subnet,endpoint_decision,revoke_decision
from .csaf import configure,sync_csaf

COMMANDS={'scan-target','scan','worker','watch-zeek','monitor-subnet','device-decision','csaf-source','sync-csaf'}


def parsers(commands):
    p=commands.add_parser('scan-target',help='Configure explicit IT discovery permissions and schedules')
    actions=p.add_subparsers(dest='action',required=True)
    save=actions.add_parser('save');save.add_argument('--asset-id',required=True);save.add_argument('--ports',nargs='+',type=int,required=True)
    save.add_argument('--identify',action='store_true');save.add_argument('--permit',action='store_true');save.add_argument('--actor',required=True);save.add_argument('--note',required=True)
    revoke=actions.add_parser('revoke');revoke.add_argument('target_id');revoke.add_argument('--actor',required=True);revoke.add_argument('--note',required=True)
    sched=actions.add_parser('schedule');sched.add_argument('target_id');sched.add_argument('--interval-minutes',type=int,default=60);sched.add_argument('--disable',action='store_true')
    actions.add_parser('list')
    p=commands.add_parser('scan',help='Queue an approved target or inspect/cancel an execution')
    group=p.add_mutually_exclusive_group(required=True);group.add_argument('--target');group.add_argument('--status');group.add_argument('--cancel')
    p=commands.add_parser('worker',help='Execute queued/scheduled discovery, one global run at a time');p.add_argument('--once',action='store_true')
    p=commands.add_parser('watch-zeek',help='Ingest stable finalized Zeek logs, never start capture')
    p.add_argument('--directory',required=True);p.add_argument('--interval-seconds',type=int,default=30);p.add_argument('--once',action='store_true')
    p=commands.add_parser('monitor-subnet');p.add_argument('name');p.add_argument('cidr')
    p=commands.add_parser('device-decision');p.add_argument('--subnet-id');p.add_argument('--ip',default='');p.add_argument('--mac',default='')
    p.add_argument('--decision',choices=('approved','blocked'),default='approved');p.add_argument('--revoke');p.add_argument('--actor',required=True);p.add_argument('--note',required=True)
    p=commands.add_parser('csaf-source');p.add_argument('url');p.add_argument('--disable',action='store_true')
    commands.add_parser('sync-csaf',help='Refresh only configured official structured advisories')


def handle(args):
    if args.command=='worker':return worker(args.db,args.once)
    if args.command=='watch-zeek':return watch(args.db,args.directory,args.interval_seconds,args.once)
    store=Store(args.db)
    try:
        if args.command=='scan-target':
            if args.action=='save':
                identify={str(p):IDENTIFICATION[p] for p in args.ports if p in IDENTIFICATION} if args.identify else {}
                return {'target_id':save_target(store,args.asset_id,args.ports,identify=identify,permission=args.permit,actor=args.actor,note=args.note)}
            if args.action=='list':return [dict(r) for r in store.connection.execute('SELECT * FROM scan_targets')]
            if args.action=='schedule':schedule(store,args.target_id,args.interval_minutes,not args.disable);return {'scheduled':not args.disable}
            row=store.connection.execute('SELECT * FROM scan_targets WHERE target_id=?',(args.target_id,)).fetchone()
            if not row:raise ValueError('Target not found')
            save_target(store,row['asset_id'],json.loads(row['ports_json']),identify=json.loads(row['identification_json']),permission=False,actor=args.actor,note=args.note)
            return {'revoked':args.target_id}
        if args.command=='scan':
            if args.target:return {'run_id':enqueue(store,args.target)}
            if args.cancel:cancel(store,args.cancel);return {'cancel_requested':args.cancel}
            row=store.connection.execute('SELECT * FROM scan_runs WHERE run_id=?',(args.status,)).fetchone()
            if not row:raise ValueError('Run not found')
            return dict(row)
        if args.command=='monitor-subnet':return {'subnet_id':add_subnet(store,args.name,args.cidr)}
        if args.command=='device-decision':
            if args.revoke:revoke_decision(store,args.revoke,args.actor,args.note);return {'revoked':args.revoke}
            return {'decision_id':endpoint_decision(store,args.subnet_id,args.ip,args.mac,args.decision,args.actor,args.note)}
        if args.command=='csaf-source':configure(store,args.url,not args.disable);return {'configured':args.url}
        return sync_csaf(store)
    finally:store.close()
