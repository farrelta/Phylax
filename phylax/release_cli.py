"""Optional commands for imported evidence and public sources."""
from .core import Store
from .watcher import watch
from .asset_intelligence import add_subnet,endpoint_decision,revoke_decision
from .csaf import configure,sync_csaf

COMMANDS={'watch-zeek','monitor-subnet','device-decision','csaf-source','sync-csaf'}


def parsers(commands):
    p=commands.add_parser('watch-zeek',help='Ingest stable finalized Zeek logs, never start capture')
    p.add_argument('--directory',required=True);p.add_argument('--interval-seconds',type=int,default=30);p.add_argument('--once',action='store_true')
    p=commands.add_parser('monitor-subnet');p.add_argument('name');p.add_argument('cidr')
    p=commands.add_parser('device-decision');p.add_argument('--subnet-id');p.add_argument('--ip',default='');p.add_argument('--mac',default='')
    p.add_argument('--decision',choices=('approved','blocked'),default='approved');p.add_argument('--revoke');p.add_argument('--actor',required=True);p.add_argument('--note',required=True)
    p=commands.add_parser('csaf-source');p.add_argument('url');p.add_argument('--disable',action='store_true')
    commands.add_parser('sync-csaf',help='Refresh only configured official structured advisories')


def handle(args):
    if args.command=='watch-zeek':return watch(args.db,args.directory,args.interval_seconds,args.once)
    store=Store(args.db)
    try:
        if args.command=='monitor-subnet':return {'subnet_id':add_subnet(store,args.name,args.cidr)}
        if args.command=='device-decision':
            if args.revoke:revoke_decision(store,args.revoke,args.actor,args.note);return {'revoked':args.revoke}
            return {'decision_id':endpoint_decision(store,args.subnet_id,args.ip,args.mac,args.decision,args.actor,args.note)}
        if args.command=='csaf-source':configure(store,args.url,not args.disable);return {'configured':args.url}
        return sync_csaf(store)
    finally:store.close()
