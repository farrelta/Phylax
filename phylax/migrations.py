"""Additive release migrations. Existing positional schemas stay intact."""
import sqlite3
import os
import uuid
from pathlib import Path

VERSION = 'asset_intelligence_v1'
DDL = '''
CREATE TABLE IF NOT EXISTS asset_context(asset_id TEXT PRIMARY KEY REFERENCES assets ON DELETE CASCADE,
 owner TEXT NOT NULL DEFAULT '',site TEXT DEFAULT '',location TEXT DEFAULT '',lifecycle TEXT DEFAULT 'unknown',
 tags_json TEXT DEFAULT '[]',criticality_rationale TEXT DEFAULT '',updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS processes(process_id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS process_links(asset_id TEXT REFERENCES assets ON DELETE CASCADE,
 process_id TEXT REFERENCES processes ON DELETE CASCADE,actor TEXT NOT NULL,note TEXT NOT NULL,
 PRIMARY KEY(asset_id,process_id));
CREATE TABLE IF NOT EXISTS monitored_subnets(subnet_id TEXT PRIMARY KEY,name TEXT NOT NULL,cidr TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS endpoint_decisions(decision_id TEXT PRIMARY KEY,subnet_id TEXT REFERENCES monitored_subnets,
 ip TEXT NOT NULL DEFAULT '',mac TEXT NOT NULL DEFAULT '',decision TEXT NOT NULL,actor TEXT NOT NULL,note TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(observation_id TEXT PRIMARY KEY,kind TEXT NOT NULL,ip TEXT NOT NULL,
 mac TEXT NOT NULL DEFAULT '',observed_at TEXT NOT NULL,ingested_at TEXT NOT NULL,source_file TEXT NOT NULL,
 event_ref TEXT NOT NULL,raw_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS observation_ip_time ON observations(ip,observed_at);
CREATE TABLE IF NOT EXISTS asset_changes(change_id TEXT PRIMARY KEY,ip TEXT NOT NULL,kind TEXT NOT NULL,
 observed_at TEXT NOT NULL,ingested_at TEXT NOT NULL,evidence_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS endpoint_alerts(alert_id TEXT PRIMARY KEY,subnet_id TEXT NOT NULL,ip TEXT NOT NULL,
 state TEXT NOT NULL,status TEXT NOT NULL,severity TEXT NOT NULL,evidence_json TEXT NOT NULL,
 acknowledged INTEGER NOT NULL DEFAULT 0,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,
 UNIQUE(subnet_id,ip));
CREATE TABLE IF NOT EXISTS software_mappings(raw_name TEXT PRIMARY KEY,vendor TEXT NOT NULL,product TEXT NOT NULL,
 actor TEXT NOT NULL,note TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS software_components(component_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets ON DELETE CASCADE,
 raw_name TEXT NOT NULL,version TEXT NOT NULL,vendor TEXT NOT NULL,product TEXT NOT NULL,
 verified INTEGER NOT NULL DEFAULT 0,active INTEGER NOT NULL DEFAULT 1,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,
 source_file TEXT NOT NULL,event_ref TEXT NOT NULL,raw_json TEXT NOT NULL,reviewer TEXT NOT NULL DEFAULT '',
 UNIQUE(asset_id,raw_name,version));
CREATE TABLE IF NOT EXISTS component_assessments(finding_id TEXT REFERENCES findings ON DELETE CASCADE,
 component_id TEXT NOT NULL,status TEXT NOT NULL,evidence_json TEXT NOT NULL,PRIMARY KEY(finding_id,component_id));
CREATE TABLE IF NOT EXISTS ingestion_files(path TEXT PRIMARY KEY,sha256 TEXT NOT NULL,status TEXT NOT NULL,
 message TEXT NOT NULL,processed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS collectors(collector_id TEXT PRIMARY KEY,kind TEXT NOT NULL,status TEXT NOT NULL,
 heartbeat TEXT NOT NULL,last_success TEXT NOT NULL DEFAULT '',message TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS scan_targets(target_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets,
 ip TEXT NOT NULL,ports_json TEXT NOT NULL,identification_json TEXT NOT NULL,permission INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 1,actor TEXT NOT NULL,note TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_schedules(target_id TEXT PRIMARY KEY REFERENCES scan_targets,
 interval_seconds INTEGER NOT NULL,next_due REAL NOT NULL,enabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS scan_runs(run_id TEXT PRIMARY KEY,target_id TEXT NOT NULL REFERENCES scan_targets,
 revision INTEGER NOT NULL,status TEXT NOT NULL,requested_at TEXT NOT NULL,started_at TEXT DEFAULT '',
 finished_at TEXT DEFAULT '',cancel_requested INTEGER NOT NULL DEFAULT 0,result_json TEXT DEFAULT '{}',error TEXT DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_scan_per_target ON scan_runs(target_id) WHERE status IN ('queued','running');
CREATE TABLE IF NOT EXISTS worker_lease(name TEXT PRIMARY KEY,owner TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS csaf_documents(url TEXT PRIMARY KEY,etag TEXT DEFAULT '',body_json TEXT DEFAULT '',
 retrieved_at TEXT DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1);
'''


def migrate(store):
    if store.connection.execute('SELECT 1 FROM schema_meta WHERE key=?',(VERSION,)).fetchone():
        return
    if store.path != ':memory:':
        backup_path=Path(store.path+'.pre-asset-intelligence.sqlite')
        if not backup_path.exists():
            temporary=Path(str(backup_path)+'.'+uuid.uuid4().hex+'.tmp')
            backup=sqlite3.connect(temporary)
            try:
                store.connection.backup(backup);backup.close();os.chmod(temporary,0o600)
                try:os.link(temporary,backup_path)
                except FileExistsError:pass # another successful opener won the backup race
            finally:
                backup.close()
                temporary.unlink(missing_ok=True)
    # Statements execute in one transaction; no executescript implicit commits.
    with store.atomic('asset_intelligence_upgrade'):
        for statement in DDL.split(';'):
            if statement.strip():store.connection.execute(statement)
        store.connection.execute("UPDATE assets SET zone='unknown' WHERE UPPER(zone)='UNKNOWN'")
        store.connection.execute("INSERT OR IGNORE INTO software_mappings VALUES('Apache','apache','http_server','system','Exact Zeek Apache name mapping')")
        store.connection.execute("INSERT OR IGNORE INTO software_mappings VALUES('Apache httpd','apache','http_server','system','Exact Nmap Apache name mapping')")
        store.connection.execute('INSERT OR IGNORE INTO schema_meta VALUES(?,?)',(VERSION,'1'))
    store.connection.commit()
