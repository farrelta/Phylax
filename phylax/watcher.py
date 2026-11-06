"""Poll finalized Zeek files; importing never supervises packet capture."""
from __future__ import annotations
import hashlib
import os
import tempfile
import time
from pathlib import Path
from .asset_intelligence import heartbeat
from .core import Store,utc_now
from .monitoring import ingest_file


class LogWatcher:
    def __init__(self,store,directory):
        self.store=store;self.directory=Path(directory).resolve(strict=True);self.seen={};self.processed={}
        if not self.directory.is_dir() or self.directory.name=='current':raise ValueError('Use a finalized-log directory, not Zeek current/')
        self.key='watch:'+str(self.directory)

    @staticmethod
    def signature(stat):return (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)

    def poll(self):
        imported=failed=0;messages=[]
        for index,path in enumerate(sorted(self.directory.iterdir())):
            if index>=1000:messages.append('Directory entry limit reached; archive older logs');break
            if path.is_symlink() or not path.is_file():continue
            kind=path.name.split('.')[0]
            if kind not in {'conn','modbus','dhcp','software'} or path.suffix not in {'.log','.jsonl','.tsv'}:continue
            signature=self.signature(path.stat())
            if signature[2]>500_000_000:messages.append(f'{path.name}: exceeds 500 MB');failed+=1;continue
            previous=self.seen.get(str(path));self.seen[str(path)]=signature
            if previous!=signature:continue
            old=self.store.connection.execute('SELECT * FROM ingestion_files WHERE path=?',(str(path),)).fetchone()
            if self.processed.get(str(path))==signature:
                if old and old['status']=='failed':messages.append(f'{path.name}: {old["message"]}')
                continue
            # Hash a stable, bounded snapshot even after restart; outcomes are content based.
            try:
                digest=hashlib.sha256()
                with tempfile.NamedTemporaryFile(prefix='phylax-finalized-',suffix='.log') as snapshot:
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                    with os.fdopen(fd,'rb') as source:
                        if self.signature(os.fstat(source.fileno()))!=signature:continue
                        size=0
                        while chunk:=source.read(1024*1024):
                            size+=len(chunk)
                            if size>500_000_000:raise ValueError('File grew beyond the size limit')
                            digest.update(chunk);snapshot.write(chunk)
                    snapshot.flush()
                    if self.signature(path.stat())!=signature:continue
                    sha=digest.hexdigest()
                    self.processed[str(path)]=signature
                    if old and old['sha256']==sha:continue
                    with self.store.atomic('watched_file'):
                        result=ingest_file(self.store,snapshot.name,kind=kind,source_file=f'log-sha256:{sha}:{path.name}',commit=False)
                        if self.signature(path.stat())!=signature:raise ValueError('File changed during import; snapshot rolled back')
                        self.store.connection.execute('INSERT OR REPLACE INTO ingestion_files VALUES(?,?,?,?,?)',(str(path),sha,'success',str(result),utc_now()))
                    self.store.connection.commit();imported+=1
            except (ValueError,OSError,UnicodeError) as exc:
                failed+=1;messages.append(f'{path.name}: {exc}')
                # Failed content is not retried until its hash changes.
                if 'sha' in locals():
                    self.store.connection.execute('INSERT OR REPLACE INTO ingestion_files VALUES(?,?,?,?,?)',(str(path),sha,'failed',str(exc)[:2000],utc_now()))
                    self.store.connection.commit()
            finally:
                if 'sha' in locals():del sha
        present={str(p) for p in self.directory.iterdir()}
        self.seen={k:v for k,v in self.seen.items() if k in present}
        self.processed={k:v for k,v in self.processed.items() if k in present}
        heartbeat(self.store,self.key,'watcher','degraded' if failed or messages else 'running','; '.join(messages) or f'{imported} files imported this poll',success=imported>0)
        return {'imported':imported,'failed':failed,'messages':messages}


def watch(database,directory,interval=30,once=False):
    if not 1<=interval<=60:raise ValueError('Polling interval must be 1–60 seconds (health heartbeat expires after 180 seconds)')
    store=Store(database);watcher=LogWatcher(store,directory)
    try:
        while True:
            result=watcher.poll()
            if once:
                time.sleep(interval);return watcher.poll()
            time.sleep(interval)
    except KeyboardInterrupt:return {'stopped':True}
    finally:
        heartbeat(store,watcher.key,'watcher','stopped');store.close()
