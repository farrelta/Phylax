"""Bounded offline Zeek orchestration. No live capture or protocol decoder."""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable
from .core import Store, utc_now
from .monitoring import ingest_file

MAGIC={b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'}


def analyze_pcap(store: Store, path: str | Path, *, policy: dict[str,Any] | None = None,
                 docker_image: str | None = None, runner: Callable[...,Any] = subprocess.run) -> dict[str,Any]:
    path=Path(path)
    if not path.is_file() or not 24 <= path.stat().st_size <= 500_000_000:
        raise ValueError('PCAP must be a regular file between 24 bytes and 500 MB')
    with path.open('rb') as capture:
        if capture.read(4) not in MAGIC:raise ValueError('Unrecognized PCAP/PCAPNG header')
    executable=shutil.which('docker' if docker_image else 'zeek',path='/opt/zeek/bin:/usr/local/bin:/usr/bin')
    if not executable:
        raise RuntimeError('Docker/Zeek executable is not installed. Install Zeek or use --docker-image with a locally installed, pinned Zeek image; existing Zeek logs can be imported with analyze-zeek.')
    if docker_image and (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_./:@-]{1,250}',docker_image) or (':' not in docker_image and '@sha256:' not in docker_image)):
        raise ValueError('Use an explicit pinned Docker image tag or digest, without command options')
    with tempfile.TemporaryDirectory(prefix='phylax-pcap-') as temp:
        work=Path(temp);input_path=work/'input.pcap';output=work/'logs';output.mkdir()
        digest=hashlib.sha256()
        with path.open('rb') as src,input_path.open('wb') as dest:
            for block in iter(lambda:src.read(1024*1024),b''):
                digest.update(block);dest.write(block)
        prior=store.connection.execute('SELECT result_json FROM pcap_runs WHERE capture_sha256=?',(digest.hexdigest(),)).fetchone()
        if prior:
            if policy is not None:
                from .monitoring import reevaluate_events
                reevaluate_events(store,policy)
            return json.loads(prior[0]) | {'already_analyzed':True}
        if docker_image:
            name='phylax-pcap-'+work.name.removeprefix('phylax-pcap-')
            command=[executable,'run','--rm','--pull=never','--name',name,'--network=none','--cap-drop=ALL','--security-opt=no-new-privileges',
                '--read-only','--pids-limit=64','--memory=512m','--cpus=1','--user',f'{os.getuid()}:{os.getgid()}',
                '--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--mount',f'type=bind,src={input_path},dst=/input.pcap,readonly',
                '--mount',f'type=bind,src={output},dst=/output','--workdir','/output','--entrypoint','zeek',docker_image,
                '-Cr','/input.pcap','LogAscii::use_json=T']
        else:command=[executable,'-Cr',str(input_path),'LogAscii::use_json=T']
        with (work/'diagnostics.txt').open('w+b') as log:
            try:
                result=runner(command,cwd=str(output),stdout=log,stderr=log,timeout=60,check=False,
                              env={'PATH':'/opt/zeek/bin:/usr/local/bin:/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
            except subprocess.TimeoutExpired as exc:
                if docker_image:
                    # Killing the Docker client alone does not stop its container.
                    runner([executable,'rm','-f',name],stdout=log,stderr=log,timeout=10,check=False)
                raise RuntimeError('Offline Zeek analysis exceeded 60 seconds') from exc
            log.seek(0);diagnostics=log.read(4096).decode('utf-8','replace')
        if result.returncode:
            raise RuntimeError('Zeek analysis failed: '+diagnostics)
        results=[]
        with store.atomic('pcap_import'):
            # ingest_file joins the enclosing savepoint rather than committing it.
            for log_name,kind in (('conn.log','conn'),('modbus.log','modbus')):
                file=output/log_name
                if file.exists():
                    if file.is_symlink():raise ValueError('Zeek output must not contain symbolic links')
                    results.append(ingest_file(store,file,kind=kind,policy=policy,source_file=f'pcap-sha256:{digest.hexdigest()}:{path.name[:120]}:{log_name}',commit=False))
            if not results:raise RuntimeError('Zeek produced no supported conn.log/modbus.log; verify capture content and installed analyzers')
            store.audit('pcap_analyzed',digest.hexdigest(),{'filename':path.name[:255],'docker_image':docker_image,'logs':len(results)})
        result={'capture_sha256':digest.hexdigest(),'docker_image':docker_image,'logs':results,
                'coverage':'Zeek connection and available Modbus logs only; ICSNPP extension installation is optional and not verified by this runner.'}
        store.connection.execute('INSERT INTO pcap_runs VALUES(?,?,?,?)',(digest.hexdigest(),docker_image or executable,json.dumps(result),utc_now()))
        store.connection.commit()
        return result
