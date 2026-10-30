"""Bounded, process-local operator jobs; every worker owns its SQLite connection."""
from __future__ import annotations
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable
from .core import Store, utc_now


class Jobs:
    def __init__(self, database: str):
        self.database=database
        self.executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='phylax-job')
        self.lock=threading.Lock()
        self.items: dict[str,dict[str,Any]]={}

    def submit(self, label: str, work: Callable[..., str]) -> str:
        with self.lock:
            for key,item in self.items.items():
                if item['label']==label and item['status'] in {'queued','running'}:return key
            if len(self.items)>=32:
                finished=[key for key,item in self.items.items() if item['status'] not in {'queued','running'}]
                if finished:self.items.pop(finished[0])
                else:raise ValueError('Job queue is full; wait for an existing job to finish')
            key=uuid.uuid4().hex
            self.items[key]={'job_id':key,'label':label,'status':'queued','message':'Waiting to start','created_at':utc_now(),'updated_at':utc_now()}
        def update(message):
            with self.lock:self.items[key].update(message=message[:2000],updated_at=utc_now())
        def run():
            store=None
            try:
                with self.lock:self.items[key]['status']='running'
                store=Store(self.database)
                message=work(store,update)
                update(message)
                with self.lock:self.items[key]['status']='complete'
            except Exception as exc:
                update(f'{type(exc).__name__}: {exc}')
                with self.lock:self.items[key]['status']='failed'
            finally:
                if store:store.close()
        self.executor.submit(run)
        return key

    def get(self, key: str) -> dict[str,Any] | None:
        with self.lock:return dict(self.items[key]) if key in self.items else None

    def close(self):
        self.executor.shutdown(wait=True,cancel_futures=True)
