"""Bounded, process-local operator jobs; every worker owns its SQLite connection."""
from __future__ import annotations
import threading
import time
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
        self.previews: dict[str, tuple[float, Any]] = {}

    def submit(self, label: str, work: Callable[..., str | dict], *, deduplicate=True) -> str:
        with self.lock:
            for key,item in self.items.items():
                if deduplicate and item['label']==label and item['status'] in {'queued','running'}:return key
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
                update(message if isinstance(message, str) else message['message'])
                with self.lock:
                    self.items[key]['status']='complete'
                    if isinstance(message, dict):self.items[key]['result']=message
            except Exception as exc:
                update(f'{type(exc).__name__}: {exc}')
                with self.lock:self.items[key]['status']='failed'
            finally:
                if store:store.close()
        self.executor.submit(run)
        return key

    def get(self, key: str) -> dict[str,Any] | None:
        with self.lock:return dict(self.items[key]) if key in self.items else None

    def prepare(self, draft: Any) -> str:
        with self.lock:
            now = time.monotonic()
            self.previews = {key: item for key, item in self.previews.items() if item[0] > now}
            if len(self.previews) >= 32:
                self.previews.pop(next(iter(self.previews)))
            key = uuid.uuid4().hex
            self.previews[key] = (now + 600, draft)
            return key

    def consume(self, key: str) -> Any:
        with self.lock:
            item = self.previews.pop(key, None)
        if item is None or item[0] <= time.monotonic():
            raise ValueError('This preview has expired. Start a new preview.')
        return item[1]

    def close(self):
        self.executor.shutdown(wait=True,cancel_futures=True)
