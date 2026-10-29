from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .core import Store
from .feeds import sync_store
from .monitoring import ingest_file, validate_policy
from .web import serve


def main() -> None:
    parser = argparse.ArgumentParser(prog="phylax", description="Local-first passive IT/OT vulnerability visibility")
    parser.add_argument("--db", default="data/phylax.db", help="SQLite database path")
    commands = parser.add_subparsers(dest="command", required=True)
    web = commands.add_parser("serve", help="Start the loopback-only dashboard")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    imp = commands.add_parser("import-assets", help="Import asset inventory CSV")
    imp.add_argument("file")
    vuln = commands.add_parser("load-fixture", help="Load a local JSON vulnerability fixture")
    vuln.add_argument("file")
    commands.add_parser("correlate", help="Re-evaluate inventory against stored intelligence")
    exp = commands.add_parser("export-report", help="Export JSON or CSV findings")
    exp.add_argument("--format", choices=("json", "csv"), default="json")
    exp.add_argument("--output", required=True)
    sync = commands.add_parser("sync-feeds", help="Incrementally synchronize NVD, CISA KEV, and ICS advisory sources")
    sync.add_argument("--backfill-days", type=int, metavar="DAYS", help="Explicitly query a wider NVD last-modified window (1-120 days); normal syncs remain incremental")
    network = commands.add_parser("analyze-zeek", help="Import a Zeek conn.log or Modbus log passively")
    network.add_argument("file")
    network.add_argument("--kind", choices=("conn", "modbus"))
    network.add_argument("--policy", help="JSON passive communication policy")
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.db, args.host, args.port)
        return
    store = Store(args.db)
    try:
        if args.command == "import-assets":
            result = store.import_csv(args.file)
            print(f"Imported {result['imported']} rows; {len(result['errors'])} errors")
            for error in result["errors"]:
                print(f"Row {error['row']}: {error['error']}")
        elif args.command == "load-fixture":
            print(store.ingest_fixture(args.file))
        elif args.command == "correlate":
            print(store.correlate())
        elif args.command == "export-report":
            Path(args.output).write_text(store.report(args.format), encoding="utf-8")
            print(f"Wrote {args.output}")
        elif args.command == "sync-feeds":
            def report_progress(source: str, stage: str, message: str) -> None:
                timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                print(f"[{timestamp}] [{source}] {stage.upper()}: {message}", file=sys.stderr, flush=True)

            if args.backfill_days is not None and not 1 <= args.backfill_days <= 120:
                parser.error("--backfill-days must be between 1 and 120")
            report_progress("Phylax", "start", "Syncing NVD incremental changes (or a requested backfill window), the full CISA KEV catalog, and CISA ICS advisory RSS. An interrupted NVD window resumes from its saved page; feed failures are independent and cached records are retained.")
            results = sync_store(store, progress=report_progress, backfill_days=args.backfill_days)
            report_progress("Phylax", "progress", "Re-evaluating local assets against stored vulnerability intelligence.")
            findings = store.correlate()
            succeeded = sum(1 for result in results.values() if result["ok"])
            report_progress("Phylax", "done", f"Feed sync complete: {succeeded}/{len(results)} sources healthy; correlation updated {sum(findings.values())} findings.")
            for source, result in results.items():
                print(f"{source}: {'ok' if result['ok'] else 'unavailable'} {result.get('records', result.get('error', ''))}")
        elif args.command == "analyze-zeek":
            import json
            policy = validate_policy(json.loads(Path(args.policy).read_text(encoding="utf-8"))) if args.policy else {}
            print(ingest_file(store, args.file, kind=args.kind, policy=policy))
    finally:
        store.close()


if __name__ == "__main__":
    main()
