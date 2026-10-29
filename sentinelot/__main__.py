from __future__ import annotations

import argparse
from pathlib import Path

from .core import Store
from .web import serve


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelot", description="Local-first passive IT/OT vulnerability visibility")
    parser.add_argument("--db", default="data/sentinelot.db", help="SQLite database path")
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
    finally:
        store.close()


if __name__ == "__main__":
    main()
