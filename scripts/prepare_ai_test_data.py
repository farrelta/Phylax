"""Prepare an isolated, clearly labeled AI workflow test database.

The vulnerability record is copied from the user's local real NVD cache. The
single asset is a documentation-only lab record, never a discovered device.
No network requests are made by this script.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phylax.core import Store  # noqa: E402


DEFAULT_CVE = "CVE-2026-0322"


def prepare(source_path: Path, output_path: Path, cve_id: str = DEFAULT_CVE) -> dict[str, object]:
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing test database: {output_path}")

    source = Store(source_path)
    try:
        row = source.connection.execute(
            "SELECT * FROM vulnerabilities WHERE cve_id=?", (cve_id.upper(),)
        ).fetchone()
        if row is None:
            raise ValueError(f"{cve_id} is not in {source_path}; sync or import public intelligence first")
        record = dict(row)
    finally:
        source.close()

    if record["synthetic"] or not record["source"].startswith("NVD"):
        raise ValueError(f"{cve_id} must be a real NVD record")
    products = json.loads(record["affected_products"])
    product = next(
        (p for p in products if p.get("vendor") == "paloaltonetworks" and p.get("product") == "pan-os"),
        None,
    )
    if not product or not any(
        r.get("start_including") == "12.2.0" and r.get("end_excluding") == "12.2.4"
        for r in product.get("version_ranges", [])
    ):
        raise ValueError(f"{cve_id} no longer has the expected source-defined PAN-OS test range")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    test = Store(output_path)
    try:
        test.import_csv(io.StringIO(
            "asset_id,ip_address,hostname,asset_type,vendor,product,version,zone,criticality,identification_source,identity_confidence,notes,verified\n"
            'ai-test-pan-os,192.0.2.50,phylax-ai-test,network device,paloaltonetworks,pan-os,12.2.3,DMZ,medium,manual,high,"TEST ONLY: simulated lab asset; not a real device or production inventory entry",true\n'
        ))
        test.ingest_normalized(
            [
                {
                    "cve_id": record["cve_id"],
                    "summary": record["summary"],
                    "published": record["published"],
                    "modified": record["modified"],
                    "severity": record["severity"],
                    "cvss": record["cvss"],
                    "source": record["source"],
                    "source_url": record["source_url"],
                    "kev": bool(record["kev"]),
                    "exploitation_metadata": record["exploitation_metadata"],
                    "mitigation": record["mitigation"],
                    "affected_products": products,
                    "references": json.loads(record["references_json"]),
                    "synthetic": False,
                }
            ]
        )
        counts = test.correlate()
        finding = test.connection.execute(
            "SELECT finding_id,status FROM findings WHERE cve_id=?", (cve_id.upper(),)
        ).fetchone()
        if not finding or finding["status"] != "CONFIRMED_MATCH":
            raise RuntimeError(f"Test finding did not reach CONFIRMED_MATCH: {dict(finding) if finding else counts}")
        test.connection.commit()
        return {"cve_id": cve_id.upper(), "status": finding["status"], "finding_id": finding["finding_id"], "counts": counts}
    finally:
        test.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-db", type=Path, default=ROOT / "data/phylax.db")
    parser.add_argument("--output-db", type=Path, default=ROOT / "data/phylax-ai-test.db")
    parser.add_argument("--cve", default=DEFAULT_CVE)
    args = parser.parse_args()
    result = prepare(args.source_db, args.output_db, args.cve)
    print(f"Created isolated AI test database: {args.output_db}")
    print(f"Real NVD record: {result['cve_id']} · {result['status']}")
    print("Asset: simulated lab-only PAN-OS 12.2.3 at documentation IP 192.0.2.50")
    print("No packets were sent and no model was called.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
