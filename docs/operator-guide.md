# Operator guide

[Documentation index](README.md)

## Dashboard navigation

| Page | Workflow |
|---|---|
| Overview | Review summary counts and open an exposure finding |
| Assets | Inventory, approvals, IT discovery, software, changes, operational context |
| Monitoring | Imported events and passive attack surface |
| Intelligence | Separate CVE and CISA ICS advisory pages with search and pagination |
| Triage | Investigate and acknowledge alerts; review remediation plans |
| Reports | Export evidence and assessment results |
| Settings | Source/collector health, network policy, glossary, advanced reassessment |

Counts derive from stored records. Source freshness, synthetic dataset labels, and missing evidence affect how those numbers should be interpreted.

## 1. Build and verify inventory

Import CSV or add/edit assets under Assets. Only `ip_address` is required. Supported columns:

```text
asset_id,ip_address,mac_address,hostname,asset_type,vendor,product,version,operating_system,zone,criticality,identification_source,identity_confidence,last_seen,notes,verified
```

```bash
python3 -m phylax --db data/phylax.db import-assets /path/to/assets.csv
```

Allowed asset types: `PLC`, `RTU`, `HMI`, `engineering workstation`, `server`, `network device`, `gateway`, `unknown`. Zones: `IT`, `OT`, `DMZ`, `unknown`. Criticality: `low`, `medium`, `high`, `critical`. Confidence: `low`, `medium`, `high`. Supplied timestamps need an explicit timezone and are normalized to UTC.

Valid CSV rows are retained; malformed rows are reported. Unknown fields of device identity can remain empty. Never identify a model or version from its IP alone. CSV exports neutralize spreadsheet formula prefixes, so unsafe leading characters may gain an apostrophe.

Manually verified identity is separate from observed metadata. Competing identities are not silently merged by hostname or MAC. Review conflicts and software changes before confirming applicability. Imports reassess findings automatically; manual recovery is available under Settings or `correlate`.

## 2. Record management decisions and context

Configure monitored subnets before expecting unmanaged-endpoint alerts. Existing inventory does not automatically count as approved.

- **Unmanaged—needs review:** observed endpoint lacks sufficient approval evidence.
- **Unauthorized:** an operator explicitly blocked the identity.
- **Identity needs review:** evidence cannot reliably satisfy an approval, for example missing MAC for a MAC-bound decision.

Approve/block/revoke with an actor and reason. Approval resolves the relevant management alert while retaining history; it does not resolve an unrelated write-policy violation. Acknowledgement does not grant approval.

Use Operational Context for owner, facility/location, lifecycle, tags, criticality rationale, and confirmed process support. Process relationships explain operational context; they do not automatically change criticality or prove disruption. Stale edit submissions are rejected rather than silently overwriting newer context.

**Inventory verification, management approval, and scan permission are independent.**

## 3. Review software and changes

Software evidence is separate from controller firmware and inventory identity. Map raw names to exact vendor/product identifiers, review the version/source, and verify or retire components. Apache mappings are included; fuzzy similarity is not proof of identity.

A new observed version invalidates prior verification and creates reviewable history. Multiple active versions can require review of installation scope. Component evidence contributes to one asset/CVE finding, with explicit source conflicts and missing data.

The Changes view records observed services, software, and IP/MAC associations. Observation time is distinct from ingestion time. Collector inactivity is separate from asset inactivity.

## 4. Investigate passive attack surface

Find searches all known inventory assets and stored communication peers within the asset filters, including inventory-only assets and older peers outside the relationship display cap. It selects details; it does not narrow the communication table. A zero-result search does not select an unrelated device.

The graph contains observed endpoints only, grouped by inventory zone. Solid directed connections represent imported communication; dashed process links represent operator-confirmed support. Groups do not establish trust boundaries, firewall permission, or live reachability.

- Select an endpoint for identity, confidence, UTC observation times, applicability, and evidence.
- Narrow screens show selected details before the scrollable graph. Reset zoom restores natural label size.
- Use **Show this endpoint’s communication** to focus the relationship listing.
- Each communication row opens its own original event evidence and returns to the current view.
- Inventory-only means no imported communication across all stored times. Previously observed endpoints outside the time window remain distinct.

Limits are explicit: 1,000 most recent eligible relationship groups, 24 diagram endpoints, 60 diagram connections, 12 process nodes, and 100 asset rows per page. Find initially lists up to 20 matches; refine it for more. Asset/focus filters apply before the relationship cap. Event totals describe the time window **before** asset/focus filters. Diagram omissions and suppressed overlapping labels are counted.

## 5. Triage and review guidance

Expand **Inspect alert** to review the observed facts, configured policy, source event, local context, and urgency factors. Keep severity, applicability, confidence, urgency, and acknowledgement distinct. Filtering and acknowledgement preserve the current review scope.

Acknowledge only after review. It does not prove resolution, change applicability, approve a device, or permit scanning. Policy reevaluation can resolve a violation while retaining historical evidence.

For a vulnerability finding, inspect affected-product/version evidence and missing prerequisites. Optional guidance generation uses public advisory data. Review the saved plan before recording approval, external implementation, and verification. Regeneration archives the old plan and clears its review state; changed evidence can also invalidate prior review. Phylax never executes a plan.

## 6. Export reports

```bash
python3 -m phylax --db data/phylax.db export-report --format json --output data/report.json
python3 -m phylax --db data/phylax.db export-report --format csv --output data/report.csv
python3 -m phylax --db data/phylax.db export-report --format markdown --output data/report.md
```

Reports include generation time, identity/confidence, applicability evidence, severity, priority factors, sources, missing data, management/software/process context, detection evidence, and limitations. JSON preserves structured evidence; CSV neutralizes formula prefixes and includes metadata even for empty reports. Review exports before sharing; they contain local network and asset information.
