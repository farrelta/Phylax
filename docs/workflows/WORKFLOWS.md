# Phylax workflow atlas

These diagrams describe implemented operator paths, decisions and recovery behavior; they are not a claim that every arbitrary input or deployment scenario is covered.

[Open the offline interactive atlas](index.html). Generated SVG and DOT files are under `diagrams/`. No inventory, database or API secrets are read by this generator.

## Workflow index

1. [End-to-end system](#overview)
2. [Setup, access and configuration](#setup)
3. [Inventory and operational context](#inventory)
4. [Passive collection and ingestion](#passive)
5. [Identity, management and change review](#management)
6. [Approved active IT discovery](#discovery)
7. [Intelligence sync, resume and offline load](#intelligence)
8. [Software, applicability and reassessment](#correlation)
9. [Policy detection, urgency and Triage](#triage)
10. [Topology investigation](#topology)
11. [Guidance generation and public-data boundary](#guidance)
12. [Complete remediation lifecycle](#lifecycle)
13. [Reporting, offline operation and recovery](#operations)
14. [Complete controlled demonstration](#demo)

<a id="overview"></a>
## End-to-end system

How all operator workflows join local evidence, decisions and review.

```mermaid
flowchart TD
    n_start["Operator opens local Phylax"]
    n_setup["Configure sources, policies, subnets and optional collectors"]
    n_assets["Manual or CSV inventory; owner and process context"]
    n_passive["Imported Zeek logs, PCAP results or finalized-log watcher"]
    n_active["Individually permitted supporting IT discovery"]
    n_intel["Public feeds, selected CSAF, CVE refresh or offline fixture"]
    n_store["Local SQLite: identity, provenance, observations, health and history"]
    n_management["Management and identity reviews"]
    n_software["Software mapping and verification"]
    n_correlate["Conservative asset / component applicability"]
    n_detect["Configured passive policy rules"]
    n_priority["Separate severity, confidence and deterministic urgency"]
    n_triage["Unified Triage: evidence, context and acknowledgement"]
    n_topology["Passive topology investigation and original evidence"]
    n_plan["Operator requests advisory guidance and remediation plan"]
    n_human["Human reviews, approves and records external work"]
    n_reassess["Update inventory / evidence; reassess findings"]
    n_report["Export JSON, CSV, Markdown or inventory CSV"]
    n_offline["Stored inventory, evidence, replay and reporting remain local"]
    n_start --> n_setup
    n_setup --> n_assets
    n_setup --> n_passive
    n_setup --> n_active
    n_setup --> n_intel
    n_assets --> n_store
    n_passive --> n_store
    n_active --> |"Probe evidence stays distinct"| n_store
    n_intel --> n_store
    n_store --> n_management
    n_store --> n_software
    n_store --> n_correlate
    n_passive --> n_detect
    n_software --> n_correlate
    n_correlate --> n_priority
    n_detect --> n_priority
    n_management --> n_priority
    n_priority --> n_triage
    n_store --> n_topology
    n_topology --> |"Investigate evidence"| n_triage
    n_triage --> n_plan
    n_plan --> n_human
    n_human --> |"No equipment action by Phylax"| n_reassess
    n_reassess --> n_store
    n_triage --> n_report
    n_human --> n_report
    n_store --> n_offline
```

[Open SVG](diagrams/overview.svg) · [Editable Graphviz source](diagrams/overview.dot)

- Inventory verification, management approval, scan permission, acknowledgement and plan approval are independent decisions.
- All local asset, network, policy and process context stays on the host. Only eligible public advisory fields can go to an operator-requested hosted model.
- An observation or vulnerability match does not prove compromise. Missing observations or findings do not prove safety.

**Implementation:** [phylax/web.py](../../phylax/web.py), [phylax/release_web.py](../../phylax/release_web.py), [phylax/core.py](../../phylax/core.py), [phylax/topology.py](../../phylax/topology.py).

<a id="setup"></a>
## Setup, access and configuration

Local startup, optional tools, safe editing and separate execution processes.

```mermaid
flowchart TD
    n_launch["Start CLI or localhost dashboard with selected database"]
    n_upgrade["Open SQLite; apply additive versioned migrations as needed"]
    n_backup["Pre-upgrade backup for an existing database"]
    n_config["Review Settings: source health and collector status"]
    n_inputs["Configure public sources, policies and monitored subnets"]
    n_optional["Configure optional AI; install Zeek / Docker or Nmap only for relevant workflows"]
    n_processes["Run dashboard, watcher and scan worker separately as needed"]
    n_request["Dashboard request"]
    n_guard{"Valid Host; mutation also has matching Origin and form token?"}
    n_deny["Reject request; retain authoritative stored state"]
    n_form["Validate bounded input and current record revision"]
    n_valid{"Valid and current?"}
    n_retry["Show escaped draft and error; reload stale record or correct fields"]
    n_save["Save explicit change with provenance / audit where supported"]
    n_continue["Continue to data and operator workflows"]
    n_launch --> n_upgrade
    n_upgrade --> |"Existing DB upgrade"| n_backup
    n_backup --> n_config
    n_upgrade --> |"New / current schema"| n_config
    n_config --> n_inputs
    n_config --> n_optional
    n_inputs --> n_processes
    n_optional --> n_processes
    n_processes --> n_continue
    n_request --> n_guard
    n_guard --> |"No"| n_deny
    n_guard --> |"Yes"| n_form
    n_form --> n_valid
    n_valid --> |"No"| n_retry
    n_retry --> |"Correct and resubmit"| n_form
    n_valid --> |"Yes"| n_save
    n_save --> n_continue
```

[Open SVG](diagrams/setup.svg) · [Editable Graphviz source](diagrams/setup.dot)

- The dashboard remains localhost-only. Typed operator names provide attribution, not multi-user authentication.
- Viewing settings does not probe connectivity. No page visit automatically scans devices or requests hosted guidance.
- Each process owns its SQLite connection. Current web forms should be reloaded after server restart.

**Implementation:** [phylax/migrations.py](../../phylax/migrations.py), [phylax/web_security.py](../../phylax/web_security.py), [phylax/web.py](../../phylax/web.py), [phylax/operator_pages.py](../../phylax/operator_pages.py).

<a id="inventory"></a>
## Inventory and operational context

Import, validate, reconcile and maintain evidence without guessing identities.

```mermaid
flowchart TD
    n_input["Add / edit an asset or import CSV"]
    n_validate["Validate addresses, enums, IDs, timestamps and bounded fields"]
    n_good{"Row valid?"}
    n_bad["Report malformed row; operator corrects and retries"]
    n_identity{"Existing asset ID or reliable simple passive record reconciliation?"}
    n_update["Update existing record under import rules"]
    n_create["Create separate asset; keep incomplete fields unknown"]
    n_conflict["Ambiguous IP / MAC evidence remains reviewable; no hostname / MAC auto-merge"]
    n_context["Add owner, facility, lifecycle, tags and criticality rationale"]
    n_process["Confirm or unlink process support with operator and note"]
    n_verify["Operator verifies product/version evidence and confidence"]
    n_reassess["Automatically reevaluate relevant findings"]
    n_independent["Management approval and scan permission remain separate"]
    n_export["Search / paginate inventory; export CSV or reports"]
    n_input --> n_validate
    n_validate --> n_good
    n_good --> |"No"| n_bad
    n_bad --> |"Retry corrected rows"| n_input
    n_good --> |"Yes"| n_identity
    n_identity --> |"Reliable match"| n_update
    n_identity --> |"New / insufficient match"| n_create
    n_create --> |"Conflicting evidence"| n_conflict
    n_update --> n_verify
    n_create --> n_verify
    n_conflict --> n_verify
    n_verify --> n_reassess
    n_update --> n_context
    n_create --> n_context
    n_context --> n_process
    n_process --> n_export
    n_reassess --> n_independent
    n_independent --> n_export
```

[Open SVG](diagrams/inventory.svg) · [Editable Graphviz source](diagrams/inventory.dot)

- A manufacturer name or IP address alone never establishes an exact model or firmware version.
- Valid CSV rows can be imported while malformed rows are reported. Re-importing a stable asset ID updates that record.
- Observed metadata remains distinct from manual verification. Process links explain support; they do not silently change criticality.

**Implementation:** [phylax/core.py](../../phylax/core.py), [phylax/validation.py](../../phylax/validation.py), [phylax/asset_intelligence.py](../../phylax/asset_intelligence.py), [phylax/configuration_pages.py](../../phylax/configuration_pages.py).

<a id="passive"></a>
## Passive collection and ingestion

Three entry paths converge on validated, provenance-preserving local observations.

```mermaid
flowchart TD
    n_entry{"Choose passive input"}
    n_file["CLI or dashboard: finalized Zeek log"]
    n_pcap["Offline PCAP: local Zeek or installed network-disabled Docker image"]
    n_tools{"Tool / capture available and valid?"}
    n_toolerror["Show diagnostic; retain stored workflows"]
    n_logs["Zeek output logs with capture reference"]
    n_watch["Watcher polls finalized conn / modbus / dhcp / software logs"]
    n_stable{"Supported, bounded, non-symlink file stable across two polls?"}
    n_wait["Wait for stability or report skipped / unsupported file"]
    n_snapshot["Snapshot and hash stable content"]
    n_new{"Content differs from saved outcome?"}
    n_skip["Skip unchanged content; retain prior success or failure diagnostic"]
    n_parse["Use dedicated JSON Lines / TSV parser for each log kind"]
    n_valid{"Whole file remains valid and unchanged during import?"}
    n_rollback["Roll back this file; record failure; changed content may retry"]
    n_commit["Atomic deduplicated records; observed time distinct from ingestion time"]
    n_dispatch["Connections / Modbus → events and rules; DHCP → identity; software → components"]
    n_health["Update collector health, change history and evidence references"]
    n_entry --> |"Import log"| n_file
    n_entry --> |"Replay capture"| n_pcap
    n_entry --> |"Watch folder"| n_watch
    n_pcap --> n_tools
    n_tools --> |"No"| n_toolerror
    n_tools --> |"Yes"| n_logs
    n_logs --> n_parse
    n_file --> n_parse
    n_watch --> n_stable
    n_stable --> |"No"| n_wait
    n_wait --> |"Later poll"| n_watch
    n_stable --> |"Yes"| n_snapshot
    n_snapshot --> n_new
    n_new --> |"No"| n_skip
    n_new --> |"Yes"| n_parse
    n_parse --> n_valid
    n_valid --> |"No"| n_rollback
    n_rollback --> |"Correct / change file"| n_watch
    n_valid --> |"Yes"| n_commit
    n_commit --> n_dispatch
    n_dispatch --> n_health
```

[Open SVG](diagrams/passive.svg) · [Editable Graphviz source](diagrams/passive.dot)

- Zeek collection is externally managed. Phylax observes only captured or imported evidence; it does not discover every silent device.
- Current supported log kinds are conn, modbus, dhcp and software. A conn service label alone does not identify a Modbus write.
- Collector inactivity and device inactivity are different. Neither silence nor a missing protocol field proves removal or malicious traffic.

**Implementation:** [phylax/pcap.py](../../phylax/pcap.py), [phylax/monitoring.py](../../phylax/monitoring.py), [phylax/observations.py](../../phylax/observations.py), [phylax/watcher.py](../../phylax/watcher.py).

<a id="management"></a>
## Identity, management and change review

Approve, block or review endpoints only within explicit monitoring scope.

```mermaid
flowchart TD
    n_obs["Connection / DHCP / software / active-probe observation"]
    n_changes["Record first sighting, services, software and IP/MAC changes"]
    n_dhcp{"DHCP association evidence?"}
    n_assigned["Assigned/client-address evidence can support a MAC association"]
    n_requested["Requested address alone does not establish an assigned identity"]
    n_subnet{"Endpoint in a configured monitored subnet?"}
    n_unmonitored["Unmonitored; no unmanaged-device alert"]
    n_compare["Compare explicit IP / MAC / pair decisions and verified identity"]
    n_status{"Resulting management state"}
    n_approved["Approved; resolve related endpoint alert and retain history"]
    n_blocked["Explicitly blocked → Unauthorized"]
    n_unmanaged["No applicable approval → Unmanaged — needs review"]
    n_ambiguous["Missing MAC-bound proof or conflicting identity → Identity review"]
    n_alert["One deduplicated endpoint alert per monitored subnet / IP"]
    n_operator["Operator reviews original evidence and records approve / block / revoke"]
    n_repeat["Reevaluate stored evidence; reactivated endpoint alert resets acknowledgement"]
    n_separate["Approval / acknowledgement never grants scan permission"]
    n_obs --> n_changes
    n_changes --> n_dhcp
    n_dhcp --> |"Assigned evidence"| n_assigned
    n_dhcp --> |"Request only"| n_requested
    n_dhcp --> |"Other observation"| n_subnet
    n_assigned --> n_subnet
    n_requested --> n_subnet
    n_subnet --> |"No"| n_unmonitored
    n_subnet --> |"Yes"| n_compare
    n_compare --> n_status
    n_status --> |"Approved"| n_approved
    n_status --> |"Blocked"| n_blocked
    n_status --> |"Unapproved"| n_unmanaged
    n_status --> |"Insufficient / conflicting"| n_ambiguous
    n_blocked --> n_alert
    n_unmanaged --> n_alert
    n_ambiguous --> n_alert
    n_alert --> n_operator
    n_operator --> n_repeat
    n_repeat --> n_compare
    n_approved --> n_separate
```

[Open SVG](diagrams/management.svg) · [Editable Graphviz source](diagrams/management.dot)

- Existing inventory is not automatically management-approved. The system uses Unauthorized only for an applicable explicit block.
- Observation and ingestion timestamps stay separate. Neither hostname nor MAC similarity automatically merges inventory records.
- Inspect the Changes and Approvals tools under Assets; a resolution keeps management history.

**Implementation:** [phylax/asset_intelligence.py](../../phylax/asset_intelligence.py), [phylax/observations.py](../../phylax/observations.py), [phylax/review_pages.py](../../phylax/review_pages.py).

<a id="discovery"></a>
## Approved active IT discovery

A persistent queue and separate worker enforce per-target permission and bounded probing.

```mermaid
flowchart TD
    n_choose["Choose known supporting IT asset / management IP"]
    n_eligible{"Known eligible inventory and literal IPv4 target?"}
    n_reject["Reject OT control endpoints, unknown / observed-only identities and ineligible targets"]
    n_permission["Save separate scan permission, 1–32 TCP ports, optional standard HTTP(S)/SSH identification"]
    n_trigger{"Manual request or enabled schedule due?"}
    n_queue["Deduplicated persistent queued run bound to permission revision"]
    n_worker["Separate worker claims database-wide lease"]
    n_lease{"Another valid lease active?"}
    n_busy["Busy; do not overlap workers"]
    n_recover["Expired running work becomes Interrupted; no automatic replay"]
    n_check{"Revalidate permission, eligibility, revision and cancellation"}
    n_cancel["Cancelled: operator request or changed / revoked target"]
    n_nmap["Bounded unprivileged TCP connect scan; no DNS / extra discovery probes"]
    n_ok{"Probe succeeds within limits?"}
    n_failed["Failed: missing Nmap, timeout or execution error"]
    n_identify["Only selected open ports: optional HTTP(S) headers or SSH banner"]
    n_finalcheck{"Permission, revision and cancellation still valid before persistence?"}
    n_result["Store port states, tool version, provenance and identification errors"]
    n_observe["Active-probe evidence and service changes; versions remain unverified"]
    n_software["Known component evidence → software review and correlation"]
    n_schedule["Next schedule after interval; missed intervals skipped"]
    n_choose --> n_eligible
    n_eligible --> |"No"| n_reject
    n_eligible --> |"Yes"| n_permission
    n_permission --> n_trigger
    n_trigger --> |"Run / schedule"| n_queue
    n_queue --> n_worker
    n_worker --> n_lease
    n_lease --> |"Yes"| n_busy
    n_lease --> |"No / expired"| n_recover
    n_recover --> n_check
    n_check --> |"No longer valid"| n_cancel
    n_check --> |"Valid"| n_nmap
    n_nmap --> n_ok
    n_ok --> |"No"| n_failed
    n_ok --> |"Yes"| n_identify
    n_identify --> n_finalcheck
    n_finalcheck --> |"No"| n_cancel
    n_finalcheck --> |"Yes"| n_result
    n_result --> n_observe
    n_observe --> n_software
    n_software --> n_schedule
    n_failed --> n_schedule
    n_cancel --> n_schedule
    n_schedule --> n_trigger
    n_permission -.-> |"Changing permission invalidates queued work"| n_cancel
```

[Open SVG](diagrams/discovery.svg) · [Editable Graphviz source](diagrams/discovery.dot)

- At most one active run per database; 30-second scan timeout, 180-second execution bound, and constrained pacing. No CIDR expansion, scripts, UDP or OS fingerprinting.
- Identification is limited to SSH 22, HTTP 80/8080 and HTTPS 443/8443. Redirects/authentication are disabled; TLS failures remain explicit.
- No response is not proof a device is offline. Results never auto-expand permissions or scan OT endpoints.

**Implementation:** [phylax/discovery.py](../../phylax/discovery.py), [phylax/release_cli.py](../../phylax/release_cli.py), [phylax/configuration_pages.py](../../phylax/configuration_pages.py).

<a id="intelligence"></a>
## Intelligence sync, resume and offline load

Public collection remains independent of inventory; failures retain cached records.

```mermaid
flowchart TD
    n_trigger["Manual Sync public sources, CLI sync-feeds or selected source sync"]
    n_channels{"Independent source paths"}
    n_checkpoint{"NVD saved window / page checkpoint exists?"}
    n_resume["Resume saved fixed window at next page; checkpoint takes precedence"]
    n_backfill{"Explicit --backfill-days 1–120?"}
    n_wide["Start requested last-modified window"]
    n_incremental["Normal sync: last successful window with one-day overlap; first run about one day"]
    n_page["Fetch bounded NVD page; timeout / transient retry handling"]
    n_saved["Normalize and persist page + checkpoint"]
    n_more{"More pages?"}
    n_finish["Clear checkpoint; store last successful synchronization"]
    n_other["KEV full JSON; ICS RSS; configured CSAF URLs with conditional cache"]
    n_single["refresh-cve: one official CVE record"]
    n_offline["Load validated offline advisory fixture; retain declared provenance"]
    n_normalize["Deduplicate by source / identifier; preserve versions, refs and retrieved time"]
    n_fail["Source unavailable / malformed: retain cache and checkpoint; other sources continue"]
    n_interrupt["Operator cancels / process stops: saved pages and checkpoint persist"]
    n_reeval["Automatically reevaluate affected local findings"]
    n_health["Show source health, recent updates, last success and staleness after 24 hours"]
    n_trigger --> n_channels
    n_channels --> |"NVD"| n_checkpoint
    n_checkpoint --> |"Yes"| n_resume
    n_checkpoint --> |"No"| n_backfill
    n_backfill --> |"Yes"| n_wide
    n_backfill --> |"No"| n_incremental
    n_resume --> n_page
    n_wide --> n_page
    n_incremental --> n_page
    n_page --> |"Valid page"| n_saved
    n_saved --> n_more
    n_more --> |"Yes"| n_page
    n_more --> |"No"| n_finish
    n_page --> |"Source failure"| n_fail
    n_page --> |"Operator cancellation / process stop"| n_interrupt
    n_interrupt --> |"Next operator sync resumes"| n_trigger
    n_channels --> |"CISA sources"| n_other
    n_other --> |"Valid / updated"| n_normalize
    n_other --> |"Unavailable"| n_fail
    n_finish --> n_normalize
    n_single --> n_normalize
    n_offline --> n_normalize
    n_normalize --> n_reeval
    n_reeval --> n_health
    n_fail --> n_health
    n_health -.-> |"Operator retries when ready"| n_trigger
```

[Open SVG](diagrams/intelligence.svg) · [Editable Graphviz source](diagrams/intelligence.dot)

- No asset inventory is sent to feed services. A backfill is a wider last-modified window, not a complete historical download.
- KEV supplies exploitation-catalog metadata, not affected-version ranges or proof of attack. RSS-only advisories remain review references without invented version conditions.
- Configured CSAF is a narrow official-URL adapter. Unsupported status relationships / version expressions remain for review; advisories without CVEs are retained.

**Implementation:** [phylax/feeds.py](../../phylax/feeds.py), [phylax/adapters.py](../../phylax/adapters.py), [phylax/csaf.py](../../phylax/csaf.py), [phylax/core.py](../../phylax/core.py).

<a id="correlation"></a>
## Software, applicability and reassessment

Exact product evidence and supported version semantics drive findings; similarity is not proof.

```mermaid
flowchart TD
    n_identity["Hardware / firmware inventory plus active software components"]
    n_component["Software observation: raw name, version, source and time"]
    n_mapping{"Exact operator-managed product mapping exists?"}
    n_unmapped["Retain unmapped component for operator mapping / review"]
    n_mapped["Normalize vendor/product; retain raw values and verification state"]
    n_changed{"Different / competing observed version?"}
    n_reset["Invalidate prior component verification; record changes; conflicting active versions need review"]
    n_candidates["Exact normalized vendor/product candidates"]
    n_candidate{"Any candidate?"}
    n_none["No applicability finding for unrelated products; missing identity stays reviewable"]
    n_conditions{"Identity confidence sufficient; prerequisites supported and sources consistent?"}
    n_review["NEEDS_REVIEW"]
    n_version{"Installed version known?"}
    n_semantics{"Can source version conditions be compared safely?"}
    n_verify_match{"Verified high-confidence identity?"}
    n_verify_exclusion{"Verified high-confidence identity?"}
    n_potential["POTENTIAL_MATCH"]
    n_affected{"Source-defined version affected?"}
    n_confirmed["CONFIRMED_MATCH"]
    n_excluded["NO_MATCH_TO_THIS_ADVISORY"]
    n_aggregate["One stable asset/CVE finding with component evidence; confirmed → potential → review → exclusion"]
    n_priority["Vulnerability urgency rule v2; score only confirmed / potential"]
    n_alert["Create/update deduplicated exposure alert; preserve acknowledgement on update"]
    n_noalert["No active exposure alert for review / excluded; retain assessment evidence"]
    n_planchange["Changed supporting finding evidence / priority: archive plan and require more evidence"]
    n_recheck["Inventory, mapping, component review or source change retriggers assessment"]
    n_component --> n_mapping
    n_mapping --> |"No"| n_unmapped
    n_unmapped --> |"Operator adds mapping"| n_mapping
    n_mapping --> |"Yes"| n_mapped
    n_mapped --> n_changed
    n_changed --> |"Yes"| n_reset
    n_changed --> |"No"| n_identity
    n_reset --> n_identity
    n_identity --> n_candidates
    n_candidates --> n_candidate
    n_candidate --> |"No"| n_none
    n_candidate --> |"Yes"| n_conditions
    n_conditions --> |"No / conflict"| n_review
    n_conditions --> |"Yes"| n_version
    n_version --> |"No"| n_potential
    n_version --> |"Yes"| n_semantics
    n_semantics --> |"No"| n_review
    n_semantics --> |"Yes"| n_affected
    n_affected --> |"Affected"| n_verify_match
    n_affected --> |"Outside / explicitly fixed"| n_verify_exclusion
    n_verify_match --> |"Yes"| n_confirmed
    n_verify_match --> |"No"| n_potential
    n_verify_exclusion --> |"Yes"| n_excluded
    n_verify_exclusion --> |"No"| n_review
    n_review --> n_aggregate
    n_potential --> n_aggregate
    n_confirmed --> n_aggregate
    n_excluded --> n_aggregate
    n_aggregate --> n_priority
    n_priority --> |"Confirmed / potential"| n_alert
    n_priority --> |"Review / excluded"| n_noalert
    n_aggregate --> |"Supporting evidence changed"| n_planchange
    n_recheck --> n_identity
    n_none -.-> |"Operator supplies evidence"| n_recheck
```

[Open SVG](diagrams/correlation.svg) · [Editable Graphviz source](diagrams/correlation.dot)

- Actual assessment ordering also checks low confidence, unsupported version semantics and conflicting source conditions. Incomplete evidence cannot produce a fabricated confirmed match.
- Vulnerability v2: KEV +3; severity critical/high/medium +3/+2/+1; asset criticality +3/+2/+1; confirmed applicability +2; known DMZ +1. Urgency: critical ≥8, high 6–7, medium 3–5, low 0–2.
- Unknown severity adds no invented CVSS. Vendor fix and observed reachability are not inferred. Removing an obsolete product association archives its plan before removing the finding.

**Implementation:** [phylax/correlation.py](../../phylax/correlation.py), [phylax/observations.py](../../phylax/observations.py), [phylax/prioritization.py](../../phylax/prioritization.py), [phylax/core.py](../../phylax/core.py).

<a id="triage"></a>
## Policy detection, urgency and Triage

Passive rules, management reviews and exposures converge on human investigation.

```mermaid
flowchart TD
    n_event["Stored conn / Modbus event and current configured policy"]
    n_fields{"For each rule: required evidence and policy section available?"}
    n_diagnostic["Record cannot-evaluate diagnostic; do not fabricate a violation"]
    n_rules["Evaluate configured rules independently"]
    n_writer{"Unauthorized Modbus writer?"}
    n_peer{"Protected-destination communication violates allowlist?"}
    n_window{"Prohibited write outside approved maintenance window?"}
    n_violate["Create/update rule + event alert with policy evidence"]
    n_normal["No rule violation; observation stays available"]
    n_repolicy["New policy version / repeat import → reevaluate stored events"]
    n_cleared["Violation cleared → resolved history; exclude from active count"]
    n_networkscore["Network / management urgency v1 from severity, relevant criticality and protected destination"]
    n_exposure["Exposure alerts already carry vulnerability v2 urgency"]
    n_endpoint["Endpoint management alerts carry their evidence"]
    n_triage["Filter unified Triage by category, urgency, review state and text"]
    n_inspect["Inspect asset, original event, policy, score factors and process context"]
    n_ack["Acknowledge reviewed alert; retain filters and evidence"]
    n_follow["Supply identity evidence, change approved policy or review a plan"]
    n_event --> n_fields
    n_fields --> |"No"| n_diagnostic
    n_fields --> |"Yes"| n_rules
    n_rules --> n_writer
    n_rules --> n_peer
    n_rules --> n_window
    n_writer --> |"Yes"| n_violate
    n_peer --> |"Yes"| n_violate
    n_window --> |"Yes"| n_violate
    n_writer --> |"No"| n_normal
    n_peer --> |"No"| n_normal
    n_window --> |"No"| n_normal
    n_repolicy --> n_fields
    n_repolicy --> |"No longer violates"| n_cleared
    n_violate --> n_networkscore
    n_endpoint --> n_networkscore
    n_networkscore --> n_triage
    n_exposure --> n_triage
    n_triage --> n_inspect
    n_inspect --> n_ack
    n_inspect --> n_follow
    n_follow -.-> |"Policy review"| n_repolicy
```

[Open SVG](diagrams/triage.svg) · [Editable Graphviz source](diagrams/triage.dot)

- Normal reads, authorized writes and new peers are not automatically malicious. Missing fields and unconfigured policy sections remain explicit.
- Network v1 adds severity 0–3, relevant asset criticality 0–3 and protected destination +1. Urgency: critical ≥6, high 4–5, medium 2–3, low 0–1.
- Acknowledgement does not fix a vulnerability, approve a device, grant permission or execute remediation. Severity, applicability, urgency and confidence stay separate.

**Implementation:** [phylax/monitoring.py](../../phylax/monitoring.py), [phylax/triage.py](../../phylax/triage.py), [phylax/triage_views.py](../../phylax/triage_views.py), [phylax/prioritization.py](../../phylax/prioritization.py).

<a id="topology"></a>
## Topology investigation

Move from a bounded passive map to actual identity, communications and finding evidence.

```mermaid
flowchart TD
    n_open["Monitoring → Attack surface"]
    n_filters["Filter subnet, zone, criticality, management state, UTC window or endpoint"]
    n_surface["Join inventory with imported operational communication; retain unknown peers"]
    n_traffic{"Observed endpoints in filtered evidence?"}
    n_empty["Empty graph: import logs or widen filters; inventory stays available"]
    n_graph["Zone-grouped node diagram and directed observed connections"]
    n_controls["Find all known assets/peers, zoom or hide confirmed process links"]
    n_select["Select an observed node or inventory-only asset"]
    n_details["Read identity confidence, management, observed times and applicability counts"]
    n_event["Open original communication event / source record"]
    n_finding["Open focused vulnerability finding or inventory editor"]
    n_context["Open operator-confirmed process context"]
    n_all["Expand inventory-only list / full assets; inspect communication and support tables"]
    n_triage["Continue investigation in Triage or plan review"]
    n_open --> n_filters
    n_filters --> n_surface
    n_surface --> n_traffic
    n_traffic --> |"No"| n_empty
    n_traffic --> |"Yes"| n_graph
    n_graph --> n_controls
    n_controls -.-> |"Local view update"| n_graph
    n_graph --> n_select
    n_surface --> n_all
    n_all --> n_select
    n_select --> n_details
    n_details --> n_event
    n_details --> n_finding
    n_graph --> |"Confirmed process link"| n_context
    n_event --> n_triage
    n_finding --> n_triage
    n_context --> n_triage
    n_empty -.-> |"Widen view"| n_filters
```

[Open SVG](diagrams/topology.svg) · [Editable Graphviz source](diagrams/topology.dot)

- The diagram is bounded to 24 observed endpoints, 60 directed connections and 12 process nodes. Omission counts are visible; evidence remains in the tables.
- Colliding port/protocol labels are suppressed with an explicit count, not lost. Inspectable edge metadata and original event links remain.
- Find includes inventory-only and older peers; zero results leave no unrelated selection. Mobile details precede the natural-size scrollable graph.
- Observation existence is independent of the 1,000-group listing cap. Asset/focus filters precede that cap; event totals are time-scoped before asset filters.
- Zone grouping is inventory context, not a trust boundary. Dashed process support is an operator assertion, not an inferred network or attack path.

**Implementation:** [phylax/topology.py](../../phylax/topology.py), [phylax/surface.py](../../phylax/surface.py), [phylax/web.py](../../phylax/web.py), [phylax/release_web.py](../../phylax/release_web.py).

<a id="guidance"></a>
## Guidance generation and public-data boundary

Only an operator request may call a hosted model, and only with trusted public advisory fields.

```mermaid
flowchart TD
    n_request["Operator requests plan for a selected finding"]
    n_job["Bounded process-local background job with progress"]
    n_eligible{"Configured provider AND trusted public snapshot AND non-synthetic record?"}
    n_localreason["Explain disabled / synthetic / untrusted-source path; no hosted request"]
    n_public["Allowlist public CVE/advisory fields and supplied reference URLs"]
    n_remote["Hosted model receives public advisory fields only"]
    n_validate{"Response shape, citations, timeout / failure and command-syntax checks pass?"}
    n_good["AI-generated, unverified public-guidance supplement"]
    n_failure["Record explicit provider / validation failure"]
    n_current{"Finding unchanged during generation?"}
    n_retry["Reject stale result; operator reviews current finding and retries"]
    n_existing{"Fallback reason and previous hosted plan exists?"}
    n_keep["Keep previous hosted plan; record failure reason"]
    n_compose["Compose deterministic local plan; attach valid public AI supplement if available"]
    n_save["Store plan, actual model, timestamps, supplied / cited URLs and provenance"]
    n_archive["Regeneration archives old contents and clears prior review / verification"]
    n_review["Continue to human lifecycle; finding severity, applicability, urgency and acknowledgement unchanged"]
    n_private["Inventory, IPs, events, policies, local risk and process context stay local"]
    n_request --> n_job
    n_job --> n_eligible
    n_eligible --> |"No"| n_localreason
    n_eligible --> |"Yes"| n_public
    n_private --> |"Local evidence only"| n_compose
    n_public --> n_remote
    n_remote --> n_validate
    n_validate --> |"Yes"| n_good
    n_validate --> |"No"| n_failure
    n_good --> n_current
    n_localreason --> n_current
    n_failure --> n_current
    n_current --> |"No"| n_retry
    n_current --> |"Yes"| n_existing
    n_existing --> |"Yes"| n_keep
    n_existing --> |"No"| n_compose
    n_compose --> n_save
    n_save --> |"Replacing prior plan"| n_archive
    n_save --> |"New plan"| n_review
    n_archive --> n_review
    n_keep --> n_review
```

[Open SVG](diagrams/guidance.svg) · [Editable Graphviz source](diagrams/guidance.dot)

- Synthetic and imported untrusted records intentionally never call a hosted model. An official public refresh can establish eligible trusted source provenance.
- Fallback is a clearly labeled local template. Provider failure does not overwrite an existing hosted plan with fallback.
- Citation checks do not prove factual support or semantic correctness. AI cannot change findings, priority, permissions, acknowledgement or equipment.

**Implementation:** [phylax/remediation_service.py](../../phylax/remediation_service.py), [phylax/ai.py](../../phylax/ai.py), [phylax/remediation.py](../../phylax/remediation.py), [phylax/jobs.py](../../phylax/jobs.py).

<a id="lifecycle"></a>
## Complete remediation lifecycle

Every allowed manual status transition from the current transition map.

```mermaid
flowchart LR
    n_start["Generate new plan / regenerate existing plan"]
    n_recommended["Recommended"]
    n_underreview["Under Review"]
    n_approved["Approved"]
    n_implemented["Implemented"]
    n_rejected["Rejected"]
    n_deferred["Deferred"]
    n_needsmoreevidence["Needs More Evidence"]
    n_verified["Verified"]
    n_evidence["Supporting finding evidence / priority changes → archive snapshot and clear review"]
    n_external["Any infrastructure change is performed separately by authorized people"]
    n_start --> |"New or replacement plan"| n_recommended
    n_recommended --> n_underreview
    n_recommended --> n_rejected
    n_recommended --> n_deferred
    n_recommended --> n_needsmoreevidence
    n_underreview --> n_recommended
    n_underreview --> |"Reviewer required"| n_approved
    n_underreview --> n_rejected
    n_underreview --> n_deferred
    n_underreview --> n_needsmoreevidence
    n_approved --> n_underreview
    n_approved --> |"Record external implementation"| n_implemented
    n_approved --> n_rejected
    n_approved --> n_deferred
    n_implemented --> n_underreview
    n_implemented --> |"Verification evidence required"| n_verified
    n_implemented --> n_deferred
    n_rejected --> n_recommended
    n_rejected --> n_underreview
    n_deferred --> n_recommended
    n_deferred --> n_underreview
    n_needsmoreevidence --> n_recommended
    n_needsmoreevidence --> n_underreview
    n_verified --> n_underreview
    n_evidence --> |"Re-review required"| n_needsmoreevidence
    n_approved -.-> |"Guidance only"| n_external
```

[Open SVG](diagrams/lifecycle.svg) · [Editable Graphviz source](diagrams/lifecycle.dot)

- Recommended must enter Under Review before approval. Approval requires a reviewer; Verified requires explicit verification evidence.
- Regeneration archives prior contents and returns to Recommended. Supporting finding changes archive evidence and set Needs More Evidence; obsolete findings archive plans before removal.
- Plan states do not automatically mark a vulnerability fixed or modify equipment. Update real inventory/evidence and reassess separately. Invalid transitions are rejected with retained draft input.

**Implementation:** [phylax/remediation_lifecycle.py](../../phylax/remediation_lifecycle.py), [phylax/core.py](../../phylax/core.py), [phylax/correlation.py](../../phylax/correlation.py).

<a id="operations"></a>
## Reporting, offline operation and recovery

Understand what persists and how each interruption recovers.

```mermaid
flowchart TD
    n_review["Reviewed local findings, observations, decisions and plans"]
    n_export["Reports or CLI export"]
    n_formats["JSON / CSV / Markdown; inventory CSV separately"]
    n_content["Generation time, identity, provenance, applicability, missing evidence, priority, changes and context"]
    n_disconnect{"Internet unavailable"}
    n_local["Inventory, stored intelligence, findings, triage, topology, reports and offline PCAP analysis remain available"]
    n_unavailable["Live feed sync / hosted generation may fail; keep cache and prior hosted plan as applicable"]
    n_restart{"Process stops / restarts"}
    n_db["SQLite inventory, evidence, permissions, scan queue, plans, source cache and NVD checkpoints persist"]
    n_nvd["NVD resumes saved page/window on next sync"]
    n_watcher["Watcher rechecks stable content hashes and saved outcomes"]
    n_scanner["Expired running scan → Interrupted; queued work revalidated; no catch-up burst"]
    n_webjobs["Web job queue/progress is process-local; inspect stored result and resubmit if needed"]
    n_health["Inspect source staleness and collector/worker heartbeat separately"]
    n_upgrade["Before schema upgrade: backup existing DB; preserve IDs and verify copy"]
    n_audit["Review stored audit / plan archives; keep reports and local backups appropriately"]
    n_review --> n_export
    n_export --> n_formats
    n_formats --> n_content
    n_content --> n_audit
    n_disconnect --> |"Stored/local workflows"| n_local
    n_disconnect --> |"Needs external service"| n_unavailable
    n_restart --> n_db
    n_db --> n_nvd
    n_db --> n_watcher
    n_db --> n_scanner
    n_restart --> n_webjobs
    n_nvd --> n_health
    n_watcher --> n_health
    n_scanner --> n_health
    n_webjobs --> n_health
    n_upgrade --> n_db
    n_health --> n_audit
```

[Open SVG](diagrams/operations.svg) · [Editable Graphviz source](diagrams/operations.dot)

- Stale intelligence is visible after the stored 24-hour source-health threshold; losing internet does not immediately make a recent cache stale.
- Reports preserve uncertainty. Acknowledgement and plan verification are not proof of compromise or automatic remediation.
- No public raw-PCAP download endpoint exists. There is no immutable forensic audit system, multi-user identity provider or production military deployment claim.

**Implementation:** [phylax/reports.py](../../phylax/reports.py), [phylax/migrations.py](../../phylax/migrations.py), [phylax/jobs.py](../../phylax/jobs.py), [phylax/watcher.py](../../phylax/watcher.py), [phylax/discovery.py](../../phylax/discovery.py).

<a id="demo"></a>
## Complete controlled demonstration

A practical route through all feature groups in a fictional isolated support-site lab.

```mermaid
flowchart TD
    n_prepare["Prepare clearly labeled fictional lab and disposable database"]
    n_inventory["Import / validate inventory; include known and incomplete identities"]
    n_context["Add owners, criticality rationale and confirmed process support"]
    n_subnet["Configure monitored subnet, management decisions and passive policy"]
    n_passive["Replay benign / write captures or import all four Zeek log kinds"]
    n_changes["Review unmanaged peer, DHCP association and service/version changes"]
    n_scan["Explicitly permit isolated supporting IT host; queue / schedule bounded discovery"]
    n_software["Review unverified software; apply exact mapping; confirm evidence"]
    n_intel["Load deterministic advisory cases plus verified public snapshot for hosted demo"]
    n_matches["Review confirmed / potential / excluded / needs-review evidence"]
    n_rules["Demonstrate writer, unexpected communication and maintenance violations"]
    n_map["Inspect topology, original events, process context and missing visibility"]
    n_triage["Compare urgency factors and acknowledge reviewed alerts"]
    n_guidance["Request eligible public guidance; exercise local fallback / provider failure honestly"]
    n_plan["Review plan; record approved, externally implemented and verified test evidence"]
    n_report["Export reports and compare evidence/counts"]
    n_offline["Disconnect; reopen stored views, offline replay and saved guidance; show health times"]
    n_prepare --> n_inventory
    n_inventory --> n_context
    n_context --> n_subnet
    n_subnet --> n_passive
    n_passive --> n_changes
    n_changes --> n_scan
    n_scan --> n_software
    n_software --> n_intel
    n_intel --> n_matches
    n_matches --> n_rules
    n_rules --> n_map
    n_map --> n_triage
    n_triage --> n_guidance
    n_guidance --> n_plan
    n_plan --> n_report
    n_report --> n_offline
```

[Open SVG](diagrams/demo.svg) · [Editable Graphviz source](diagrams/demo.dot)

- This is a demonstration itinerary, not a requirement to approve all test endpoints or scan OT. The isolated demo starts with active scanning disabled.
- Synthetic advisory cases are useful for deterministic applicability but never sent to a hosted model. Use a separately refreshed eligible public advisory to demonstrate hosted guidance.
- Use saved guidance with its original provenance when offline. Neither provider availability nor a newly published CVE should determine whether the demonstration succeeds.

**Implementation:** [scripts/prepare_release_demo.py](../../scripts/prepare_release_demo.py), [docs/manual-testing.md](../../docs/manual-testing.md), [demo/README.md](../../demo/README.md).
