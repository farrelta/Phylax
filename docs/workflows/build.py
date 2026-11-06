"""Build the offline workflow atlas from reviewed application workflows.

Run with Python 3 and Graphviz installed. Viewing the generated files needs neither.
This generator reads the remediation transition map but never opens an asset DB.
"""
from pathlib import Path
import html
import json
import re
import shutil
import subprocess
import sys
import textwrap

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phylax.remediation_lifecycle import TRANSITIONS

OUT=Path(__file__).resolve().parent
DIAGRAMS=OUT/'diagrams'
PALETTE={'action':('#14202f','#7197bd'),'decision':('#292419','#b39461'),
         'data':('#17202a','#738397'),'result':('#15271f','#7eaa90'),
         'review':('#292217','#c4a071'),'stop':('#2b1c23','#bd8591')}
WORKFLOWS=[]


def flow(key,title,description,nodes,edges,notes,sources,*,direction='TB'):
    WORKFLOWS.append(dict(key=key,title=title,description=description,nodes=nodes,edges=edges,
                          notes=notes,sources=sources,direction=direction))

# Node types describe the workflow role, not a vulnerability severity.
flow('overview','End-to-end system','How all operator workflows join local evidence, decisions and review.',[
('start','Operator opens local Phylax','action'),('setup','Configure sources, policies, subnets and optional collectors','action'),
('assets','Manual or CSV inventory; owner and process context','data'),('passive','Imported Zeek logs, PCAP results or finalized-log watcher','data'),
('active','Individually permitted supporting IT discovery','action'),('intel','Public feeds, selected CSAF, CVE refresh or offline fixture','data'),
('store','Local SQLite: identity, provenance, observations, health and history','data'),('management','Management and identity reviews','review'),
('software','Software mapping and verification','review'),('correlate','Conservative asset / component applicability','action'),
('detect','Configured passive policy rules','action'),('priority','Separate severity, confidence and deterministic urgency','result'),
('triage','Unified Triage: evidence, context and acknowledgement','review'),('topology','Passive topology investigation and original evidence','review'),
('plan','Operator requests advisory guidance and remediation plan','review'),('human','Human reviews, approves and records external work','review'),
('reassess','Update inventory / evidence; reassess findings','action'),('report','Export JSON, CSV, Markdown or inventory CSV','result'),
('offline','Stored inventory, evidence, replay and reporting remain local','data')],[
('start','setup'),('setup','assets'),('setup','passive'),('setup','active'),('setup','intel'),
('assets','store'),('passive','store'),('active','store','Probe evidence stays distinct'),('intel','store'),
('store','management'),('store','software'),('store','correlate'),('passive','detect'),
('software','correlate'),('correlate','priority'),('detect','priority'),('management','priority'),
('priority','triage'),('store','topology'),('topology','triage','Investigate evidence'),('triage','plan'),
('plan','human'),('human','reassess','No equipment action by Phylax'),('reassess','store'),
('triage','report'),('human','report'),('store','offline')],[
'Inventory verification, management approval, scan permission, acknowledgement and plan approval are independent decisions.',
'All local asset, network, policy and process context stays on the host. Only eligible public advisory fields can go to an operator-requested hosted model.',
'An observation or vulnerability match does not prove compromise. Missing observations or findings do not prove safety.'],
['phylax/web.py','phylax/release_web.py','phylax/core.py','phylax/topology.py'])

flow('setup','Setup, access and configuration','Local startup, optional tools, safe editing and separate execution processes.',[
('launch','Start CLI or localhost dashboard with selected database','action'),('upgrade','Open SQLite; apply additive versioned migrations as needed','action'),
('backup','Pre-upgrade backup for an existing database','data'),('config','Review Settings: source health and collector status','review'),
('inputs','Configure public sources, policies and monitored subnets','action'),('optional','Configure optional AI; install Zeek / Docker or Nmap only for relevant workflows','action'),
('processes','Run dashboard, watcher and scan worker separately as needed','action'),('request','Dashboard request','data'),
('guard','Valid Host; mutation also has matching Origin and form token?','decision'),('deny','Reject request; retain authoritative stored state','stop'),
('form','Validate bounded input and current record revision','action'),('valid','Valid and current?','decision'),('retry','Show escaped draft and error; reload stale record or correct fields','review'),
('save','Save explicit change with provenance / audit where supported','data'),('continue','Continue to data and operator workflows','result')],[
('launch','upgrade'),('upgrade','backup','Existing DB upgrade'),('backup','config'),('upgrade','config','New / current schema'),
('config','inputs'),('config','optional'),('inputs','processes'),('optional','processes'),('processes','continue'),
('request','guard'),('guard','deny','No'),('guard','form','Yes'),('form','valid'),('valid','retry','No'),('retry','form','Correct and resubmit'),('valid','save','Yes'),('save','continue')],[
'The dashboard remains localhost-only. Typed operator names provide attribution, not multi-user authentication.',
'Viewing settings does not probe connectivity. No page visit automatically scans devices or requests hosted guidance.',
'Each process owns its SQLite connection. Current web forms should be reloaded after server restart.'],
['phylax/migrations.py','phylax/web_security.py','phylax/web.py','phylax/operator_pages.py'])

flow('inventory','Inventory and operational context','Import, validate, reconcile and maintain evidence without guessing identities.',[
('input','Add / edit an asset or import CSV','action'),('validate','Validate addresses, enums, IDs, timestamps and bounded fields','action'),
('good','Row valid?','decision'),('bad','Report malformed row; operator corrects and retries','review'),
('identity','Existing asset ID or reliable simple passive record reconciliation?','decision'),('update','Update existing record under import rules','data'),
('create','Create separate asset; keep incomplete fields unknown','data'),('conflict','Ambiguous IP / MAC evidence remains reviewable; no hostname / MAC auto-merge','review'),
('context','Add owner, facility, lifecycle, tags and criticality rationale','action'),('process','Confirm or unlink process support with operator and note','action'),
('verify','Operator verifies product/version evidence and confidence','review'),('reassess','Automatically reevaluate relevant findings','action'),
('independent','Management approval and scan permission remain separate','review'),('export','Search / paginate inventory; export CSV or reports','result')],[
('input','validate'),('validate','good'),('good','bad','No'),('bad','input','Retry corrected rows'),('good','identity','Yes'),
('identity','update','Reliable match'),('identity','create','New / insufficient match'),('create','conflict','Conflicting evidence'),
('update','verify'),('create','verify'),('conflict','verify'),('verify','reassess'),('update','context'),('create','context'),
('context','process'),('process','export'),('reassess','independent'),('independent','export')],[
'A manufacturer name or IP address alone never establishes an exact model or firmware version.',
'Valid CSV rows can be imported while malformed rows are reported. Re-importing a stable asset ID updates that record.',
'Observed metadata remains distinct from manual verification. Process links explain support; they do not silently change criticality.'],
['phylax/core.py','phylax/validation.py','phylax/asset_intelligence.py','phylax/configuration_pages.py'])

flow('passive','Passive collection and ingestion','Three entry paths converge on validated, provenance-preserving local observations.',[
('entry','Choose passive input','decision'),('file','CLI or dashboard: finalized Zeek log','data'),('pcap','Offline PCAP: local Zeek or installed network-disabled Docker image','action'),
('tools','Tool / capture available and valid?','decision'),('toolerror','Show diagnostic; retain stored workflows','stop'),('logs','Zeek output logs with capture reference','data'),
('watch','Watcher polls finalized conn / modbus / dhcp / software logs','action'),('stable','Supported, bounded, non-symlink file stable across two polls?','decision'),
('wait','Wait for stability or report skipped / unsupported file','review'),('snapshot','Snapshot and hash stable content','action'),('new','Content differs from saved outcome?','decision'),
('skip','Skip unchanged content; retain prior success or failure diagnostic','data'),('parse','Use dedicated JSON Lines / TSV parser for each log kind','action'),
('valid','Whole file remains valid and unchanged during import?','decision'),('rollback','Roll back this file; record failure; changed content may retry','stop'),
('commit','Atomic deduplicated records; observed time distinct from ingestion time','data'),('dispatch','Connections / Modbus → events and rules; DHCP → identity; software → components','action'),
('health','Update collector health, change history and evidence references','result')],[
('entry','file','Import log'),('entry','pcap','Replay capture'),('entry','watch','Watch folder'),('pcap','tools'),('tools','toolerror','No'),('tools','logs','Yes'),('logs','parse'),('file','parse'),
('watch','stable'),('stable','wait','No'),('wait','watch','Later poll'),('stable','snapshot','Yes'),('snapshot','new'),('new','skip','No'),('new','parse','Yes'),
('parse','valid'),('valid','rollback','No'),('rollback','watch','Correct / change file'),('valid','commit','Yes'),('commit','dispatch'),('dispatch','health')],[
'Zeek collection is externally managed. Phylax observes only captured or imported evidence; it does not discover every silent device.',
'Current supported log kinds are conn, modbus, dhcp and software. A conn service label alone does not identify a Modbus write.',
'Collector inactivity and device inactivity are different. Neither silence nor a missing protocol field proves removal or malicious traffic.'],
['phylax/pcap.py','phylax/monitoring.py','phylax/observations.py','phylax/watcher.py'])

flow('management','Identity, management and change review','Approve, block or review endpoints only within explicit monitoring scope.',[
('obs','Connection / DHCP / software / active-probe observation','data'),('changes','Record first sighting, services, software and IP/MAC changes','data'),
('dhcp','DHCP association evidence?','decision'),('assigned','Assigned/client-address evidence can support a MAC association','data'),('requested','Requested address alone does not establish an assigned identity','review'),
('subnet','Endpoint in a configured monitored subnet?','decision'),('unmonitored','Unmonitored; no unmanaged-device alert','data'),
('compare','Compare explicit IP / MAC / pair decisions and verified identity','action'),('status','Resulting management state','decision'),
('approved','Approved; resolve related endpoint alert and retain history','result'),('blocked','Explicitly blocked → Unauthorized','stop'),
('unmanaged','No applicable approval → Unmanaged — needs review','review'),('ambiguous','Missing MAC-bound proof or conflicting identity → Identity review','review'),
('alert','One deduplicated endpoint alert per monitored subnet / IP','data'),('operator','Operator reviews original evidence and records approve / block / revoke','review'),
('repeat','Reevaluate stored evidence; reactivated endpoint alert resets acknowledgement','action'),('separate','Approval / acknowledgement never grants scan permission','result')],[
('obs','changes'),('changes','dhcp'),('dhcp','assigned','Assigned evidence'),('dhcp','requested','Request only'),('dhcp','subnet','Other observation'),('assigned','subnet'),('requested','subnet'),
('subnet','unmonitored','No'),('subnet','compare','Yes'),('compare','status'),('status','approved','Approved'),('status','blocked','Blocked'),('status','unmanaged','Unapproved'),('status','ambiguous','Insufficient / conflicting'),
('blocked','alert'),('unmanaged','alert'),('ambiguous','alert'),('alert','operator'),('operator','repeat'),('repeat','compare'),('approved','separate')],[
'Existing inventory is not automatically management-approved. The system uses Unauthorized only for an applicable explicit block.',
'Observation and ingestion timestamps stay separate. Neither hostname nor MAC similarity automatically merges inventory records.',
'Inspect the Changes and Approvals tools under Assets; a resolution keeps management history.'],
['phylax/asset_intelligence.py','phylax/observations.py','phylax/review_pages.py'])

flow('discovery','Approved active IT discovery','A persistent queue and separate worker enforce per-target permission and bounded probing.',[
('choose','Choose known supporting IT asset / management IP','review'),('eligible','Known eligible inventory and literal IPv4 target?','decision'),
('reject','Reject OT control endpoints, unknown / observed-only identities and ineligible targets','stop'),('permission','Save separate scan permission, 1–32 TCP ports, optional standard HTTP(S)/SSH identification','action'),
('trigger','Manual request or enabled schedule due?','decision'),('queue','Deduplicated persistent queued run bound to permission revision','data'),('worker','Separate worker claims database-wide lease','action'),
('lease','Another valid lease active?','decision'),('busy','Busy; do not overlap workers','data'),('recover','Expired running work becomes Interrupted; no automatic replay','review'),
('check','Revalidate permission, eligibility, revision and cancellation','decision'),('cancel','Cancelled: operator request or changed / revoked target','stop'),
('nmap','Bounded unprivileged TCP connect scan; no DNS / extra discovery probes','action'),('ok','Probe succeeds within limits?','decision'),('failed','Failed: missing Nmap, timeout or execution error','stop'),
('identify','Only selected open ports: optional HTTP(S) headers or SSH banner','action'),('finalcheck','Permission, revision and cancellation still valid before persistence?','decision'),('result','Store port states, tool version, provenance and identification errors','data'),
('observe','Active-probe evidence and service changes; versions remain unverified','data'),('software','Known component evidence → software review and correlation','result'),
('schedule','Next schedule after interval; missed intervals skipped','action')],[
('choose','eligible'),('eligible','reject','No'),('eligible','permission','Yes'),('permission','trigger'),('trigger','queue','Run / schedule'),('queue','worker'),('worker','lease'),
('lease','busy','Yes'),('lease','recover','No / expired'),('recover','check'),('check','cancel','No longer valid'),('check','nmap','Valid'),('nmap','ok'),('ok','failed','No'),('ok','identify','Yes'),
('identify','finalcheck'),('finalcheck','cancel','No'),('finalcheck','result','Yes'),('result','observe'),('observe','software'),('software','schedule'),('failed','schedule'),('cancel','schedule'),('schedule','trigger'),
('permission','cancel','Changing permission invalidates queued work','dashed')],[
'At most one active run per database; 30-second scan timeout, 180-second execution bound, and constrained pacing. No CIDR expansion, scripts, UDP or OS fingerprinting.',
'Identification is limited to SSH 22, HTTP 80/8080 and HTTPS 443/8443. Redirects/authentication are disabled; TLS failures remain explicit.',
'No response is not proof a device is offline. Results never auto-expand permissions or scan OT endpoints.'],
['phylax/discovery.py','phylax/release_cli.py','phylax/configuration_pages.py'])

flow('intelligence','Intelligence sync, resume and offline load','Public collection remains independent of inventory; failures retain cached records.',[
('trigger','Manual Sync public sources, CLI sync-feeds or selected source sync','action'),('channels','Independent source paths','decision'),
('checkpoint','NVD saved window / page checkpoint exists?','decision'),('resume','Resume saved fixed window at next page; checkpoint takes precedence','action'),
('backfill','Explicit --backfill-days 1–120?','decision'),('wide','Start requested last-modified window','action'),('incremental','Normal sync: last successful window with one-day overlap; first run about one day','action'),
('page','Fetch bounded NVD page; timeout / transient retry handling','action'),('saved','Normalize and persist page + checkpoint','data'),('more','More pages?','decision'),
('finish','Clear checkpoint; store last successful synchronization','result'),('other','KEV full JSON; ICS RSS; configured CSAF URLs with conditional cache','action'),
('single','refresh-cve: one official CVE record','action'),('offline','Load validated offline advisory fixture; retain declared provenance','data'),
('normalize','Deduplicate by source / identifier; preserve versions, refs and retrieved time','data'),('fail','Source unavailable / malformed: retain cache and checkpoint; other sources continue','stop'),('interrupt','Operator cancels / process stops: saved pages and checkpoint persist','data'),
('reeval','Automatically reevaluate affected local findings','action'),('health','Show source health, recent updates, last success and staleness after 24 hours','review')],[
('trigger','channels'),('channels','checkpoint','NVD'),('checkpoint','resume','Yes'),('checkpoint','backfill','No'),('backfill','wide','Yes'),('backfill','incremental','No'),
('resume','page'),('wide','page'),('incremental','page'),('page','saved','Valid page'),('saved','more'),('more','page','Yes'),('more','finish','No'),('page','fail','Source failure'),('page','interrupt','Operator cancellation / process stop'),('interrupt','trigger','Next operator sync resumes'),
('channels','other','CISA sources'),('other','normalize','Valid / updated'),('other','fail','Unavailable'),('finish','normalize'),('single','normalize'),('offline','normalize'),('normalize','reeval'),('reeval','health'),('fail','health'),('health','trigger','Operator retries when ready','dashed')],[
'No asset inventory is sent to feed services. A backfill is a wider last-modified window, not a complete historical download.',
'KEV supplies exploitation-catalog metadata, not affected-version ranges or proof of attack. RSS-only advisories remain review references without invented version conditions.',
'Configured CSAF is a narrow official-URL adapter. Unsupported status relationships / version expressions remain for review; advisories without CVEs are retained.'],
['phylax/feeds.py','phylax/adapters.py','phylax/csaf.py','phylax/core.py'])

flow('correlation','Software, applicability and reassessment','Exact product evidence and supported version semantics drive findings; similarity is not proof.',[
('identity','Hardware / firmware inventory plus active software components','data'),('component','Software observation: raw name, version, source and time','data'),
('mapping','Exact operator-managed product mapping exists?','decision'),('unmapped','Retain unmapped component for operator mapping / review','review'),('mapped','Normalize vendor/product; retain raw values and verification state','data'),
('changed','Different / competing observed version?','decision'),('reset','Invalidate prior component verification; record changes; conflicting active versions need review','review'),
('candidates','Exact normalized vendor/product candidates','action'),('candidate','Any candidate?','decision'),('none','No applicability finding for unrelated products; missing identity stays reviewable','review'),
('conditions','Identity confidence sufficient; prerequisites supported and sources consistent?','decision'),('review','NEEDS_REVIEW','review'),('version','Installed version known?','decision'),('semantics','Can source version conditions be compared safely?','decision'),('verify_match','Verified high-confidence identity?','decision'),('verify_exclusion','Verified high-confidence identity?','decision'),
('potential','POTENTIAL_MATCH','review'),('affected','Source-defined version affected?','decision'),('confirmed','CONFIRMED_MATCH','result'),('excluded','NO_MATCH_TO_THIS_ADVISORY','data'),
('aggregate','One stable asset/CVE finding with component evidence; confirmed → potential → review → exclusion','data'),('priority','Vulnerability urgency rule v2; score only confirmed / potential','action'),
('alert','Create/update deduplicated exposure alert; preserve acknowledgement on update','result'),('noalert','No active exposure alert for review / excluded; retain assessment evidence','data'),
('planchange','Changed supporting finding evidence / priority: archive plan and require more evidence','review'),('recheck','Inventory, mapping, component review or source change retriggers assessment','action')],[
('component','mapping'),('mapping','unmapped','No'),('unmapped','mapping','Operator adds mapping'),('mapping','mapped','Yes'),('mapped','changed'),('changed','reset','Yes'),('changed','identity','No'),('reset','identity'),
('identity','candidates'),('candidates','candidate'),('candidate','none','No'),('candidate','conditions','Yes'),('conditions','review','No / conflict'),('conditions','version','Yes'),
('version','potential','No'),('version','semantics','Yes'),('semantics','review','No'),('semantics','affected','Yes'),('affected','verify_match','Affected'),('affected','verify_exclusion','Outside / explicitly fixed'),('verify_match','confirmed','Yes'),('verify_match','potential','No'),('verify_exclusion','excluded','Yes'),('verify_exclusion','review','No'),
('review','aggregate'),('potential','aggregate'),('confirmed','aggregate'),('excluded','aggregate'),('aggregate','priority'),('priority','alert','Confirmed / potential'),('priority','noalert','Review / excluded'),
('aggregate','planchange','Supporting evidence changed'),('recheck','identity'),('none','recheck','Operator supplies evidence','dashed')],[
'Actual assessment ordering also checks low confidence, unsupported version semantics and conflicting source conditions. Incomplete evidence cannot produce a fabricated confirmed match.',
'Vulnerability v2: KEV +3; severity critical/high/medium +3/+2/+1; asset criticality +3/+2/+1; confirmed applicability +2; known DMZ +1. Urgency: critical ≥8, high 6–7, medium 3–5, low 0–2.',
'Unknown severity adds no invented CVSS. Vendor fix and observed reachability are not inferred. Removing an obsolete product association archives its plan before removing the finding.'],
['phylax/correlation.py','phylax/observations.py','phylax/prioritization.py','phylax/core.py'])

flow('triage','Policy detection, urgency and Triage','Passive rules, management reviews and exposures converge on human investigation.',[
('event','Stored conn / Modbus event and current configured policy','data'),('fields','For each rule: required evidence and policy section available?','decision'),
('diagnostic','Record cannot-evaluate diagnostic; do not fabricate a violation','review'),('rules','Evaluate configured rules independently','action'),
('writer','Unauthorized Modbus writer?','decision'),('peer','Protected-destination communication violates allowlist?','decision'),('window','Prohibited write outside approved maintenance window?','decision'),
('violate','Create/update rule + event alert with policy evidence','data'),('normal','No rule violation; observation stays available','data'),
('repolicy','New policy version / repeat import → reevaluate stored events','action'),('cleared','Violation cleared → resolved history; exclude from active count','result'),
('networkscore','Network / management urgency v1 from severity, relevant criticality and protected destination','action'),
('exposure','Exposure alerts already carry vulnerability v2 urgency','data'),('endpoint','Endpoint management alerts carry their evidence','data'),
('triage','Filter unified Triage by category, urgency, review state and text','review'),('inspect','Inspect asset, original event, policy, score factors and process context','review'),
('ack','Acknowledge reviewed alert; retain filters and evidence','action'),('follow','Supply identity evidence, change approved policy or review a plan','review')],[
('event','fields'),('fields','diagnostic','No'),('fields','rules','Yes'),('rules','writer'),('rules','peer'),('rules','window'),
('writer','violate','Yes'),('peer','violate','Yes'),('window','violate','Yes'),('writer','normal','No'),('peer','normal','No'),('window','normal','No'),
('repolicy','fields'),('repolicy','cleared','No longer violates'),('violate','networkscore'),('endpoint','networkscore'),('networkscore','triage'),('exposure','triage'),
('triage','inspect'),('inspect','ack'),('inspect','follow'),('follow','repolicy','Policy review','dashed')],[
'Normal reads, authorized writes and new peers are not automatically malicious. Missing fields and unconfigured policy sections remain explicit.',
'Network v1 adds severity 0–3, relevant asset criticality 0–3 and protected destination +1. Urgency: critical ≥6, high 4–5, medium 2–3, low 0–1.',
'Acknowledgement does not fix a vulnerability, approve a device, grant permission or execute remediation. Severity, applicability, urgency and confidence stay separate.'],
['phylax/monitoring.py','phylax/triage.py','phylax/triage_views.py','phylax/prioritization.py'])

flow('topology','Topology investigation','Move from a bounded passive map to actual identity, communications and finding evidence.',[
('open','Monitoring → Attack surface','action'),('filters','Filter subnet, zone, criticality, management state, UTC window or endpoint','action'),
('surface','Join inventory with imported operational communication; retain unknown peers','data'),('traffic','Observed endpoints in filtered evidence?','decision'),
('empty','Empty graph: import logs or widen filters; inventory stays available','review'),('graph','Zone-grouped node diagram and directed observed connections','result'),
('controls','Find all known assets/peers, zoom or hide confirmed process links','action'),('select','Select an observed node or inventory-only asset','review'),
('details','Read identity confidence, management, observed times and applicability counts','data'),('event','Open original communication event / source record','review'),
('finding','Open focused vulnerability finding or inventory editor','review'),('context','Open operator-confirmed process context','review'),
('all','Expand inventory-only list / full assets; inspect communication and support tables','review'),('triage','Continue investigation in Triage or plan review','result')],[
('open','filters'),('filters','surface'),('surface','traffic'),('traffic','empty','No'),('traffic','graph','Yes'),('graph','controls'),('controls','graph','Local view update','dashed'),
('graph','select'),('surface','all'),('all','select'),('select','details'),('details','event'),('details','finding'),('graph','context','Confirmed process link'),
('event','triage'),('finding','triage'),('context','triage'),('empty','filters','Widen view','dashed')],[
'The diagram is bounded to 24 observed endpoints, 60 directed connections and 12 process nodes. Omission counts are visible; evidence remains in the tables.',
'Colliding port/protocol labels are suppressed with an explicit count, not lost. Inspectable edge metadata and original event links remain.',
'Find includes inventory-only and older peers; zero results leave no unrelated selection. Mobile details precede the natural-size scrollable graph.',
'Observation existence is independent of the 1,000-group listing cap. Asset/focus filters precede that cap; event totals are time-scoped before asset filters.',
'Zone grouping is inventory context, not a trust boundary. Dashed process support is an operator assertion, not an inferred network or attack path.'],
['phylax/topology.py','phylax/surface.py','phylax/web.py','phylax/release_web.py'])

flow('guidance','Guidance generation and public-data boundary','Only an operator request may call a hosted model, and only with trusted public advisory fields.',[
('request','Operator requests plan for a selected finding','review'),('job','Bounded process-local background job with progress','action'),
('eligible','Configured provider AND trusted public snapshot AND non-synthetic record?','decision'),
('localreason','Explain disabled / synthetic / untrusted-source path; no hosted request','data'),('public','Allowlist public CVE/advisory fields and supplied reference URLs','data'),
('remote','Hosted model receives public advisory fields only','action'),('validate','Response shape, citations, timeout / failure and command-syntax checks pass?','decision'),
('good','AI-generated, unverified public-guidance supplement','data'),('failure','Record explicit provider / validation failure','stop'),('current','Finding unchanged during generation?','decision'),
('retry','Reject stale result; operator reviews current finding and retries','review'),('existing','Fallback reason and previous hosted plan exists?','decision'),
('keep','Keep previous hosted plan; record failure reason','result'),('compose','Compose deterministic local plan; attach valid public AI supplement if available','action'),
('save','Store plan, actual model, timestamps, supplied / cited URLs and provenance','data'),('archive','Regeneration archives old contents and clears prior review / verification','review'),
('review','Continue to human lifecycle; finding severity, applicability, urgency and acknowledgement unchanged','result'),
('private','Inventory, IPs, events, policies, local risk and process context stay local','data')],[
('request','job'),('job','eligible'),('eligible','localreason','No'),('eligible','public','Yes'),('private','compose','Local evidence only'),('public','remote'),('remote','validate'),
('validate','good','Yes'),('validate','failure','No'),('good','current'),('localreason','current'),('failure','current'),('current','retry','No'),('current','existing','Yes'),
('existing','keep','Yes'),('existing','compose','No'),('compose','save'),('save','archive','Replacing prior plan'),('save','review','New plan'),('archive','review'),('keep','review')],[
'Synthetic and imported untrusted records intentionally never call a hosted model. An official public refresh can establish eligible trusted source provenance.',
'Fallback is a clearly labeled local template. Provider failure does not overwrite an existing hosted plan with fallback.',
'Citation checks do not prove factual support or semantic correctness. AI cannot change findings, priority, permissions, acknowledgement or equipment.'],
['phylax/remediation_service.py','phylax/ai.py','phylax/remediation.py','phylax/jobs.py'])

# Generate every valid user-facing lifecycle transition from the authoritative map.
state_nodes=[('start','Generate new plan / regenerate existing plan','action')]
state_ids={name:re.sub(r'[^a-z]','',name.casefold()) for name in TRANSITIONS}
for name in TRANSITIONS:
    state_nodes.append((state_ids[name],name,'result' if name=='Verified' else 'review'))
state_nodes.extend([('evidence','Supporting finding evidence / priority changes → archive snapshot and clear review','data'),
                    ('external','Any infrastructure change is performed separately by authorized people','data')])
state_edges=[('start',state_ids['Recommended'],'New or replacement plan')]
for source,targets in TRANSITIONS.items():
    for target in targets:
        label='Reviewer required' if target=='Approved' else 'Verification evidence required' if target=='Verified' else 'Record external implementation' if target=='Implemented' else ''
        state_edges.append((state_ids[source],state_ids[target],label))
state_edges.extend([('evidence',state_ids['Needs More Evidence'],'Re-review required'),(state_ids['Approved'],'external','Guidance only','dashed')])
flow('lifecycle','Complete remediation lifecycle','Every allowed manual status transition from the current transition map.',state_nodes,state_edges,[
'Recommended must enter Under Review before approval. Approval requires a reviewer; Verified requires explicit verification evidence.',
'Regeneration archives prior contents and returns to Recommended. Supporting finding changes archive evidence and set Needs More Evidence; obsolete findings archive plans before removal.',
'Plan states do not automatically mark a vulnerability fixed or modify equipment. Update real inventory/evidence and reassess separately. Invalid transitions are rejected with retained draft input.'],
['phylax/remediation_lifecycle.py','phylax/core.py','phylax/correlation.py'],direction='LR')

flow('operations','Reporting, offline operation and recovery','Understand what persists and how each interruption recovers.',[
('review','Reviewed local findings, observations, decisions and plans','data'),('export','Reports or CLI export','action'),('formats','JSON / CSV / Markdown; inventory CSV separately','result'),
('content','Generation time, identity, provenance, applicability, missing evidence, priority, changes and context','data'),
('disconnect','Internet unavailable','decision'),('local','Inventory, stored intelligence, findings, triage, topology, reports and offline PCAP analysis remain available','result'),
('unavailable','Live feed sync / hosted generation may fail; keep cache and prior hosted plan as applicable','review'),
('restart','Process stops / restarts','decision'),('db','SQLite inventory, evidence, permissions, scan queue, plans, source cache and NVD checkpoints persist','data'),
('nvd','NVD resumes saved page/window on next sync','action'),('watcher','Watcher rechecks stable content hashes and saved outcomes','action'),
('scanner','Expired running scan → Interrupted; queued work revalidated; no catch-up burst','review'),('webjobs','Web job queue/progress is process-local; inspect stored result and resubmit if needed','review'),
('health','Inspect source staleness and collector/worker heartbeat separately','review'),('upgrade','Before schema upgrade: backup existing DB; preserve IDs and verify copy','action'),
('audit','Review stored audit / plan archives; keep reports and local backups appropriately','data')],[
('review','export'),('export','formats'),('formats','content'),('content','audit'),('disconnect','local','Stored/local workflows'),('disconnect','unavailable','Needs external service'),
('restart','db'),('db','nvd'),('db','watcher'),('db','scanner'),('restart','webjobs'),('nvd','health'),('watcher','health'),('scanner','health'),('webjobs','health'),
('upgrade','db'),('health','audit')],[
'Stale intelligence is visible after the stored 24-hour source-health threshold; losing internet does not immediately make a recent cache stale.',
'Reports preserve uncertainty. Acknowledgement and plan verification are not proof of compromise or automatic remediation.',
'No public raw-PCAP download endpoint exists. There is no immutable forensic audit system, multi-user identity provider or production military deployment claim.'],
['phylax/reports.py','phylax/migrations.py','phylax/jobs.py','phylax/watcher.py','phylax/discovery.py'])

flow('demo','Complete controlled demonstration','A practical route through all feature groups in a fictional isolated support-site lab.',[
('prepare','Prepare clearly labeled fictional lab and disposable database','action'),('inventory','Import / validate inventory; include known and incomplete identities','action'),
('context','Add owners, criticality rationale and confirmed process support','action'),('subnet','Configure monitored subnet, management decisions and passive policy','action'),
('passive','Replay benign / write captures or import all four Zeek log kinds','action'),('changes','Review unmanaged peer, DHCP association and service/version changes','review'),
('scan','Explicitly permit isolated supporting IT host; queue / schedule bounded discovery','action'),('software','Review unverified software; apply exact mapping; confirm evidence','review'),
('intel','Load deterministic advisory cases plus verified public snapshot for hosted demo','data'),('matches','Review confirmed / potential / excluded / needs-review evidence','review'),
('rules','Demonstrate writer, unexpected communication and maintenance violations','review'),('map','Inspect topology, original events, process context and missing visibility','review'),
('triage','Compare urgency factors and acknowledge reviewed alerts','review'),('guidance','Request eligible public guidance; exercise local fallback / provider failure honestly','review'),
('plan','Review plan; record approved, externally implemented and verified test evidence','review'),('report','Export reports and compare evidence/counts','result'),
('offline','Disconnect; reopen stored views, offline replay and saved guidance; show health times','result')],[
('prepare','inventory'),('inventory','context'),('context','subnet'),('subnet','passive'),('passive','changes'),('changes','scan'),('scan','software'),('software','intel'),
('intel','matches'),('matches','rules'),('rules','map'),('map','triage'),('triage','guidance'),('guidance','plan'),('plan','report'),('report','offline')],[
'This is a demonstration itinerary, not a requirement to approve all test endpoints or scan OT. The isolated demo starts with active scanning disabled.',
'Synthetic advisory cases are useful for deterministic applicability but never sent to a hosted model. Use a separately refreshed eligible public advisory to demonstrate hosted guidance.',
'Use saved guidance with its original provenance when offline. Neither provider availability nor a newly published CVE should determine whether the demonstration succeeds.'],
['scripts/prepare_release_demo.py','docs/manual-testing.md','demo/README.md'])


def wrapped(label):
    return '\n'.join('\n'.join(textwrap.wrap(line,31,break_long_words=False,break_on_hyphens=False)) for line in label.splitlines())


def dot_source(item):
    lines=['digraph workflow {',f'graph [rankdir={item["direction"]}, bgcolor="#0b1017", pad="0.35", nodesep="0.38", ranksep="0.6", splines=polyline, outputorder=edgesfirst];',
           'node [fontname="DejaVu Sans", fontsize=12, fontcolor="#e6e8ec", shape=box, style="rounded,filled", penwidth=1.1, margin="0.18,0.12"];',
           'edge [fontname="DejaVu Sans", fontsize=10, fontcolor="#c2cbd8", color="#8392a5", arrowsize=0.7, penwidth=1.1];']
    for key,label,kind in item['nodes']:
        fill,line=PALETTE[kind];shape='diamond' if kind=='decision' else 'cylinder' if kind=='data' else 'box'
        lines.append(f'{json.dumps(key)} [label={json.dumps(wrapped(label))}, tooltip={json.dumps(label)}, shape={shape}, fillcolor="{fill}", color="{line}"];')
    for edge in item['edges']:
        a,b,*rest=edge;label=rest[0] if rest else '';style=rest[1] if len(rest)>1 else 'solid'
        lines.append(f'{json.dumps(a)} -> {json.dumps(b)} [label={json.dumps(wrapped(label))}, style={style}];')
    return '\n'.join(lines+['}'])


def mermaid(item):
    lines=['flowchart '+('LR' if item['direction']=='LR' else 'TD')]
    for key,label,kind in item['nodes']:
        safe=html.escape(label,quote=True).replace('\n','<br/>')
        lines.append(f'    n_{key}' + ('{"'+safe+'"}' if kind=='decision' else '["'+safe+'"]'))
    for edge in item['edges']:
        a,b,*rest=edge;label=rest[0] if rest else '';style=rest[1] if len(rest)>1 else 'solid'
        arrow='-.->' if style=='dashed' else '-->'
        lines.append(f'    n_{a} {arrow}'+((' |"'+html.escape(label,quote=True)+'"|') if label else '')+' n_'+b)
    return '\n'.join(lines)


def main():
    binary=shutil.which('dot',path='/usr/bin:/usr/local/bin')
    if not binary:raise SystemExit('Graphviz dot is required to rebuild; generated atlas/SVGs work without it.')
    DIAGRAMS.mkdir(exist_ok=True)
    markdown=['# Phylax workflow atlas','',
              'These diagrams describe implemented operator paths, decisions and recovery behavior; they are not a claim that every arbitrary input or deployment scenario is covered.','',
              '[Open the offline interactive atlas](index.html). Generated SVG and DOT files are under `diagrams/`. No inventory, database or API secrets are read by this generator.','',
              '## Workflow index','']
    items=[]
    for index,item in enumerate(WORKFLOWS):
        dot=dot_source(item);(DIAGRAMS/(item['key']+'.dot')).write_text(dot)
        result=subprocess.run([binary,'-Tsvg'],input=dot.encode(),capture_output=True,check=True,timeout=15)
        svg=result.stdout.decode();svg=re.sub(r'^.*?(?=<svg\b)','',svg,flags=re.S)
        svg=svg.replace('<svg ','<svg role="img" aria-label="'+html.escape(item['title'],quote=True)+'" ',1)
        (DIAGRAMS/(item['key']+'.svg')).write_text(svg)
        if item['key']=='overview':
            image=subprocess.run([binary,'-Tpng','-Gdpi=110'],input=dot.encode(),capture_output=True,check=True,timeout=15)
            (DIAGRAMS/'overview.png').write_bytes(image.stdout)
        items.append({**item,'svg':svg,'index':index+1})
        markdown.append(f'{index+1}. [{item["title"]}](#{item["key"]})')
    for item in WORKFLOWS:
        markdown += ['',f'<a id="{item["key"]}"></a>',f'## {item["title"]}','',item['description'],'',
                     '```mermaid',mermaid(item),'```','',f'[Open SVG](diagrams/{item["key"]}.svg) · [Editable Graphviz source](diagrams/{item["key"]}.dot)','']
        markdown += ['- '+note for note in item['notes']]
        markdown += ['','**Implementation:** '+', '.join('['+source+'](../../'+source+')' for source in item['sources'])+'.']
    (OUT/'WORKFLOWS.md').write_text('\n'.join(markdown)+'\n')
    html_page(items)
    (OUT/'manifest.json').write_text(json.dumps({'workflow_count':len(items),'chapters':[{k:item[k] for k in ('key','title','sources')} for item in items]},indent=2)+'\n')
    print(f'Built {len(items)} workflow diagrams, offline atlas, Mermaid documentation and source files.')


def html_page(items):
    nav=''.join(f'<button class="chapter" data-key="{i["key"]}" data-search="{html.escape(i["title"]+" "+i["description"]+" "+" ".join(n[1] for n in i["nodes"])+" "+" ".join(i["notes"]),quote=True)}"><span>{i["index"]:02d}</span>{html.escape(i["title"])}</button>' for i in items)
    sections=''
    for item in items:
        notes=''.join('<li>'+html.escape(n)+'</li>' for n in item['notes'])
        text_steps='<ol>'+''.join('<li>'+html.escape(n[1])+'</li>' for n in item['nodes'])+'</ol>'
        sources=' · '.join('<code>'+html.escape(s)+'</code>' for s in item['sources'])
        sections+=f'''<section class="workflow" id="{item['key']}" aria-labelledby="title-{item['key']}">
<h2 id="title-{item['key']}">{html.escape(item['title'])}</h2><p class="description">{html.escape(item['description'])}</p>
<div class="tools"><div><button data-zoom="out" aria-label="Zoom out">−</button><button data-zoom="fit">Fit width</button><button data-zoom="in" aria-label="Zoom in">+</button><output aria-live="polite">100%</output></div><a href="diagrams/{item['key']}.svg" target="_blank" rel="noopener">Open SVG</a><a href="diagrams/{item['key']}.svg" download>Download SVG</a><a href="diagrams/{item['key']}.dot" download>DOT source</a></div>
<div class="diagram" tabindex="0" role="region" aria-label="{html.escape(item['title'],quote=True)} diagram; scroll to explore">{item['svg']}</div>
<p class="hint">Zoom for detail. Scroll or use arrow keys inside the diagram to explore. Dashed arrows show feedback or external human steps.</p>
<div class="notes"><h3>Decision boundaries</h3><ul>{notes}</ul></div><details><summary>Text version of workflow nodes</summary>{text_steps}</details><details><summary>Implementation references</summary><p>{sources}</p></details></section>'''
    page='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Phylax · Workflow atlas</title><style>
:root{color-scheme:dark;--bg:#0b1017;--surface:#101720;--line:#293545;--text:#e6e8ec;--muted:#a6b0be;--link:#9cbce6;--control:#6a7e96;font:15px/1.55 "Segoe UI",Arial,sans-serif}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text)}a{color:var(--link);text-underline-offset:3px}button,input{font:inherit;color:inherit;background:var(--surface);border:1px solid var(--control);border-radius:3px}button{cursor:pointer;min-height:44px;padding:7px 12px;white-space:nowrap}button:hover{background:#202c3b}input{width:100%;min-height:44px;padding:8px 10px}input::placeholder{color:var(--muted)}:focus-visible{outline:2px solid var(--link);outline-offset:3px}header{padding:22px 28px;border-bottom:1px solid var(--line)}header a{text-decoration:none;font-size:13px;letter-spacing:.14em;font-weight:700;color:var(--text)}h1{margin:8px 0 5px;font-size:29px;line-height:1.2}header p{margin:0;color:var(--muted);max-width:82ch}.shell{display:grid;grid-template-columns:285px minmax(0,1fr)}aside{border-right:1px solid var(--line);padding:22px 16px;height:calc(100vh - 161px);position:sticky;top:0;overflow:auto}aside label{font-size:13px;display:block;margin:0 8px 8px;color:var(--muted)}aside input{margin-bottom:14px}.chapter{display:flex;gap:10px;align-items:baseline;text-align:left;border:0;background:transparent;white-space:normal;width:100%;padding:9px 10px;color:var(--muted);border-left:2px solid transparent;border-radius:0}.chapter span{font-size:11px;color:var(--muted);flex:none}.chapter[aria-current]{border-left-color:var(--link);color:var(--text);background:#182435}.chapter[hidden]{display:none}main{padding:24px 28px 48px;min-width:0}.workflow{display:none}.workflow.active{display:block}h2{font-size:24px;line-height:1.25;margin:0 0 8px}h3{font-size:15px;margin:0 0 8px}.description{color:var(--muted);margin:0 0 20px;max-width:80ch}.tools{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:12px 14px;border:1px solid var(--line);border-bottom:0;background:var(--surface)}.tools>div{display:flex;align-items:center;gap:7px;margin-right:auto}.tools a{font-size:13px}output{font-size:12px;color:var(--muted);min-width:38px;padding-left:5px}.diagram{overflow:auto;max-height:72vh;border:1px solid var(--line);background:var(--bg)}.diagram svg{display:block;max-width:none;height:auto}.hint{font-size:12px;color:var(--muted);margin:9px 0 24px}.notes{max-width:90ch;border-top:1px solid var(--line);padding-top:18px}.notes ul{margin:0;padding-left:20px}.notes li{margin:9px 0}details{margin-top:20px;color:var(--muted);font-size:13px}summary{cursor:pointer;color:var(--link)}code{font:12px/1.5 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}.legend{display:flex;flex-wrap:wrap;gap:8px 20px;margin:0 0 20px;font-size:12px;color:var(--muted)}.legend span{display:flex;align-items:center;gap:7px}.legend i{display:inline-block;width:10px;height:10px;border:1px solid #7197bd;background:#14202f}.legend .decision{background:#292419;border-color:#b39461}.legend .data{background:#17202a;border-color:#738397}.legend .review{background:#292217;border-color:#c4a071}.legend .stop{background:#2b1c23;border-color:#bd8591}.legend .result{background:#15271f;border-color:#7eaa90}.menu-toggle{display:none}footer{margin-top:28px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}.empty-menu{font-size:13px;color:var(--muted);padding:0 10px}::selection{background:#375a82;color:#fff}html{scrollbar-color:#54657a var(--bg)}
@media(max-width:900px){header{padding:20px 16px}.shell{display:block}aside{height:auto;position:static;border-right:0;border-bottom:1px solid var(--line);padding:14px 16px}.menu-toggle{display:block;width:100%;text-align:left}.menu-body{display:none;margin-top:14px}.menu-body.open{display:block}main{padding:22px 16px 40px}.tools{gap:12px}.tools>div{width:100%;margin-right:0}.diagram{max-height:65vh}h1{font-size:26px}h2{font-size:23px}input{font-size:16px}}@media print{header,aside,.tools,.hint,.legend,footer{display:none}.shell{display:block}main{padding:0}.workflow{display:block!important;break-before:page}.diagram{max-height:none;overflow:visible}.diagram svg{width:100%!important}.notes{font-size:11px}}
</style><noscript><style>.workflow{display:block;margin-bottom:48px}.menu-body{display:block}.menu-toggle,.tools{display:none}</style></noscript></head><body><header><a href="#overview">PHYLAX</a><h1>Workflow atlas</h1><p>Current operator paths, decision boundaries and recovery loops. Fully offline; no connection to your asset database.</p></header><div class="shell"><aside><button class="menu-toggle" aria-expanded="false" aria-controls="chapter-menu">Choose workflow · 14 diagrams</button><div id="chapter-menu" class="menu-body"><label for="chapter-search">Find a workflow</label><input id="chapter-search" type="search" placeholder="Inventory, sync, failure…"><nav aria-label="Workflow chapters">NAV</nav><p class="empty-menu" hidden>No matching workflows.</p></div></aside><main><div class="legend" aria-label="Diagram legend"><span><i></i>Action</span><span><i class="decision"></i>Decision</span><span><i class="data"></i>Stored data</span><span><i class="review"></i>Human review</span><span><i class="stop"></i>Reject / failure</span><span><i class="result"></i>Outcome</span></div>SECTIONS<footer>These maps describe implemented feature paths, not every possible input or deployment scenario. No active scan, feed synchronization, model call or device action is triggered here. <a href="WORKFLOWS.md">Mermaid source and workflow notes</a>.</footer></main></div><script>
const sections=[...document.querySelectorAll('.workflow')],chapters=[...document.querySelectorAll('.chapter')];let current=null;const scales=new Map();function resize(scale){if(!current)return;const svg=current.querySelector('svg'),base=svg.viewBox.baseVal.width;scale=Math.max(.2,Math.min(2.5,scale));svg.style.width=(base*scale)+'px';scales.set(current.id,scale);current.querySelector('output').textContent=Math.round(scale*100)+'%';}function fit(){if(current)resize(current.querySelector('.diagram').clientWidth/current.querySelector('svg').viewBox.baseVal.width);}function show(key){current=sections.find(s=>s.id===key)||sections[0];for(const s of sections)s.classList.toggle('active',s===current);for(const b of chapters){if(b.dataset.key===current.id)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}requestAnimationFrame(()=>{if(scales.has(current.id))resize(scales.get(current.id));else fit();});document.title='Phylax · '+current.querySelector('h2').textContent;}for(const b of chapters)b.addEventListener('click',()=>{location.hash=b.dataset.key;document.querySelector('.menu-body').classList.remove('open');document.querySelector('.menu-toggle').setAttribute('aria-expanded','false');});window.addEventListener('hashchange',()=>show(location.hash.slice(1)));for(const button of document.querySelectorAll('[data-zoom]'))button.addEventListener('click',()=>{const command=button.dataset.zoom;if(command==='fit')fit();else resize((scales.get(current.id)||1)+(command==='in' ? .2 : -.2));});document.querySelector('#chapter-search').addEventListener('input',event=>{let visible=0;for(const b of chapters){const match=b.dataset.search.toLowerCase().includes(event.target.value.trim().toLowerCase());b.hidden=!match;if(match)visible++;}document.querySelector('.empty-menu').hidden=visible>0;});document.querySelector('.menu-toggle').addEventListener('click',()=>{const open=document.querySelector('.menu-body').classList.toggle('open');document.querySelector('.menu-toggle').setAttribute('aria-expanded',String(open));});show(location.hash.slice(1));
</script></body></html>'''
    (OUT/'index.html').write_text(page.replace('NAV',nav).replace('SECTIONS',sections))


if __name__=='__main__':main()
