# Phylax workflow atlas

[Documentation index](../README.md) · [Current operator guide](../operator-guide.md)

Open **[index.html](index.html)** in a browser. All 14 diagrams are embedded, so the
atlas works offline and does not connect to Phylax, the asset database, feeds or AI.
Choose a chapter, search workflow terms, zoom, scroll, or download an SVG.
The textual node lists and decision notes accompany each diagram.

[Full Mermaid documentation](WORKFLOWS.md) · [Overview PNG](diagrams/overview.png)

## Coverage

1. End-to-end system.
2. Setup, access protections and configuration.
3. Inventory and operational context.
4. Passive PCAP / log ingestion and folder watcher.
5. Identity, management approval, blocking, revocation and changes.
6. Approved active IT discovery, scheduling, cancellation and recovery.
7. Intelligence ingestion, incremental updates, backfill and NVD resume.
8. Software mapping, applicability, uncertainty and reassessment.
9. Passive policy rules, scoring and unified Triage.
10. Topology investigation and source evidence.
11. Hosted guidance eligibility, privacy, validation and fallback.
12. Every allowed remediation lifecycle transition.
13. Reports, offline operation, persistence and recovery.
14. A complete controlled demonstration itinerary.

The maps cover
implemented feature paths and significant decision / recovery branches, rather
than every combination of arbitrary input, deployment or error conditions.
They are documentation, not newly implemented application features. Dashed arrows
indicate feedback or external human steps; role colors are not severity ratings.

## Editable source and rebuild

- `build.py` contains the reviewed workflow definitions.
- `diagrams/*.dot` are editable Graphviz sources; `diagrams/*.svg` are standalone
  vector diagrams. Regenerating overwrites these generated files.
- `WORKFLOWS.md` contains equivalent Mermaid diagrams, notes and code references.
- The remediation lifecycle edges are generated from the actual
  `phylax/remediation_lifecycle.py` transition map.

To rebuild after reviewing workflow semantics against current code:

```bash
python3 docs/workflows/build.py
```

Rebuilding requires Graphviz `dot` on `/usr/bin` or `/usr/local/bin`. Viewing the
HTML, SVG or PNG files requires no packages or internet connection. No database,
feed, capture, scan or model is opened by the generator. For local HTTP viewing,
serve this documentation directory on loopback only:

```bash
python3 -m http.server 8877 --bind 127.0.0.1 --directory docs/workflows
```

Then open `http://127.0.0.1:8877/`. Stop with Ctrl+C. This is a documentation
viewer, separate from the Phylax dashboard.

## Maintaining the diagrams

After changes to application workflows, update `build.py` and rebuild the atlas.
Check generated SVGs, source references, lifecycle transitions, and navigation
at desktop and mobile widths. The diagrams document behavior; they are not
performance benchmarks or evidence of a deployment certification.
