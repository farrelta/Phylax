# Phylax documentation

These guides describe the current implementation. Run all commands from the repository root. Use the same `--db` path for dashboard, imports, watcher, and scanner worker when they should share data.

## Read in order

1. [Setup](setup.md): start locally, configure secrets, and understand storage and upgrades.
2. [Operator guide](operator-guide.md): use the dashboard from inventory through investigation and reporting.
3. [Intelligence](intelligence.md): understand source freshness, matching evidence, and priority.
4. [Monitoring and discovery](monitoring.md): import passive evidence, configure policy, and permit bounded IT discovery.
5. [Architecture and security](architecture.md): understand data flow, hosted-data boundaries, and coverage limits.
6. [Testing and demonstration](testing.md): run deterministic checks and rehearse the fictional support-site scenario.

## Visual reference

The [workflow atlas](workflows/index.html) contains 14 offline diagrams. Its [Mermaid version](workflows/WORKFLOWS.md) is readable on GitHub. The [atlas guide](workflows/README.md) explains rebuilding with Graphviz; Graphviz is not an application dependency.
