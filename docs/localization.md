# Interface languages

Phylax supports **English** and **Bahasa Indonesia** without a translation service or extra dependencies. Use the language selector at the top of any dashboard page, then select **Apply language / Terapkan bahasa**. The preference is saved in a host-only cookie for one year. Before a preference is saved, the dashboard uses the browser's supported language preference, falling back to English.

The selection applies across overview and finding detail, inventory and asset editing, monitoring and event evidence, topology, CVE intelligence and ICS advisories, triage, remediation plans, management approvals, discovery, software review, asset changes, operational context, policy, settings, glossary, reports, and job progress pages. It includes labels, accessible descriptions, empty states, pagination, application-generated evidence explanations, success notices, validation messages, and workflow status labels.

Markdown reports use the selected interface language. JSON, report CSV, and inventory CSV retain their canonical schemas and values for interchange. Dates retain their recorded UTC representation. External advisories, vendor guidance, AI responses, operator-entered content, technical identifiers, policy JSON, and raw evidence retain their original text.

## Implementation and maintenance

- `phylax/locales/id.json` maps English application text to Indonesian. Numeric placeholders such as `{0}` capture dynamic values in application messages; translations must retain each placeholder.
- `phylax/i18n.py` selects the request language and translates rendered text and accessible labels at the HTTP response boundary. Every route shares this boundary, including validation and job views. No global mutable language state or database migration is required.
- Form names, values, routes, tokens, CSS, SVG coordinates, and internal states are preserved. Language selection is a CSRF-protected POST that redirects locally.
- Raw records, code, and editable textareas are excluded from translation. Mark external text with `translate="no"`, or use `ui.verbatim()` for escaped HTML text. Keep application-generated labels outside these protected elements. SVG identity labels use `translate="no"` directly on the SVG text element.
- Add catalog entries when introducing application text. Prefer a complete sentence or a message template to preserve natural Indonesian word order. Runtime captions can combine independently translated sentences and facts separated by ` · `.
- Background work retains canonical messages; each viewer sees the language of their own request. Localizing a display never changes applicability, prioritization, permissions, or lifecycle transitions.

Run the localization and full regression checks from the repository root:

```bash
python3 -m unittest discover -s tests -p test_localization.py -v
python3 -m unittest discover -s tests -v
```

The localization checks exercise every page in both languages, compare functional HTML attributes, check placeholder integrity, and cover preference persistence, redirects, request protections, failed submissions, canonical workflow values, job progress, and exports.
