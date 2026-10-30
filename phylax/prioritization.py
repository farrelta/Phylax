"""Transparent local urgency rules, separate from source severity/applicability."""
from __future__ import annotations
from typing import Any


def prioritize(asset: dict[str, Any], vulnerability: dict[str, Any], status: str) -> dict[str, Any]:
    applicable = status in {'CONFIRMED_MATCH','POTENTIAL_MATCH'}
    severity = str(vulnerability.get('severity') or 'unknown').casefold()
    zone = asset.get('zone','unknown')
    factors = [
        {'input':'KEV membership','value':bool(vulnerability.get('kev')),'points':3 if vulnerability.get('kev') else 0},
        {'input':'Source severity','value':severity,'points':{'critical':3,'high':2,'medium':1}.get(severity,0)},
        {'input':'Asset criticality','value':asset.get('criticality','unknown'),'points':{'critical':3,'high':2,'medium':1}.get(asset.get('criticality'),0)},
        {'input':'Confirmed applicability','value':status,'points':2 if status=='CONFIRMED_MATCH' else 0},
        {'input':'Network zone','value':zone,'points':1 if zone=='DMZ' else 0},
        {'input':'Verified vendor fix','value':'unknown; source text is not verification','points':0},
    ]
    score = sum(f['points'] for f in factors) if applicable else None
    priority = 'not_applicable' if score is None else 'critical' if score >= 8 else 'high' if score >= 6 else 'medium' if score >= 3 else 'low'
    missing = []
    if severity == 'unknown': missing.append('Source severity is missing; no CVSS or exploit probability was inferred.')
    if zone == 'unknown': missing.append('Network zone is unknown.')
    missing.append('No verified vendor fix state is stored. Observed communication does not prove reachability or exploitation.')
    return {'priority':priority,'score':score,'factors':factors,'uncertainty':missing,'rule_version':'2'}
