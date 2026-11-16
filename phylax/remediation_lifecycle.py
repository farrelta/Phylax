"""Shared lifecycle choices; backend validation remains authoritative."""

from .remediation import CONFIRMED

ADVANCES = {'Recommended', 'Approved', 'Implemented', 'Verified'}

TRANSITIONS = {
    'Recommended': ('Under Review', 'Rejected', 'Deferred', 'Needs More Evidence'),
    'Under Review': ('Recommended', 'Approved', 'Rejected', 'Deferred', 'Needs More Evidence'),
    'Approved': ('Under Review', 'Implemented', 'Rejected', 'Deferred'),
    'Implemented': ('Under Review', 'Verified', 'Deferred'),
    'Rejected': ('Recommended', 'Under Review'),
    'Deferred': ('Recommended', 'Under Review'),
    'Needs More Evidence': ('Recommended', 'Under Review'),
    'Verified': ('Under Review',),
}


def plan_review_block(item):
    if item.get('finding_status') != CONFIRMED:
        return 'Confirm that this finding applies before advancing the fix plan.'
    revision = item['plan'].get('finding_revision')
    if not revision or revision != item.get('current_finding_revision'):
        return 'Generate a replacement plan using the current finding evidence before advancing.'
    return ''
