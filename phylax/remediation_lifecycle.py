"""Shared lifecycle choices; backend validation remains authoritative."""

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
