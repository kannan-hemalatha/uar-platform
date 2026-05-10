# app/report.py
from app.models import UAREntry
from datetime import datetime


def generate_remediation_report(review):
    """
    Auto-generates a remediation report when an Approver approves a review.
    Collects all entries where decision is REMOVE_ROLE or DEACTIVATE.
    """
    entries = UAREntry.query.filter_by(review_id=review.id).all()
    remediation = [
        {
            'account_name': e.account_name,
            'current_role': e.current_role,
            'system':       e.system,
            'decision':     e.decision,
            'comment':      e.comment,
            'decided_at':   str(e.decided_at),
        }
        for e in entries
        if e.decision in ('REMOVE_ROLE', 'DEACTIVATE')
    ]

    report = {
        'review_id':    review.id,
        'review_title': review.title,
        'approved_at':  str(review.approved_at),
        'approver_id':  review.approver_id,
        'total_entries':         len(entries),
        'remediation_count':     len(remediation),
        'remediation_entries':   remediation,
    }

    # Print to console for now - in Sprint 5 save to GCS or DB
    print(f'[REPORT] Review {review.id} approved.')
    print(f'[REPORT] {len(remediation)} accounts require remediation.')
    return report

