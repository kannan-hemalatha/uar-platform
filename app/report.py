# app/report.py — report generator
def generate_remediation_report(review):
    entries = UAREntry.query.filter_by(review_id=review.id).all()
    remediation = [e for e in entries if e.decision in ('REMOVE_ROLE','DEACTIVATE')]
    # Saves report to DB or GCS; available for download on approval screen

