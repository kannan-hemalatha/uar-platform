# app/workflow.py — SoD validation
def validate_sod(initiator_id, reviewer_id, approver_id):
    errors = []
    if initiator_id == reviewer_id: errors.append('Initiator and Reviewer must differ')
    if reviewer_id  == approver_id: errors.append('Reviewer and Approver must differ')
    if initiator_id == approver_id: errors.append('Initiator and Approver must differ')
    return errors

# Status flow: PENDING → IN_REVIEW → APPROVED or REJECTED
def submit_review(review_id, current_user_id):
    review = UARReview.query.get_or_404(review_id)
    review.status = 'IN_REVIEW'
    db.session.commit()
    audit_log('REVIEW_SUBMITTED', 'uar_reviews', review.id)
    send_reviewer_notification(review)   # triggers email to Reviewer

