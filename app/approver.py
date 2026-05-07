# Approve - triggers report generation
@main.route('/reviews/<int:id>/approve', methods=['POST'])
@login_required
@role_required('approver')
def approve_review(id):
    review = UARReview.query.get_or_404(id)
    review.status = 'APPROVED'
    review.approved_at = datetime.utcnow()
    db.session.commit()
    audit_log('REVIEW_APPROVED', 'uar_reviews', review.id)
    generate_remediation_report(review)   # auto-generates report
    return redirect(url_for('main.review_complete', id=id))

