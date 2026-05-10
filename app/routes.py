# app/routes.py - role enforcement decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if current_user.role not in roles: abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator

Write Reviewer decision API - PATCH /entries/{id}/decision

@main.route('/entries/<int:entry_id>/decision', methods=['PATCH'])
@login_required
@role_required('reviewer')
def save_decision(entry_id):
    entry = UAREntry.query.get_or_404(entry_id)
    data = request.get_json()
    old = entry.decision
    entry.decision = data['decision']   # RETAIN / REMOVE_ROLE / DEACTIVATE
    entry.comment  = data.get('comment','')
    entry.decided_at = datetime.utcnow()
    db.session.commit()
    audit_log('DECISION_SAVED', 'uar_entries', entry.id, old, entry.decision)
    return jsonify({'status': 'ok'})

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

# Admin can create, update, deactivate users and change role assignments
@main.route('/admin/users', methods=['GET','POST'])
@login_required
@role_required('admin')
def manage_users(): ...

@main.route('/admin/users/<int:id>/role', methods=['POST'])
@login_required
@role_required('admin')
def change_role(id): ...

