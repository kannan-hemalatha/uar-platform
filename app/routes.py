# app/routes.py
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, abort, jsonify)
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime
from app import db
from app.models import User, UARReview, UAREntry, AuditLog
from app.audit import audit_log
from app.workflow import validate_sod, submit_review
from app.upload import upload_to_gcs, parse_and_validate
from app.report import generate_remediation_report

main = Blueprint('main', __name__)


# ── RBAC decorator ────────────────────────────────────────────────────
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── INITIATOR ROUTES ──────────────────────────────────────────────────
@main.route('/')
@login_required
def dashboard():
    """Initiator dashboard - shows all reviews they submitted."""
    reviews = UARReview.query.filter_by(
        initiator_id=current_user.id).order_by(
        UARReview.created_at.desc()).all()
    return render_template('initiator/dashboard.html', reviews=reviews)

@main.route('/new-review', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def new_review():
    """Create a new UAR review cycle."""
    eligible_users = User.query.filter(
        User.is_active == True,
        User.id != current_user.id
    ).all()

    if request.method == 'POST':
        title       = request.form.get('title')
        reviewer_id = int(request.form.get('reviewer_id'))
        approver_id = int(request.form.get('approver_id'))

        sod_errors = validate_sod(current_user.id, reviewer_id, approver_id)
        if sod_errors:
            return render_template('initiator/new_review.html',
                                   sod_errors=sod_errors,
                                   eligible_users=eligible_users)

        review = UARReview(
            title        = title,
            initiator_id = current_user.id,
            reviewer_id  = reviewer_id,
            approver_id  = approver_id,
            status       = 'PENDING'
        )
        db.session.add(review)
        db.session.commit()
        audit_log('REVIEW_CREATED', 'uar_reviews', review.id)
        return redirect(url_for('main.upload_file', review_id=review.id))

    return render_template('initiator/new_review.html',
                           sod_errors=[],
                           eligible_users=eligible_users)


@main.route('/review/<int:review_id>/upload', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def upload_file(review_id):
    """Upload CSV or Excel file for an existing review."""
    review = UARReview.query.get_or_404(review_id)
    validation_errors = []

    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            validation_errors.append('No file selected')
            return render_template('initiator/upload.html',
                                   validation_errors=validation_errors)

        gcs_uri = upload_to_gcs(file, file.filename)
        df, errors = parse_and_validate(gcs_uri)

        if errors:
            return render_template('initiator/upload.html',
                                   validation_errors=errors)

        # Save all entries to the database
        for _, row in df.iterrows():
            entry = UAREntry(
                review_id    = review_id,
                account_name = row['account_name'],
                current_role = row['current_role'],
                system       = row['system'],
                last_login   = str(row.get('last_login', ''))
            )
            db.session.add(entry)
        db.session.commit()
        audit_log('FILE_UPLOADED', 'uar_reviews', review_id)

        # Submit the review and notify the Reviewer
        submit_review(review_id, current_user.id)
        flash('Review submitted successfully. Reviewer has been notified.')
        return redirect(url_for('main.dashboard'))

    return render_template('initiator/upload.html', validation_errors=[])


# ── REVIEWER ROUTES ───────────────────────────────────────────────────
@main.route('/reviewer/queue')
@login_required
@role_required('reviewer')
def reviewer_queue():
    """Show all reviews assigned to this Reviewer."""
    reviews = UARReview.query.filter_by(
        reviewer_id=current_user.id,
        status='IN_REVIEW'
    ).all()
    return render_template('reviewer/queue.html', reviews=reviews)


@main.route('/review/<int:review_id>/decide', methods=['GET', 'POST'])
@login_required
@role_required('reviewer')
def review_decide(review_id):
    """Reviewer makes decisions on each entry."""
    review  = UARReview.query.get_or_404(review_id)
    entries = UAREntry.query.filter_by(review_id=review_id).all()


    if request.method == 'POST':
        for entry in entries:
            decision = request.form.get(f'decision_{entry.id}')
            comment  = request.form.get(f'comment_{entry.id}', '')
            old      = entry.decision
            entry.decision   = decision
            entry.comment    = comment
            entry.decided_at = datetime.utcnow()
            audit_log('DECISION_SAVED', 'uar_entries', entry.id,
                      old_value=old, new_value=decision)
        review.status       = 'PENDING_APPROVAL'
        review.completed_at = datetime.utcnow()
        db.session.commit()
        audit_log('REVIEW_SUBMITTED', 'uar_reviews', review.id)
        flash('Review submitted for approval.')
        return redirect(url_for('main.reviewer_queue'))

    return render_template('reviewer/review_queue.html',
                           review=review, entries=entries)


# ── APPROVER ROUTES ───────────────────────────────────────────────────
@main.route('/approver/queue')
@login_required
@role_required('approver')
def approver_queue():
    """Show all reviews waiting for this Approver."""
    reviews = UARReview.query.filter_by(
        approver_id=current_user.id,
        status='PENDING_APPROVAL'
    ).all()
    return render_template('approver/queue.html', reviews=reviews)


@main.route('/review/<int:review_id>/approve-view')
@login_required
@role_required('approver')
def approve_view(review_id):
    """Approver read-only summary view."""
    review  = UARReview.query.get_or_404(review_id)
    entries = UAREntry.query.filter_by(review_id=review_id).all()
    return render_template('approver/approver_view.html',
                           review=review, entries=entries)


@main.route('/reviews/<int:id>/approve', methods=['POST'])
@login_required
@role_required('approver')
def approve_review(id):
    """Approve a review and generate the remediation report."""
    review             = UARReview.query.get_or_404(id)
    review.status      = 'APPROVED'
    review.approved_at = datetime.utcnow()
    db.session.commit()
    audit_log('REVIEW_APPROVED', 'uar_reviews', review.id)
    generate_remediation_report(review)
    flash('Review approved. Remediation report generated.')
    return redirect(url_for('main.approver_queue'))


@main.route('/reviews/<int:id>/reject', methods=['POST'])
@login_required
@role_required('approver')
def reject_review(id):
    """Reject a review with a mandatory written reason."""
    review               = UARReview.query.get_or_404(id)
    reason               = request.form.get('reason', '').strip()
    if not reason:
        flash('Rejection reason is required.')
        return redirect(url_for('main.approve_view', review_id=id))
    review.status        = 'REJECTED'
    review.reject_reason = reason
    db.session.commit()
    audit_log('REVIEW_REJECTED', 'uar_reviews', review.id,
              new_value=reason)
    flash('Review rejected and returned to Reviewer.')
    return redirect(url_for('main.approver_queue'))


# ── ADMIN ROUTES ──────────────────────────────────────────────────────
@main.route('/admin/users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_users():
    """Admin user management - list all users."""
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=users)


@main.route('/admin/users/<int:id>/role', methods=['POST'])
@login_required
@role_required('admin')
def change_role(id):
    """Change a user's role."""
    valid_roles = ['initiator','reviewer','approver','admin','developer']
    user        = User.query.get_or_404(id)
    new_role    = request.form.get('role')
    if new_role not in valid_roles:
        flash('Invalid role selected.')
        return redirect(url_for('main.admin_users'))
    old_role   = user.role
    user.role  = new_role
    db.session.commit()
    audit_log('ROLE_CHANGED', 'users', user.id,
              old_value=old_role, new_value=new_role)
    flash(f'Role updated for {user.username}.')
    return redirect(url_for('main.admin_users'))


@main.route('/admin/users/<int:id>/deactivate', methods=['POST'])
@login_required
@role_required('admin')
def deactivate_user(id):
    """Deactivate a user account."""
    user           = User.query.get_or_404(id)
    user.is_active = False
    db.session.commit()
    audit_log('USER_DEACTIVATED', 'users', user.id)
    flash(f'{user.username} has been deactivated.')
    return redirect(url_for('main.admin_users'))


# ── AUDIT LOG VIEW (optional - useful for testing) ────────────────────
@main.route('/admin/audit')
@login_required
@role_required('admin')
def audit_view():
    """Admin view of the full audit log."""
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('admin/audit.html', logs=logs)

