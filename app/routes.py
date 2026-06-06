# app/routes.py
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, abort, Response, session)  # DEF-020/021: session for staged upload
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from app import db
from app.models import (User, UARReview, UAREntry, AuditLog,
                        SystemConfig, RevisionHistory)
from app.audit import audit_log
from app.workflow import (validate_sod, submit_review, submit_for_approval,
                          send_reviewer_notification)
from app.upload import upload_to_gcs, parse_and_validate
from app.report import generate_remediation_report
from flask import jsonify, request
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

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
    """Initiator dashboard - view all reviews I have created."""
    # DEF-029 FIX: '/' previously rendered the initiator dashboard (with the
    # '+ New Review' button) for every role. Redirect non-initiators to their
    # own home so reviewers/approvers never see initiator-only actions.
    if current_user.role == 'reviewer':
        return redirect(url_for('main.reviewer_queue'))
    if current_user.role == 'approver':
        return redirect(url_for('main.approver_queue'))
    if current_user.role == 'admin':
        return redirect(url_for('main.admin_users'))

    # DEF-031 FIX: support sortable dashboard via ?sort=&dir= query params.
    sort = request.args.get('sort', 'created_at')
    direction = request.args.get('dir', 'desc')
    sortable = {
        'title': UARReview.title,
        'status': UARReview.status,
        'created_at': UARReview.created_at,
    }
    col = sortable.get(sort, UARReview.created_at)
    col = col.asc() if direction == 'asc' else col.desc()
    reviews = UARReview.query.filter_by(
        initiator_id=current_user.id).order_by(col).all()
    return render_template('initiator/dashboard.html', reviews=reviews,
                           sort=sort, dir=direction)


@main.route('/new-review', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def new_review():
    """Create a new UAR review - choose manual entry or file upload."""
    # DEF-022 FIX: separate role-specific eligible lists (was a single mixed
    # list of initiator/reviewer/approver for both dropdowns).
    eligible_reviewers = User.query.filter(
        User.is_active == True,
        User.id != current_user.id,
        User.role == 'reviewer'
    ).order_by(User.username).all()
    eligible_approvers = User.query.filter(
        User.is_active == True,
        User.id != current_user.id,
        User.role == 'approver'
    ).order_by(User.username).all()

    if request.method == 'POST':
        title        = request.form.get('title', '').strip()
        reviewer_id  = request.form.get('reviewer_id', '')
        approver_id  = request.form.get('approver_id', '')
        entry_method = request.form.get('entry_method', 'upload')

        # Validate required fields
        if not title or not reviewer_id or not approver_id:
            flash('Review title, Reviewer, and Approver are all required.')
            return render_template('initiator/new_review.html',
                                   sod_errors=[],
                                   eligible_reviewers=eligible_reviewers,  # DEF-022
                                   eligible_approvers=eligible_approvers,  # DEF-022
                                   form_data=request.form)

        reviewer_id = int(reviewer_id)
        approver_id = int(approver_id)

        # SoD validation
        sod_errors = validate_sod(current_user.id, reviewer_id, approver_id)
        if sod_errors:
            return render_template('initiator/new_review.html',
                                   sod_errors=sod_errors,
                                   eligible_reviewers=eligible_reviewers,  # DEF-022
                                   eligible_approvers=eligible_approvers,  # DEF-022
                                   form_data=request.form)

        # Create the review record
        review = UARReview(
            title=title, initiator_id=current_user.id,
            reviewer_id=reviewer_id, approver_id=approver_id,
            status='PENDING')
        db.session.add(review)
        db.session.commit()
        audit_log('REVIEW_CREATED', 'uar_reviews', review.id)

        # Route to the chosen data entry method
        if entry_method == 'manual':
            return redirect(url_for('main.add_entries',
                                    review_id=review.id))
        else:
            return redirect(url_for('main.upload_file',
                                    review_id=review.id))

    return render_template('initiator/new_review.html',
                           sod_errors=[],
                           eligible_reviewers=eligible_reviewers,  # DEF-022
                           eligible_approvers=eligible_approvers,  # DEF-022
                           form_data=None)


@main.route('/review/<int:review_id>/upload', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def upload_file(review_id):
    """DEF-019/020/021 FIX: Step 1 of the staged upload flow. Accepts the file,
    stores it, runs alias-based column mapping + duplicate detection, then
    sends the Initiator to the mapping-review screen (instead of silently
    importing and auto-submitting)."""
    review = UARReview.query.get_or_404(review_id)
    if review.initiator_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            return render_template('initiator/upload.html',
                                   validation_errors=['No file selected'])

        uri = upload_to_gcs(file, file.filename)
        from app.upload import analyze_upload
        analysis = analyze_upload(uri)

        # DEF-020/021 FIX: stash the file URI + analysis in the session so the
        # Initiator can review/adjust the mapping and confirm before any data
        # is written or submitted. Nothing is imported yet at this stage.
        session[f'upload_uri_{review_id}'] = uri
        audit_log('FILE_UPLOADED', 'uar_reviews', review_id,
                  new_value=f'{file.filename}; {analysis["row_count"]} rows')
        return redirect(url_for('main.upload_mapping', review_id=review_id))

    return render_template('initiator/upload.html', validation_errors=[])


@main.route('/review/<int:review_id>/upload/mapping', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def upload_mapping(review_id):
    """DEF-019/020 FIX: mapping-review screen. The Initiator sees the
    auto-detected column->field mapping, any duplicate columns, and unmapped/
    missing required fields, and can adjust the mapping before proceeding."""
    review = UARReview.query.get_or_404(review_id)
    if review.initiator_id != current_user.id:
        abort(403)

    uri = session.get(f'upload_uri_{review_id}')
    if not uri:
        flash('Please upload a file first.')
        return redirect(url_for('main.upload_file', review_id=review_id))

    from app.upload import analyze_upload, build_rows
    analysis = analyze_upload(uri)

    if request.method == 'POST':
        # Build the confirmed mapping from the per-column dropdowns.
        mapping = {}
        for col in analysis['source_columns']:
            mapping[col] = request.form.get(f'map_{col}', '').strip()

        # DEF-020 FIX: validate the confirmed mapping covers all required
        # fields and contains no duplicate target assignments.
        chosen = [t for t in mapping.values() if t]
        dup_targets = {t for t in chosen if chosen.count(t) > 1}
        missing = [f for f in analysis['required_fields']
                   if f not in chosen]

        errors = []
        if dup_targets:
            errors.append('Each field may be mapped only once. Duplicate '
                          'mapping for: ' + ', '.join(sorted(dup_targets)))
        if missing:
            errors.append('All required fields must be mapped. Missing: '
                          + ', '.join(missing))

        if errors:
            for e in errors:
                flash(e)
            return render_template('initiator/upload_mapping.html',
                                   review=review, analysis=analysis,
                                   current_mapping=mapping)

        # Mapping is valid -> build the preview rows and go to preview/edit.
        rows, row_errors = build_rows(uri, mapping)
        session[f'upload_mapping_{review_id}'] = mapping
        session[f'upload_rows_{review_id}'] = rows
        audit_log('UPLOAD_MAPPING_CONFIRMED', 'uar_reviews', review_id,
                  new_value=str({k: v for k, v in mapping.items() if v}))
        return redirect(url_for('main.upload_preview', review_id=review_id))

    return render_template('initiator/upload_mapping.html',
                           review=review, analysis=analysis,
                           current_mapping=analysis['auto_mapping'])


@main.route('/review/<int:review_id>/upload/preview', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def upload_preview(review_id):
    """DEF-020/021 FIX: preview/edit screen. Lists the parsed entries and lets
    the Initiator add / edit / remove rows, then explicitly confirm before
    submission. No auto-submit."""
    review = UARReview.query.get_or_404(review_id)
    if review.initiator_id != current_user.id:
        abort(403)

    rows = session.get(f'upload_rows_{review_id}')
    if rows is None:
        flash('Please upload and map a file first.')
        return redirect(url_for('main.upload_file', review_id=review_id))

    from app.upload import REQUIRED_COLS, ALL_TARGET_FIELDS

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'remove':
            idx = int(request.form.get('row_index', -1))
            if 0 <= idx < len(rows):
                rows.pop(idx)
            session[f'upload_rows_{review_id}'] = rows
            flash('Entry removed.')
            return redirect(url_for('main.upload_preview', review_id=review_id))

        if action == 'edit':
            idx = int(request.form.get('row_index', -1))
            if 0 <= idx < len(rows):
                for f in ALL_TARGET_FIELDS:
                    rows[idx][f] = request.form.get(f, '').strip()
            session[f'upload_rows_{review_id}'] = rows
            flash('Entry updated.')
            return redirect(url_for('main.upload_preview', review_id=review_id))

        if action == 'add':
            new_row = {f: request.form.get(f, '').strip()
                       for f in ALL_TARGET_FIELDS}
            rows.append(new_row)
            session[f'upload_rows_{review_id}'] = rows
            flash('Entry added.')
            return redirect(url_for('main.upload_preview', review_id=review_id))

        if action == 'confirm':
            # DEF-021 FIX: explicit confirmation step. Validate, persist the
            # entries, then submit — and only here show a success message.
            if not rows:
                flash('Add at least one entry before submitting.')
                return redirect(url_for('main.upload_preview',
                                        review_id=review_id))

            row_errors = []
            for n, r in enumerate(rows, 1):
                miss = [f for f in REQUIRED_COLS if not r.get(f)]
                if miss:
                    row_errors.append(f'Entry {n}: missing {", ".join(miss)}')
            if row_errors:
                for e in row_errors:
                    flash(e)
                return redirect(url_for('main.upload_preview',
                                        review_id=review_id))

            for r in rows:
                entry = UAREntry(
                    review_id     = review_id,
                    account_name  = r.get('account_name', ''),
                    current_role  = r.get('current_role', ''),
                    system        = r.get('system', ''),
                    last_login    = r.get('last_login', ''),
                    justification = r.get('justification', ''))
                db.session.add(entry)
            db.session.commit()
            audit_log('ENTRIES_IMPORTED', 'uar_reviews', review_id,
                      new_value=f'{len(rows)} entries imported via file upload')

            # Clear the staged session data.
            for k in (f'upload_uri_{review_id}', f'upload_mapping_{review_id}',
                      f'upload_rows_{review_id}'):
                session.pop(k, None)

            submit_review(review_id, current_user.id)
            # DEF-021 FIX: explicit success confirmation message.
            flash(f'Success: {len(rows)} entries imported and the review has '
                  f'been submitted. The Reviewer has been notified by email.')
            return redirect(url_for('main.dashboard'))

    return render_template('initiator/upload_preview.html',
                           review=review, rows=rows,
                           required_fields=REQUIRED_COLS,
                           all_fields=ALL_TARGET_FIELDS)


@main.route('/review/<int:review_id>/add-entry', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def add_entries(review_id):
    """Manual guided data entry - FR-01, FR-02, FR-03."""
    review  = UARReview.query.get_or_404(review_id)
    entries = UAREntry.query.filter_by(review_id=review_id).all()

    if request.method == 'POST':
        account_name  = request.form.get('account_name', '').strip()
        current_role  = request.form.get('current_role', '').strip()
        system        = request.form.get('system', '').strip()
        last_login    = request.form.get('last_login', '').strip()
        justification = request.form.get('justification', '').strip()

        # FR-03 - field-level validation of required fields
        errors = []
        if not account_name:
            errors.append('Account Name is required.')
        if not current_role:
            errors.append('Current Role is required.')
        if not system:
            errors.append('System / Application is required.')
        if not last_login:
            errors.append('Last Login Date is required.')

        if errors:
            for e in errors:
                flash(e)
            return render_template('initiator/add_entries.html',
                                   review=review, entries=entries)

        entry = UAREntry(
            review_id     = review_id,
            account_name  = account_name,
            current_role  = current_role,
            system        = system,
            last_login    = last_login,
            justification = justification)
        db.session.add(entry)
        db.session.commit()
        audit_log('ENTRY_ADDED', 'uar_entries', entry.id,
                  new_value=account_name)
        flash(f'Entry for {account_name} added successfully.')
        return redirect(url_for('main.add_entries', review_id=review_id))

    return render_template('initiator/add_entries.html',
                           review=review, entries=entries)


@main.route('/review/<int:review_id>/remove-entry/<int:entry_id>',
            methods=['POST'])
@login_required
@role_required('initiator')
def remove_entry(review_id, entry_id):
    """Remove a manually entered entry before submission - FR-18."""
    entry = UAREntry.query.get_or_404(entry_id)
    account_name = entry.account_name
    db.session.delete(entry)
    db.session.commit()
    audit_log('ENTRY_REMOVED', 'uar_entries', entry_id,
              old_value=account_name)
    flash(f'Entry for {account_name} removed.')
    return redirect(url_for('main.add_entries', review_id=review_id))


@main.route('/review/<int:review_id>/submit-manual', methods=['POST'])
@login_required
@role_required('initiator')
def submit_manual(review_id):
    """Submit a manually entered review for the Reviewer - FR-21."""
    review  = UARReview.query.get_or_404(review_id)
    entries = UAREntry.query.filter_by(review_id=review_id).all()

    if not entries:
        flash('You must add at least one entry before submitting.')
        return redirect(url_for('main.add_entries', review_id=review_id))

    submit_review(review_id, current_user.id)
    flash('Review submitted successfully. Reviewer has been notified.')
    return redirect(url_for('main.dashboard'))


@main.route('/review/<int:review_id>/revise', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def revise_review(review_id):
    review  = UARReview.query.get_or_404(review_id)
    entries = UAREntry.query.filter_by(review_id=review_id).all()

    if review.initiator_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        for entry in entries:
            for field in ['account_name', 'current_role', 'system',
                          'last_login', 'justification']:
                new_val = request.form.get(f'{field}_{entry.id}',
                                            getattr(entry, field))
                old_val = getattr(entry, field)
                if old_val != new_val:
                    rev = RevisionHistory(
                        entry_id=entry.id, review_id=review_id,
                        field_name=field,
                        old_value=str(old_val),
                        new_value=str(new_val),
                        changed_by=current_user.id)
                    db.session.add(rev)
                setattr(entry, field, new_val)
        db.session.commit()
        audit_log('ENTRIES_REVISED', 'uar_reviews', review_id)

        if request.form.get('action') == 'submit':
            submit_review(review_id, current_user.id)
            flash('Review revised and resubmitted successfully.')
            return redirect(url_for('main.dashboard'))

        flash('Changes saved.')
        return redirect(url_for('main.revise_review', review_id=review_id))

    return render_template('initiator/revise.html',
                           review=review, entries=entries)


# ── REVIEWER ROUTES ───────────────────────────────────────────────────
@main.route('/reviewer/queue')
@login_required
@role_required('reviewer')
def reviewer_queue():
    """Reviewer's queue - IN_REVIEW reviews (includes those returned
    by the Approver for rework) and historical reviews."""
    reviews = UARReview.query.filter_by(
        reviewer_id=current_user.id, status='IN_REVIEW').all()

    # Count of reviews that came back from the Approver for rework
    returned_count = sum(1 for r in reviews if r.reject_reason)

    # Historical reviews - completed list shows only states the Reviewer
    # has finished with. REJECTED is no longer terminal under Option 2,
    # so it does NOT appear here - it appears in the main queue instead.
    reviews_completed = UARReview.query.filter(
        UARReview.reviewer_id == current_user.id,
        UARReview.status.in_(['APPROVED', 'PENDING_APPROVAL'])
    ).order_by(UARReview.completed_at.desc()).all()

    return render_template('reviewer/queue.html',
                           reviews=reviews,
                           reviews_completed=reviews_completed,
                           returned_count=returned_count)


@main.route('/review/<int:review_id>/decide', methods=['GET', 'POST'])
# Removed @login_required - authenticated via token (email link) or session below
# Removed @role_required('reviewer') - role enforced via token / current_user check
def review_decide(review_id):
    from app.auth import verify_access_token
    token    = request.args.get('token') or request.form.get('token')
    reviewer = verify_access_token(token, review_id, 'reviewer') if token else None

    if reviewer is None and current_user.is_authenticated and current_user.role == 'reviewer':
        reviewer = current_user

    review = UARReview.query.get_or_404(review_id)
    if reviewer is None or review.reviewer_id != reviewer.id:
        abort(403)

    entries = UAREntry.query.filter_by(review_id=review_id).all()

    if review.status != 'IN_REVIEW':
        flash('This review is no longer in your queue.')
        return redirect(url_for('main.reviewer_queue'))

    if request.method == 'POST':
        for entry in entries:
            decision = request.form.get(f'decision_{entry.id}')
            comment  = request.form.get(f'comment_{entry.id}', '')
            old      = entry.decision
            entry.decision   = decision
            entry.comment    = comment
            entry.decided_at = datetime.utcnow()
            # DEF-018 FIX: include the reviewer's comment in the audit record
            # so the comment is captured under the DECISION_SAVED action
            # (previously only the decision value was logged).
            audit_log('DECISION_SAVED', 'uar_entries', entry.id,
                      old_value=old,
                      new_value=f'decision={decision}; comment={comment or "(none)"}',
                      actor_id=reviewer.id)

        # If this is a rework after Approver rejection, audit the rework
        # before clearing the reject_reason field
        was_rework = review.reject_reason is not None
        if was_rework:
            audit_log('REVIEW_RESUBMITTED_AFTER_REJECT',
                      'uar_reviews', review.id,
                      old_value=review.reject_reason,
                      new_value='resubmitted after rework')

        review.completed_at = datetime.utcnow()
        review.reject_reason = None     # clear - rework complete
        db.session.commit()
        audit_log('REVIEW_SUBMITTED', 'uar_reviews', review.id, actor_id=reviewer.id)
        submit_for_approval(review.id, reviewer.id)
        flash('Review completed and submitted for approval. '
              'Please log in to view all completed and pending reviews.')
        return redirect(url_for('auth.login', next=url_for('main.reviewer_queue')))

    return render_template('reviewer/review_queue.html',
                           review=review, entries=entries, access_token=token)


# ── APPROVER ROUTES ───────────────────────────────────────────────────
@main.route('/approver/queue')
@login_required
@role_required('approver')
def approver_queue():
    """Approver's queue - pending approval and historical reviews.
    REJECTED no longer appears here as a terminal state - under Option 2,
    rejection returns the review to the Reviewer's queue for rework."""
    reviews = UARReview.query.filter_by(
        approver_id=current_user.id, status='PENDING_APPROVAL').all()
    reviews_completed = UARReview.query.filter(
        UARReview.approver_id == current_user.id,
        UARReview.status == 'APPROVED'
    ).order_by(UARReview.approved_at.desc()).all()
    return render_template('approver/queue.html',
                           reviews=reviews,
                           reviews_completed=reviews_completed)


@main.route('/review/<int:review_id>/approve-view')
# Removed @login_required - authenticated via token (email link) or session below
# Removed @role_required('approver') - role enforced via token / current_user check
def approve_view(review_id):
    from app.auth import verify_access_token
    token    = request.args.get('token') or request.form.get('token')
    approver = verify_access_token(token, review_id, 'approver') if token else None

    if approver is None and current_user.is_authenticated and current_user.role == 'approver':
        approver = current_user

    review = UARReview.query.get_or_404(review_id)
    if approver is None or review.approver_id != approver.id:
        abort(403)

    entries = UAREntry.query.filter_by(review_id=review_id).all()
    return render_template('approver/approver_view.html',
                           review=review, entries=entries, access_token=token)


@main.route('/reviews/<int:id>/approve', methods=['POST'])
def approve_review(id):
    from app.auth import verify_access_token
    token    = request.form.get('token')
    approver = verify_access_token(token, id, 'approver') if token else None

    if approver is None and current_user.is_authenticated and current_user.role == 'approver':
        approver = current_user

    review = UARReview.query.get_or_404(id)
    if approver is None or review.approver_id != approver.id:
        abort(403)

    # DEF-006 FIX: prevent re-actioning a review that is no longer pending
    # approval (e.g. an already-approved review reached again via the email
    # token). Only PENDING_APPROVAL reviews may be approved.
    if review.status != 'PENDING_APPROVAL':
        flash('This review has already been actioned and can no longer '
              'be approved or rejected.')
        if current_user.is_authenticated:
            return redirect(url_for('main.approver_queue'))
        return redirect(url_for('auth.login'))

    review.status      = 'APPROVED'
    review.approved_at = datetime.utcnow()
    db.session.commit()
    audit_log('REVIEW_APPROVED', 'uar_reviews', review.id, actor_id=approver.id)
    generate_remediation_report(review)
    flash('Review approved. Remediation report generated.')
    return redirect(url_for('main.approver_queue'))


@main.route('/reviews/<int:id>/reject', methods=['POST'])
# Removed @login_required - authenticated via token (email link) or session below
# Removed @role_required('approver') - role enforced via token / current_user check
def reject_review(id):
    from app.auth import verify_access_token
    token    = request.form.get('token')
    approver = verify_access_token(token, id, 'approver') if token else None

    if approver is None and current_user.is_authenticated and current_user.role == 'approver':
        approver = current_user

    review = UARReview.query.get_or_404(id)
    if approver is None or review.approver_id != approver.id:
        abort(403)

    # DEF-006 FIX: only a review still pending approval may be rejected.
    # Blocks re-rejection of an already-approved/already-rejected cycle
    # reached again through the tokenized email link.
    if review.status != 'PENDING_APPROVAL':
        flash('This review has already been actioned and can no longer '
              'be approved or rejected.')
        if current_user.is_authenticated:
            return redirect(url_for('main.approver_queue'))
        return redirect(url_for('auth.login'))

    reason = request.form.get('reason', '').strip()

    if not reason:
        flash('Rejection reason is required.')
        return redirect(url_for('main.approve_view', review_id=id, token=token))

    # Return review to Reviewer's queue for rework
    review.status        = 'IN_REVIEW'
    review.reject_reason = reason
    review.completed_at  = None     # reset so Reviewer can resubmit
    db.session.commit()

    audit_log('REVIEW_REJECTED_TO_REVIEWER', 'uar_reviews', review.id,
              new_value=f'rejected by {approver.username}: {reason}', actor_id=approver.id)

    # Notify the Reviewer that the cycle is back with them for rework
    send_reviewer_notification(review)

    flash('Review rejected and returned to Reviewer. '
          'Reviewer has been notified by email.')
    return redirect(url_for('main.approver_queue'))


# ── SHARED - Report viewing for cycle participants ────────────────────
@main.route('/review/<int:id>/report')
@login_required
def view_report(id):
    """View the remediation report for a cycle you participated in."""
    review = UARReview.query.get_or_404(id)

    # Initiator, Reviewer, Approver of this cycle, or any Admin can view
    if current_user.role != 'admin' and current_user.id not in [
        review.initiator_id, review.reviewer_id, review.approver_id
    ]:
        abort(403)

    if review.status != 'APPROVED':
        flash('Report is only available after the review is approved.')
        return redirect(url_for('main.dashboard'))

    entries = UAREntry.query.filter_by(review_id=id).all()
    summary = {
        'total':       len(entries),
        'retain':      sum(1 for e in entries if e.decision == 'RETAIN'),
        'remove_role': sum(1 for e in entries
                           if e.decision == 'REMOVE_ROLE'),
        'deactivate':  sum(1 for e in entries
                           if e.decision == 'DEACTIVATE'),
    }
    remediation = [e for e in entries
                   if e.decision in ('REMOVE_ROLE', 'DEACTIVATE')]
    authorized_users = User.query.filter(
        User.is_active == True,
        User.role.in_(['initiator', 'reviewer', 'approver', 'admin'])
    ).order_by(User.username).all()

    return render_template('admin/remediation.html',
        review=review, summary=summary,
        remediation=remediation,
        authorized_users=authorized_users,
        is_admin_view=False)        # DEF-002: tells template to use participant URLs


# ── SHARED - Report export for cycle participants (DEF-002) ───────────
@main.route('/review/<int:id>/report/export')
@login_required
def view_report_export(id):
    """DEF-002 FIX: CSV/PDF export of the remediation report for any cycle
    participant (Initiator/Reviewer/Approver) or Admin. Previously only the
    admin-only /admin/cycles/<id>/remediation/export route existed, so the
    export buttons on the participant report view returned Forbidden."""
    review = UARReview.query.get_or_404(id)
    if current_user.role != 'admin' and current_user.id not in [
        review.initiator_id, review.reviewer_id, review.approver_id
    ]:
        abort(403)
    if review.status != 'APPROVED':
        flash('Report is only available after the review is approved.')
        return redirect(url_for('main.dashboard'))
    # Reuse the same export implementation as the admin route.
    return _build_remediation_export(review)


# ── ADMIN - User Management ───────────────────────────────────────────
@main.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=users)


@main.route('/admin/users/create', methods=['POST'])
@login_required
@role_required('admin')
def create_user_route():
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role     = request.form.get('role', '')
    valid_roles = ['initiator','reviewer','approver','admin','developer']

    if not username or not email or not password or role not in valid_roles:
        flash('All fields are required and role must be valid.')
        return redirect(url_for('main.admin_users'))

    existing = User.query.filter(
        (User.username == username) | (User.email == email)).first()
    if existing:
        flash('Username or email already exists.')
        return redirect(url_for('main.admin_users'))

    new_user = User(username=username, email=email,
                    password_hash=generate_password_hash(password),
                    role=role, is_active=True)
    db.session.add(new_user)
    db.session.commit()
    audit_log('USER_CREATED', 'users', new_user.id, new_value=username)
    flash(f'User {username} created successfully with role {role}.')
    return redirect(url_for('main.admin_users'))


@main.route('/admin/users/<int:id>/edit', methods=['GET'])
@login_required
@role_required('admin')
def edit_user_form(id):
    user = User.query.get_or_404(id)
    return render_template('admin/edit_user.html', user=user)


@main.route('/admin/users/<int:id>/edit', methods=['POST'])
@login_required
@role_required('admin')
def edit_user(id):
    user      = User.query.get_or_404(id)
    username  = request.form.get('username', '').strip()
    email     = request.form.get('email', '').strip()
    password  = request.form.get('password', '').strip()
    role      = request.form.get('role', '')
    is_active = request.form.get('is_active') == 'true'
    valid_roles = ['initiator','reviewer','approver','admin','developer']

    if not username or not email or role not in valid_roles:
        flash('Username, email, and a valid role are required.')
        return redirect(url_for('main.edit_user_form', id=id))

    duplicate = User.query.filter(
        (User.username == username) | (User.email == email),
        User.id != id).first()
    if duplicate:
        flash('That username or email is already used by another account.')
        return redirect(url_for('main.edit_user_form', id=id))

    changes = []
    if user.username != username:
        changes.append(f'username: {user.username} to {username}')
    if user.email != email:
        changes.append(f'email: {user.email} to {email}')
    if user.role != role:
        changes.append(f'role: {user.role} to {role}')
    if user.is_active != is_active:
        changes.append('status changed')

    user.username  = username
    user.email     = email
    user.role      = role
    user.is_active = is_active
    if password:
        user.password_hash = generate_password_hash(password)
        changes.append('password updated')

    db.session.commit()
    audit_log('USER_EDITED', 'users', user.id,
              new_value=', '.join(changes) if changes else 'no changes')
    flash(f'User {username} updated successfully.')
    return redirect(url_for('main.admin_users'))


@main.route('/admin/users/<int:id>/role', methods=['POST'])
@login_required
@role_required('admin')
def change_role(id):
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
    user           = User.query.get_or_404(id)
    user.is_active = False
    db.session.commit()
    audit_log('USER_DEACTIVATED', 'users', user.id)
    flash(f'{user.username} has been deactivated.')
    return redirect(url_for('main.admin_users'))


# ── ADMIN - All UAR Cycles oversight (FR-56) ──────────────────────────
@main.route('/admin/cycles')
@login_required
@role_required('admin')
def admin_all_cycles():
    status       = request.args.get('status', '')
    initiator_id = request.args.get('initiator_id', '')

    query = UARReview.query
    if status:
        query = query.filter_by(status=status)
    if initiator_id:
        query = query.filter_by(initiator_id=int(initiator_id))

    cycles = query.order_by(UARReview.created_at.desc()).all()

    # Metrics reflect the currently filtered cycles.
    # Under Option 2: "rework" = IN_REVIEW with a reject_reason set
    metrics = {
        'total':            len(cycles),
        'in_review':        sum(1 for c in cycles
                                if c.status == 'IN_REVIEW'
                                and not c.reject_reason),
        'in_rework':        sum(1 for c in cycles
                                if c.status == 'IN_REVIEW'
                                and c.reject_reason),
        'pending_approval': sum(1 for c in cycles
                                if c.status == 'PENDING_APPROVAL'),
        'approved':         sum(1 for c in cycles
                                if c.status == 'APPROVED'),
        'overdue':          sum(1 for c in cycles
                                if c.status in ['IN_REVIEW','PENDING_APPROVAL']
                                and c.created_at < 
                                    datetime.utcnow() - timedelta(days=7)
                                )
    }

    initiators = User.query.filter_by(role='initiator',
                                       is_active=True).all()

    return render_template('admin/all_cycles.html',
        cycles=cycles, metrics=metrics, initiators=initiators,
        filters={'status': status, 'initiator_id': initiator_id})


@main.route('/admin/cycles/<int:id>')
@login_required
@role_required('admin')
def admin_cycle_detail(id):
    review  = UARReview.query.get_or_404(id)
    entries = UAREntry.query.filter_by(review_id=id).all()
    return render_template('admin/cycle_detail.html',
                           review=review, entries=entries)


@main.route('/admin/cycles/<int:id>/remediation')
@login_required
@role_required('admin')
def admin_remediation(id):
    review  = UARReview.query.get_or_404(id)
    entries = UAREntry.query.filter_by(review_id=id).all()

    summary = {
        'total':       len(entries),
        'retain':      sum(1 for e in entries if e.decision == 'RETAIN'),
        'remove_role': sum(1 for e in entries
                           if e.decision == 'REMOVE_ROLE'),
        'deactivate':  sum(1 for e in entries
                           if e.decision == 'DEACTIVATE'),
    }
    remediation = [e for e in entries
                   if e.decision in ('REMOVE_ROLE', 'DEACTIVATE')]

    authorized_users = User.query.filter(
        User.is_active == True,
        User.role.in_(['initiator', 'reviewer', 'approver', 'admin'])
    ).order_by(User.username).all()

    return render_template('admin/remediation.html',
        review=review, summary=summary,
        remediation=remediation,
        authorized_users=authorized_users,
        is_admin_view=True)        # DEF-002: admin context -> admin URLs


@main.route('/admin/cycles/<int:id>/remediation/export')
@login_required
@role_required('admin')
def admin_remediation_export(id):
    """Export the remediation report as CSV or PDF (admin)."""
    review = UARReview.query.get_or_404(id)
    # DEF-002 FIX: shared export logic now lives in _build_remediation_export
    # so the participant report view can export the same way without hitting
    # this admin-only route.
    return _build_remediation_export(review)


def _build_remediation_export(review):
    """DEF-002 FIX: shared CSV/PDF remediation export used by both the admin
    route and the participant view_report_export route."""
    id      = review.id
    fmt     = request.args.get('format', 'csv')
    entries = UAREntry.query.filter_by(review_id=id).all()
    remediation = [e for e in entries
                   if e.decision in ('REMOVE_ROLE', 'DEACTIVATE')]

    if fmt == 'csv':
        import csv, io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['UAR Automation Platform - Remediation Report'])
        writer.writerow(['Title', review.title])
        writer.writerow(['Initiator', review.initiator.username])
        writer.writerow(['Reviewer', review.reviewer.username])
        writer.writerow(['Approver', review.approver.username])
        writer.writerow(['Initiated',
            review.created_at.strftime('%Y-%m-%d')])
        writer.writerow(['Approved',
            review.approved_at.strftime('%Y-%m-%d')
            if review.approved_at else ''])
        writer.writerow([])
        writer.writerow(['#','Account Name','System',
                         'Current Role','Decision','Comment'])
        for i, e in enumerate(remediation, 1):
            writer.writerow([i, e.account_name, e.system,
                             e.current_role, e.decision,
                             e.comment or ''])
        audit_log('REPORT_EXPORTED', 'uar_reviews', id,
                  new_value='format=csv')
        return Response(output.getvalue(), mimetype='text/csv',
            headers={'Content-Disposition':
                f'attachment; filename=remediation_{review.id}.csv'})

    elif fmt == 'pdf':
        import io
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (SimpleDocTemplate, Paragraph,
            Spacer, Table, TableStyle, PageBreak)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
            leftMargin=0.6*inch, rightMargin=0.6*inch,
            topMargin=0.6*inch, bottomMargin=0.6*inch)
        styles  = getSampleStyleSheet()
        title   = ParagraphStyle('title', parent=styles['Heading1'],
                                  fontSize=18, textColor=colors.HexColor('#1A1A1A'),
                                  spaceAfter=12)
        heading = ParagraphStyle('heading', parent=styles['Heading2'],
                                  fontSize=12, textColor=colors.HexColor('#404040'),
                                  spaceAfter=8)
        normal  = styles['Normal']

        story = []
        story.append(Paragraph('UAR Remediation Report', title))
        story.append(Paragraph(review.title, heading))
        story.append(Spacer(1, 12))

        # Review summary table
        summary_data = [
            ['Initiator', review.initiator.username],
            ['Reviewer', review.reviewer.username],
            ['Approver', review.approver.username],
            ['Initiated', review.created_at.strftime('%d %b %Y')],
            ['Completed', review.completed_at.strftime('%d %b %Y')
                          if review.completed_at else 'N/A'],
            ['Approved', review.approved_at.strftime('%d %b %Y')
                         if review.approved_at else 'N/A'],
        ]
        summary_table = Table(summary_data, colWidths=[1.5*inch, 4.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#EBEBEB')),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#1A1A1A')),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 16))

        # Decision counts
        retain = sum(1 for e in entries if e.decision == 'RETAIN')
        remove = sum(1 for e in entries if e.decision == 'REMOVE_ROLE')
        deact  = sum(1 for e in entries if e.decision == 'DEACTIVATE')
        story.append(Paragraph('Decision Summary', heading))
        counts_data = [
            ['Total Entries', 'Retain', 'Remove Role', 'Deactivate'],
            [str(len(entries)), str(retain), str(remove), str(deact)],
        ]
        counts_table = Table(counts_data, colWidths=[1.5*inch]*4)
        counts_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1A1A1A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(counts_table)
        story.append(Spacer(1, 16))

        # Remediation list
        story.append(Paragraph('Remediation Action List', heading))
        if remediation:
            rem_data = [['#', 'Account', 'System', 'Role',
                         'Decision', 'Comment']]
            for i, e in enumerate(remediation, 1):
                rem_data.append([
                    str(i),
                    e.account_name[:25],
                    e.system[:20],
                    e.current_role[:20],
                    e.decision.replace('_',' '),
                    (e.comment or '-')[:30],
                ])
            rem_table = Table(rem_data,
                colWidths=[0.4*inch, 1.4*inch, 1.2*inch,
                           1.2*inch, 1.1*inch, 1.7*inch])
            rem_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1A1A1A')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
                ('ROWBACKGROUNDS', (0,1), (-1,-1),
                    [colors.white, colors.HexColor('#F5F5F5')]),
            ]))
            story.append(rem_table)
        else:
            story.append(Paragraph(
                'No remediation actions required. '
                'All entries marked Retain Access.', normal))

        story.append(Spacer(1, 24))
        story.append(Paragraph(
            f'Generated by UAR Automation Platform on '
            f'{datetime.utcnow().strftime("%d %b %Y %H:%M UTC")}',
            ParagraphStyle('footer', parent=normal,
                fontSize=8, textColor=colors.HexColor('#666666'))))

        doc.build(story)
        buffer.seek(0)

        audit_log('REPORT_EXPORTED', 'uar_reviews', id,
                  new_value='format=pdf')
        return Response(buffer.getvalue(), mimetype='application/pdf',
            headers={'Content-Disposition':
                f'attachment; filename=remediation_{review.id}.pdf'})

    else:
        flash('Unsupported export format.')
        return redirect(url_for('main.admin_remediation', id=id))


@main.route('/admin/cycles/<int:id>/remediation/share', methods=['POST'])
@login_required
@role_required('admin')
def admin_remediation_share(id):
    """Email the remediation report to selected authorized users."""
    review     = UARReview.query.get_or_404(id)
    recipients = request.form.getlist('recipients')
    message    = request.form.get('message', '').strip()

    if not recipients:
        flash('Select at least one recipient.')
        return redirect(url_for('main.admin_remediation', id=id))

    recipient_users = User.query.filter(
        User.id.in_([int(r) for r in recipients]),
        User.is_active == True
    ).all()

    try:
        from flask_mail import Message
        from app import mail

        subject = f'UAR Remediation Report - {review.title}'
        body = (
            f'A remediation report has been shared with you.\n\n'
            f'Review: {review.title}\n'
            f'Approved: '
            f'{review.approved_at.strftime("%d %b %Y") if review.approved_at else "Pending"}\n'
            f'Shared by: {current_user.username}\n\n'
        )
        if message:
            body += f'Message from {current_user.username}:\n{message}\n\n'
        body += (
            f'View the full report at: '
            f'{request.url_root}admin/cycles/{review.id}/remediation\n\n'
            f'UAR Automation Platform'
        )

        for user in recipient_users:
            msg = Message(subject=subject,
                          recipients=[user.email],
                          body=body)
            mail.send(msg)
            audit_log('REPORT_SHARED', 'uar_reviews', id,
                      new_value=f'shared to {user.username} '
                                f'({user.email})')

        flash(f'Report sent to '
              f'{len(recipient_users)} recipient(s) successfully.')
    except Exception as e:
        flash(f'Could not send report: {e}')

    return redirect(url_for('main.admin_remediation', id=id))


@main.route('/admin/cycles/<int:id>/revisions')
@login_required
@role_required('admin')
def admin_revisions(id):
    review    = UARReview.query.get_or_404(id)
    revisions = RevisionHistory.query.filter_by(review_id=id) \
        .order_by(RevisionHistory.changed_at.desc()).all()
    return render_template('admin/revision_history.html',
                           review=review, revisions=revisions)


# ── ADMIN - Audit Trail Viewer (FR-50, FR-51, FR-52, FR-53) ───────────
@main.route('/admin/audit')
@login_required
@role_required('admin')
def admin_audit():
    action       = request.args.get('action', '')
    user_id      = request.args.get('user_id', '')
    from_date    = request.args.get('from_date', '')
    to_date      = request.args.get('to_date', '')
    target_table = request.args.get('target_table', '')
    target_id    = request.args.get('target_id', '')

    query = AuditLog.query
    if action:
        query = query.filter_by(action=action)
    if user_id:
        query = query.filter_by(user_id=int(user_id))
    if target_table:
        query = query.filter_by(target_table=target_table)
    if target_id:
        query = query.filter_by(target_id=int(target_id))
    if from_date:
        query = query.filter(AuditLog.created_at >=
                             datetime.strptime(from_date, '%Y-%m-%d'))
    if to_date:
        query = query.filter(AuditLog.created_at <=
                             datetime.strptime(to_date, '%Y-%m-%d')
                             + timedelta(days=1))

    logs = query.order_by(AuditLog.created_at.desc()).limit(500).all()

    available_actions = [a[0] for a in
        db.session.query(AuditLog.action).distinct().all()]
    all_users = User.query.order_by(User.username).all()

    return render_template('admin/audit.html',
        logs=logs, available_actions=available_actions,
        all_users=all_users,
        filters={'action': action, 'user_id': user_id,
                 'from_date': from_date, 'to_date': to_date})


@main.route('/admin/audit/export')
@login_required
@role_required('admin')
def admin_audit_export():
    fmt = request.args.get('format', 'csv')
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()

    if fmt == 'csv':
        import csv, io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp','User','Action','Target Table',
                         'Target ID','Old Value','New Value','IP'])
        for log in logs:
            writer.writerow([
                log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                log.user.username if log.user else 'System',
                log.action, log.target_table or '',
                log.target_id or '', log.old_value or '',
                log.new_value or '', log.ip_address or ''])
        audit_log('AUDIT_EXPORTED', new_value='format=csv')
        return Response(output.getvalue(), mimetype='text/csv',
            headers={'Content-Disposition':
                     'attachment; filename=audit_log.csv'})

    elif fmt == 'pdf':
        import io
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph,
            Spacer, Table, TableStyle)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter),
            leftMargin=0.4*inch, rightMargin=0.4*inch,
            topMargin=0.4*inch, bottomMargin=0.4*inch)
        styles = getSampleStyleSheet()
        title  = ParagraphStyle('title', parent=styles['Heading1'],
                                fontSize=16,
                                textColor=colors.HexColor('#1A1A1A'),
                                spaceAfter=12)
        story  = [Paragraph('UAR Platform - Audit Trail Export', title),
                  Spacer(1, 12)]

        data = [['Timestamp','User','Action','Table','ID',
                 'Old','New','IP']]
        for log in logs[:500]:  # Limit to 500 rows per PDF
            data.append([
                log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                (log.user.username if log.user else 'System')[:15],
                log.action[:18],
                (log.target_table or '-')[:12],
                str(log.target_id or '-')[:6],
                (log.old_value or '-')[:25],
                (log.new_value or '-')[:25],
                (log.ip_address or '-')[:15],
            ])

        table = Table(data, repeatRows=1,
            colWidths=[1.3*inch, 1.0*inch, 1.2*inch, 0.8*inch,
                       0.5*inch, 1.7*inch, 1.7*inch, 1.0*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1A1A1A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#CCCCCC')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1),
                [colors.white, colors.HexColor('#F5F5F5')]),
        ]))
        story.append(table)
        story.append(Spacer(1, 16))
        story.append(Paragraph(
            f'Showing {min(len(logs), 500)} of {len(logs)} entries. '
            f'Generated {datetime.utcnow().strftime("%d %b %Y %H:%M UTC")}',
            ParagraphStyle('footer', parent=styles['Normal'],
                fontSize=8, textColor=colors.HexColor('#666666'))))

        doc.build(story)
        buffer.seek(0)
        audit_log('AUDIT_EXPORTED', new_value='format=pdf')
        return Response(buffer.getvalue(), mimetype='application/pdf',
            headers={'Content-Disposition':
                     'attachment; filename=audit_log.pdf'})

    else:
        flash('Unsupported export format.')
        return redirect(url_for('main.admin_audit'))


# ── ADMIN - System Configuration (FR-55) ──────────────────────────────
@main.route('/admin/config', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_config():
    config_keys = [
        'reviewer_link_expiry_hours',
        'reminder_threshold_days',
        'default_cycle_duration_days',
        'reviewer_subject_template',
        'reviewer_body_template',
        'approver_subject_template',
        'approver_body_template',
        'report_email_template',
        'smtp_server',
        'smtp_port',
        'smtp_sender',
    ]

    if request.method == 'POST':
        for key in config_keys:
            value = request.form.get(key, '').strip()
            cfg = SystemConfig.query.filter_by(key=key).first()
            old_value = cfg.value if cfg else None
            if cfg:
                cfg.value = value
                cfg.updated_by = current_user.id
            else:
                cfg = SystemConfig(key=key, value=value,
                                   updated_by=current_user.id)
                db.session.add(cfg)
            if old_value != value:
                audit_log('CONFIG_CHANGED', 'system_config',
                          target_id=cfg.id if cfg.id else 0,
                          old_value=old_value, new_value=value)
        db.session.commit()
        flash('System configuration updated successfully.')
        return redirect(url_for('main.admin_config'))

    config = {c.key: c.value for c in SystemConfig.query.all()}
    if config.get('reviewer_link_expiry_hours'):
        config['reviewer_link_expiry_hours'] = \
            int(config['reviewer_link_expiry_hours'])
    if config.get('reminder_threshold_days'):
        config['reminder_threshold_days'] = \
            int(config['reminder_threshold_days'])
    if config.get('default_cycle_duration_days'):
        config['default_cycle_duration_days'] = \
            int(config['default_cycle_duration_days'])
    if config.get('smtp_port'):
        config['smtp_port'] = int(config['smtp_port'])

    return render_template('admin/system_config.html', config=config)


@main.route('/tasks/purge-old-data', methods=['POST'])
def purge_old_data():

    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning(
            "Unauthorized attempt to access purge endpoint."
        )

        return jsonify({
            "error": "Unauthorized access token missing"
        }), 401

    total_rows_deleted = 0
    batch_size = 5000

    purge_query = text("""
        WITH deleted AS (
            DELETE FROM audit_log
            WHERE id IN (
                SELECT id
                FROM audit_log
                WHERE created_at < NOW() - INTERVAL '7 years'
                LIMIT :limit_val
            )
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted;
    """)

    try:

        with db.engine.begin() as conn:

            while True:

                result = conn.execute(
                    purge_query,
                    {"limit_val": batch_size}
                )

                batch_count = result.scalar() or 0

                total_rows_deleted += batch_count

                logger.info(
                    f"Batched purge deleted {batch_count} records."
                )

                if batch_count == 0:
                    break

        logger.info(
            f"Purge complete. Total deleted items: "
            f"{total_rows_deleted}"
        )

        return jsonify({
            "status": "success",
            "rows_deleted": total_rows_deleted
        })

    except Exception as e:

        logger.exception(
            f"Database purge failure: {str(e)}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
