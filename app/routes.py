# app/routes.py
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, abort, Response)
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from app import db
from app.models import (User, UARReview, UAREntry, AuditLog,
                        SystemConfig, RevisionHistory)
from app.audit import audit_log
from app.workflow import validate_sod, submit_review, approve_review
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
    reviews = UARReview.query.filter_by(
        initiator_id=current_user.id).order_by(
        UARReview.created_at.desc()).all()
    return render_template('initiator/dashboard.html', reviews=reviews)


@main.route('/new-review', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def new_review():
    """Create a new UAR review - choose manual entry or file upload."""
    eligible_users = User.query.filter(
        User.is_active == True,
        User.id != current_user.id,
        User.role.in_(['initiator', 'reviewer', 'approver'])
    ).all()

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
                                   eligible_users=eligible_users,
                                   form_data=request.form)

        reviewer_id = int(reviewer_id)
        approver_id = int(approver_id)

        # SoD validation
        sod_errors = validate_sod(current_user.id, reviewer_id, approver_id)
        if sod_errors:
            return render_template('initiator/new_review.html',
                                   sod_errors=sod_errors,
                                   eligible_users=eligible_users,
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
                           eligible_users=eligible_users,
                           form_data=None)


@main.route('/review/<int:review_id>/upload', methods=['GET', 'POST'])
@login_required
@role_required('initiator')
def upload_file(review_id):
    review = UARReview.query.get_or_404(review_id)
    validation_errors = []

    if review.initiator_id != current_user.id:
        abort(403)

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

        for _, row in df.iterrows():
            entry = UAREntry(
                review_id    = review_id,
                account_name = row['account_name'],
                current_role = row['current_role'],
                system       = row['system'],
                last_login   = str(row.get('last_login', '')))
            db.session.add(entry)
        db.session.commit()
        audit_log('FILE_UPLOADED', 'uar_reviews', review_id)

        submit_review(review_id, current_user.id)
        flash('Review submitted successfully. Reviewer has been notified.')
        return redirect(url_for('main.dashboard'))

    return render_template('initiator/upload.html', validation_errors=[])


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
    reviews = UARReview.query.filter_by(
        reviewer_id=current_user.id, status='IN_REVIEW').all()
    reviews_completed = UARReview.query.filter(
        UARReview.reviewer_id == current_user.id,
        UARReview.status.in_(['APPROVED', 'REJECTED', 'PENDING_APPROVAL'])
    ).order_by(UARReview.completed_at.desc()).all()
    return render_template('reviewer/queue.html',
                           reviews=reviews,
                           reviews_completed=reviews_completed)


@main.route('/review/<int:review_id>/decide', methods=['GET', 'POST'])
@login_required
@role_required('reviewer')
def review_decide(review_id):
    review  = UARReview.query.get_or_404(review_id)
    entries = UAREntry.query.filter_by(review_id=review_id).all()

    if review.reviewer_id != current_user.id:
        abort(403)
    if review.status != 'IN_REVIEW':
        abort(403)

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
        review.completed_at = datetime.utcnow()
        db.session.commit()
        approve_review(review.id, current_user.id)   # ← handles status + audit + email
        flash('Review submitted for approval. Approver has been notified.')
        return redirect(url_for('main.reviewer_queue'))

    return render_template('reviewer/review_queue.html',
                           review=review, entries=entries)


# ── APPROVER ROUTES ───────────────────────────────────────────────────
@main.route('/approver/queue')
@login_required
@role_required('approver')
def approver_queue():
    reviews = UARReview.query.filter_by(
        approver_id=current_user.id, status='PENDING_APPROVAL').all()
    reviews_completed = UARReview.query.filter(
        UARReview.approver_id == current_user.id,
        UARReview.status.in_(['APPROVED', 'REJECTED'])
    ).order_by(UARReview.approved_at.desc()).all()
    return render_template('approver/queue.html',
                           reviews=reviews,
                           reviews_completed=reviews_completed)


@main.route('/review/<int:review_id>/approve-view')
@login_required
@role_required('approver')
def approve_view(review_id):
    review  = UARReview.query.get_or_404(review_id)
    entries = UAREntry.query.filter_by(review_id=review_id).all()
    return render_template('approver/approver_view.html',
                           review=review, entries=entries)


@main.route('/reviews/<int:id>/approve', methods=['POST'])
@login_required
@role_required('approver')
def approve_review(id):
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
    review = UARReview.query.get_or_404(id)
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash('Rejection reason is required.')
        return redirect(url_for('main.approve_view', review_id=id))
    review.status        = 'REJECTED'
    review.reject_reason = reason
    db.session.commit()
    audit_log('REVIEW_REJECTED', 'uar_reviews', review.id, new_value=reason)
    flash('Review rejected and returned to Reviewer.')
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
        authorized_users=authorized_users)


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

    # Metrics reflect the currently filtered cycles
    metrics = {
        'total':            len(cycles),
        'in_review':        sum(1 for c in cycles
                                if c.status == 'IN_REVIEW'),
        'pending_approval': sum(1 for c in cycles
                                if c.status == 'PENDING_APPROVAL'),
        'approved':         sum(1 for c in cycles
                                if c.status == 'APPROVED'),
        'rejected':         sum(1 for c in cycles
                                if c.status == 'REJECTED'),
        'overdue':          sum(1 for c in cycles
                                if c.status in ['IN_REVIEW','PENDING_APPROVAL']
                                and c.created_at <
                                    datetime.utcnow() - timedelta(days=7)),
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
        authorized_users=authorized_users)


@main.route('/admin/cycles/<int:id>/remediation/export')
@login_required
@role_required('admin')
def admin_remediation_export(id):
    """Export the remediation report as CSV or PDF."""
    fmt     = request.args.get('format', 'csv')
    review  = UARReview.query.get_or_404(id)
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

