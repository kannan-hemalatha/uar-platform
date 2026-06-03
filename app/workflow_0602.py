# app/workflow.py
from app import db, mail
from app.models import UARReview, User, SystemConfig
from app.audit import audit_log
from flask_mail import Message
from flask import current_app
from datetime import datetime, timedelta
import jwt
import os


def validate_sod(initiator_id, reviewer_id, approver_id):
    """Check that all three role holders are distinct individuals."""
    errors = []
    if initiator_id == reviewer_id:
        errors.append('Initiator and Reviewer must be different people')
    if reviewer_id == approver_id:
        errors.append('Reviewer and Approver must be different people')
    if initiator_id == approver_id:
        errors.append('Initiator and Approver must be different people')
    return errors


def _get_expiry_hours():
    """Read the link expiry from system_config (default 72 hours)."""
    cfg = SystemConfig.query.filter_by(
        key='reviewer_link_expiry_hours').first()
    return int(cfg.value) if cfg and cfg.value else 72


def _get_base_url():
    """Get the platform's base URL from env or fall back to request."""
    base_url = os.environ.get('BASE_URL')
    if not base_url:
        try:
            from flask import request
            base_url = request.url_root.rstrip('/')
        except Exception:
            base_url = ('https://uar-platform-test-748821193892'
                        '.us-central1.run.app')
    return base_url


def send_reviewer_notification(review):
    """Send a tokenised email link to the assigned Reviewer.
    Used for fresh assignments AND when the Approver rejects and the
    review is returned to the Reviewer for rework (Option 2)."""
    try:
        expiry_hours = _get_expiry_hours()

        from app.auth import generate_access_token
        token = generate_access_token(
            review.id, review.reviewer_id, 'reviewer',
            expires_hours=expiry_hours)

        base_url = _get_base_url()
        link = f'{base_url}/review/{review.id}/decide?token={token}'

        # Different subject and body depending on whether this is a fresh
        # assignment or a returned-for-rework notification
        is_rework = review.reject_reason is not None

        if is_rework:
            subject = (f'UAR Review Returned for Rework: {review.title}')
            body = (
                f'Hello {review.reviewer.username},\n\n'
                f'A User Access Review has been returned to you by the '
                f'Approver and requires rework.\n\n'
                f'Review: {review.title}\n'
                f'Approver: {review.approver.username}\n'
                f'Rejection reason: {review.reject_reason}\n\n'
                f'Click the link below to update your decisions and '
                f'resubmit:\n{link}\n\n'
                f'This link expires in {expiry_hours} hours.\n\n'
                f'UAR Automation Platform'
            )
        else:
            subject = f'UAR Review Assigned: {review.title}'
            body = (
                f'Hello {review.reviewer.username},\n\n'
                f'A User Access Review has been assigned to you.\n\n'
                f'Review: {review.title}\n'
                f'Submitted by: {review.initiator.username}\n\n'
                f'Click the link below to begin your review:\n{link}\n\n'
                f'This link expires in {expiry_hours} hours.\n\n'
                f'UAR Automation Platform'
            )

        msg = Message(subject=subject,
                      recipients=[review.reviewer.email],
                      body=body)
        mail.send(msg)
        # DEF-016 FIX: record an audit event whenever a notification email
        # is sent (review assignment or rework return).
        audit_log('EMAIL_SENT', 'uar_reviews', review.id,
                  new_value=('reviewer rework notification'
                             if is_rework else 'reviewer assignment notification'))
        print(f'[EMAIL SUCCESS] Reviewer notification sent to '
              f'{review.reviewer.email} for review {review.id} '
              f'(rework={is_rework})', flush=True)

    except Exception as e:
        import traceback
        print(f'[EMAIL ERROR] Could not send reviewer notification: {e}',
              flush=True)
        print(traceback.format_exc(), flush=True)


def submit_review(review_id, current_user_id):
    """Change review status to IN_REVIEW and notify the Reviewer."""
    review = UARReview.query.get_or_404(review_id)
    review.status = 'IN_REVIEW'
    db.session.commit()
    audit_log('REVIEW_SUBMITTED', 'uar_reviews', review.id)
    send_reviewer_notification(review)


def submit_for_approval(review_id, actor_id=None):
    """Change review status to PENDING_APPROVAL and notify the Approver."""
    review = UARReview.query.get_or_404(review_id)
    review.status = 'PENDING_APPROVAL'
    review.completed_at = datetime.utcnow()
    db.session.commit()
    audit_log('REVIEW_SUBMITTED_FOR_APPROVAL', 'uar_reviews', review.id,
              actor_id=actor_id)
    send_approver_notification(review)


def send_approver_notification(review):
    """Send a tokenised email link to the assigned Approver."""
    try:
        expiry_hours = _get_expiry_hours()

        from app.auth import generate_access_token
        token = generate_access_token(
            review.id, review.approver_id, 'approver',
            expires_hours=expiry_hours)

        base_url = _get_base_url()
        link = f'{base_url}/review/{review.id}/approve-view?token={token}'

        msg = Message(
            subject=f'UAR Approval Required: {review.title}',
            recipients=[review.approver.email],
            body=(
                f'Hello {review.approver.username},\n\n'
                f'A User Access Review requires your approval.\n\n'
                f'Review: {review.title}\n'
                f'Submitted by: {review.initiator.username}\n'
                f'Reviewed by: {review.reviewer.username}\n\n'
                f'Click the link below to approve or reject:\n{link}\n\n'
                f'This link expires in {expiry_hours} hours.\n\n'
                f'UAR Automation Platform'
            )
        )
        mail.send(msg)
        # DEF-016 FIX: record an audit event whenever the approver
        # notification email is sent.
        audit_log('EMAIL_SENT', 'uar_reviews', review.id,
                  new_value='approver approval-required notification')
        print(f'[EMAIL SUCCESS] Approver notification sent to '
              f'{review.approver.email} for review {review.id}',
              flush=True)

    except Exception as e:
        import traceback
        print(f'[EMAIL ERROR] Could not send approver notification: {e}',
              flush=True)
        print(traceback.format_exc(), flush=True)