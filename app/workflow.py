# app/workflow.py
from app import db, mail
from app.models import UARReview, User
from app.audit import audit_log
from flask_mail import Message
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


def send_reviewer_notification(review):
    """Send a tokenised email link to the assigned Reviewer."""
    try:
        current_app.logger.info(
        f"JWT encode secret length: {len(JWT_SECRET)}"
        ) 
        token = jwt.encode(
            {
                'review_id': review.id,
                'exp': datetime.utcnow() + timedelta(hours=72)
            },
            os.environ.get('FLASK_SECRET_KEY', 'dev-only'),
            algorithm='HS256'
        )

        # Build the reviewer link
        # Locally this will use localhost - on Cloud Run it uses the real URL
        base_url = os.environ.get('BASE_URL', 'https://uar-platform-test-748821193892.us-central1.run.app')
        link = f'{base_url}/review/{review.id}/decide?token={token}'

        msg = Message(
            subject=f'UAR Review Assigned: {review.title}',
            recipients=[review.reviewer.email],
            body=(
                f'Hello {review.reviewer.username},\n\n'
                f'A User Access Review has been assigned to you.\n\n'
                f'Review: {review.title}\n'
                f'Submitted by: {review.initiator.username}\n\n'
                f'Click the link below to begin your review:\n{link}\n\n'
                f'This link expires in 72 hours.\n\n'
                f'UAR Automation Platform'
            )
        )
        mail.send(msg)

    except Exception as e:
        # Log the error but do not crash the upload flow
        # The review is still submitted even if the email fails
        print(f'[EMAIL WARNING] Could not send reviewer notification: {e}')


def submit_review(review_id, current_user_id):
    """Change review status to IN_REVIEW and notify the Reviewer."""
    review = UARReview.query.get_or_404(review_id)
    review.status = 'IN_REVIEW'
    db.session.commit()
    audit_log('REVIEW_SUBMITTED', 'uar_reviews', review.id)
    send_reviewer_notification(review)

