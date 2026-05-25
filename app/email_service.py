from flask_mail import Message
from app import mail
import jwt, os
from datetime import datetime, timedelta

def send_reviewer_notification(review):
    token = jwt.encode(
        {'review_id': review.id, 'exp': datetime.utcnow() + timedelta(hours=72)},
        os.environ['FLASK_SECRET_KEY'], algorithm='HS256')
    link = f'https://uar-platform-test.a.run.app/review/{review.id}?token={token}'
    msg = Message('UAR Review Assigned to You',
                  recipients=[review.reviewer.email])
    msg.body = f'Click to review: {link}'
    mail.send(msg)

