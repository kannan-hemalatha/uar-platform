from app import db
from datetime import datetime
from sqlalchemy import event

class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role          = db.Column(db.String(30))  # initiator / reviewer / approver / admin / developer
    is_active     = db.Column(db.Boolean, default=True)
    @property
    def is_authenticated(self): return True
    @property
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

class UARReview(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    title        = db.Column(db.String(200))
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewer_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approver_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status       = db.Column(db.String(20), default='PENDING')
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    approved_at  = db.Column(db.DateTime)
    reject_reason= db.Column(db.Text)

class UAREntry(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    review_id     = db.Column(db.Integer, db.ForeignKey('uar_review.id'), nullable=False)
    account_name  = db.Column(db.String(200), nullable=False)
    current_role  = db.Column(db.String(200), nullable=False)
    system        = db.Column(db.String(200), nullable=False)
    last_login    = db.Column(db.String(50))
    justification = db.Column(db.Text)
    decision      = db.Column(db.String(30))  # RETAIN / REMOVE_ROLE / DEACTIVATE
    comment       = db.Column(db.Text)

class AuditLog(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'))
    action       = db.Column(db.String(100), nullable=False)
    target_table = db.Column(db.String(50))
    target_id    = db.Column(db.Integer)
    old_value    = db.Column(db.Text)
    new_value    = db.Column(db.Text)
    ip_address   = db.Column(db.String(50))
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow)

# Append-only enforcement - delete raises an exception
@event.listens_for(AuditLog, 'before_delete')
def prevent_audit_delete(mapper, connection, target):
    raise Exception('Audit log records cannot be deleted (regulatory requirement)')

