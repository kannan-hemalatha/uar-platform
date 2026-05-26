# app/models.py
from app import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role          = db.Column(db.String(30), nullable=False)
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class UARReview(db.Model):
    __tablename__ = 'uar_reviews'
    id            = db.Column(db.Integer, primary_key=True)
    title         = db.Column(db.String(200))
    initiator_id  = db.Column(db.Integer, db.ForeignKey('users.id'),
                              nullable=False)
    reviewer_id   = db.Column(db.Integer, db.ForeignKey('users.id'),
                              nullable=False)
    approver_id   = db.Column(db.Integer, db.ForeignKey('users.id'),
                              nullable=False)
    status        = db.Column(db.String(20), default='PENDING')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at  = db.Column(db.DateTime)
    approved_at   = db.Column(db.DateTime)
    reject_reason = db.Column(db.Text)

    initiator = db.relationship('User', foreign_keys=[initiator_id])
    reviewer  = db.relationship('User', foreign_keys=[reviewer_id])
    approver  = db.relationship('User', foreign_keys=[approver_id])
    entries   = db.relationship('UAREntry', backref='review', lazy=True)


class UAREntry(db.Model):
    __tablename__ = 'uar_entries'
    id            = db.Column(db.Integer, primary_key=True)
    review_id     = db.Column(db.Integer,
                              db.ForeignKey('uar_reviews.id'),
                              nullable=False)
    account_name  = db.Column(db.String(200), nullable=False)
    current_role  = db.Column(db.String(200), nullable=False)
    system        = db.Column(db.String(200), nullable=False)
    last_login    = db.Column(db.String(50))
    justification = db.Column(db.Text)
    decision      = db.Column(db.String(30))
    comment       = db.Column(db.Text)
    decided_at    = db.Column(db.DateTime)


class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'))
    action       = db.Column(db.String(100), nullable=False)
    target_table = db.Column(db.String(50))
    target_id    = db.Column(db.Integer)
    old_value    = db.Column(db.Text)
    new_value    = db.Column(db.Text)
    ip_address   = db.Column(db.String(50))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])


class SystemConfig(db.Model):
    """Stores configurable system parameters - FR-55."""
    __tablename__ = 'system_config'
    id          = db.Column(db.Integer, primary_key=True)
    key         = db.Column(db.String(100), unique=True, nullable=False)
    value       = db.Column(db.Text)
    description = db.Column(db.Text)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow,
                            onupdate=datetime.utcnow)
    updated_by  = db.Column(db.Integer, db.ForeignKey('users.id'))


class RevisionHistory(db.Model):
    """Tracks all changes to UAR entries - FR-19, FR-20."""
    __tablename__ = 'revision_history'
    id          = db.Column(db.Integer, primary_key=True)
    entry_id    = db.Column(db.Integer,
                            db.ForeignKey('uar_entries.id'))
    review_id   = db.Column(db.Integer,
                            db.ForeignKey('uar_reviews.id'))
    field_name  = db.Column(db.String(100))
    old_value   = db.Column(db.Text)
    new_value   = db.Column(db.Text)
    changed_by  = db.Column(db.Integer, db.ForeignKey('users.id'))
    changed_at  = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[changed_by])

