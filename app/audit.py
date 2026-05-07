from app import db
from app.models import AuditLog
from flask import request
from flask_login import current_user

def audit_log(action, table, target_id, old=None, new=None):
    entry = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action, target_table=table, target_id=target_id,
        old_value=str(old) if old else None,
        new_value=str(new) if new else None,
        ip_address=request.remote_addr
    )
    db.session.add(entry)
    db.session.commit()

