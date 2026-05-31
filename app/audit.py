# app/audit.py
from app import db
from app.models import AuditLog
from flask import request
from flask_login import current_user


def audit_log(action, target_table=None, target_id=None,
              old_value=None, new_value=None, actor_id=None):
    try:
        entry = AuditLog(
            user_id      = actor_id if actor_id is not None else (
                           current_user.id if current_user.is_authenticated else None),
            action       = action,
            target_table = target_table,
            target_id    = target_id,
            old_value    = str(old_value) if old_value is not None else None,
            new_value    = str(new_value) if new_value is not None else None,
            ip_address   = request.remote_addr
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        print(f'[AUDIT WARNING] Could not write audit entry: {e}')

