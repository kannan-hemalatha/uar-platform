# app/routes.py - role enforcement decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if current_user.role not in roles: abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator

