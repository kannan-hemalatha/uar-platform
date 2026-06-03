# app/auth.py
from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import db, login_manager
from app.models import User
import jwt
from datetime import datetime, timedelta

auth = Blueprint('auth', __name__)


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login calls this to get the logged-in user object."""
    return User.query.get(int(user_id))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_page = request.form.get('next') or request.args.get('next')
        user     = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password')
            return render_template('auth/login.html', next=next_page)

        if not user.is_active:
            flash('Your account has been deactivated. Contact your Admin.')
            return render_template('auth/login.html', next=next_page)
        
        login_user(user)

        # Honour ?next= if present, otherwise route by role
        if next_page and next_page != '/':
            return redirect(next_page)

        # Route to the correct dashboard based on role
        if user.role == 'initiator':
            return redirect(url_for('main.dashboard'))
        elif user.role == 'reviewer':
            return redirect(url_for('main.reviewer_queue'))
        elif user.role == 'approver':
            return redirect(url_for('main.approver_queue'))
        elif user.role == 'admin':
            return redirect(url_for('main.admin_users'))
        else:
            return redirect(url_for('main.dashboard'))

    return render_template('auth/login.html', next=request.args.get('next', ''))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


def generate_access_token(review_id, user_id, role, expires_hours=72):
    """Signed, time-limited token for reviewer/approver email links."""
    payload = {
        'review_id': review_id,
        'user_id':   user_id,
        'role':      role,
        'exp':       datetime.utcnow() + timedelta(hours=expires_hours),
        'iat':       datetime.utcnow(),
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


def verify_access_token(token, review_id, expected_role):
    """Returns the User if the token is valid for this review+role, else None."""
    try:
        payload = jwt.decode(
            token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    if payload.get('review_id') != review_id:
        return None
    if payload.get('role') != expected_role:
        return None
    user = User.query.get(payload.get('user_id'))
    if not user or not user.is_active:
        return None
    return user


# ── Helper: create an admin user for first-time setup ─────────────────
# Run this ONCE from the Flask shell to create your first user:
# flask shell
# >>> from app.auth import create_user
# >>> create_user('admin1', 'admin@test.com', 'password123', 'admin')
def create_user(username, email, password, role):
    from app import db
    user = User(
        username      = username,
        email         = email,
        password_hash = generate_password_hash(password),
        role          = role,
        is_active     = True
    )
    db.session.add(user)
    db.session.commit()
    print(f'User {username} created with role {role}')

