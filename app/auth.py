# app/auth.py
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import db, login_manager
from app.models import User

auth = Blueprint('auth', __name__)


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login calls this to get the logged-in user object."""
    return User.query.get(int(user_id))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user     = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password')
            return render_template('auth/login.html')

        if not user.is_active:
            flash('Your account has been deactivated. Contact your Admin.')
            return render_template('auth/login.html')

        login_user(user)

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

    return render_template('auth/login.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


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

