from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_mail import Mail
from google.cloud import secretmanager
from werkzeug.middleware.proxy_fix import ProxyFix
import os

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def get_secret(name):
    client = secretmanager.SecretManagerServiceClient()
    project = os.environ.get('GOOGLE_CLOUD_PROJECT')
    secret_path = f'projects/{project}/secrets/{name}/versions/latest'
    response = client.access_secret_version(request={'name': secret_path})
    return response.payload.data.decode('UTF-8')

def create_app():
    app = Flask(__name__)

    # Trust one layer of proxy headers (Cloud Run / reverse proxy) so that
    # request.scheme and url_for(_external=True) reflect HTTPS. Harmless
    # locally where no X-Forwarded-* headers are present.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    is_gcp = os.environ.get('GOOGLE_CLOUD_PROJECT') is not None
 
    if is_gcp:
        app.config['SECRET_KEY'] = get_secret('FLASK_SECRET_KEY')
        app.config['SQLALCHEMY_DATABASE_URI'] = get_secret('DATABASE_URL')
        app.config['MAIL_SERVER'] = get_secret('MAIL_SERVER')
        app.config['MAIL_USERNAME'] = get_secret('MAIL_USERNAME')
        app.config['MAIL_PASSWORD'] = get_secret('MAIL_PASSWORD')
        app.config['JIRA_BASE_URL'] = get_secret('JIRA_BASE_URL')
        app.config['JIRA_EMAIL'] = get_secret('JIRA_EMAIL')
        app.config['JIRA_API_TOKEN'] = get_secret('JIRA_API_TOKEN')

        # HTTPS-only session cookie (cloud only; local dev over http would
        # break if SECURE were forced there)
        app.config['SESSION_COOKIE_SECURE']   = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    else:
        if os.path.exists('.env'):
            from dotenv import load_dotenv
            load_dotenv()
        app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret')
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///uar_dev.db')
        app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
        app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
        app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
        app.config['JIRA_BASE_URL'] = os.getenv('JIRA_BASE_URL', '')
        app.config['JIRA_EMAIL'] = os.getenv('JIRA_EMAIL', '')
        app.config['JIRA_API_TOKEN'] = os.getenv('JIRA_API_TOKEN', '')

    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False

    app.config['MAIL_DEFAULT_SENDER'] = (
    'adminuar@gmail.com'
    )

    db.init_app(app)
    csrf = CSRFProtect(app)

    # Force HTTPS + HSTS in the cloud. CSP disabled for now so Bootstrap/inline
    # styles keep working; tighten with a tailored policy later.
    if is_gcp:
        from flask_talisman import Talisman
        Talisman(app, force_https=True, strict_transport_security=True,
                 content_security_policy=None)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    mail.init_app(app)

    from app.auth import auth
    from app.routes import main
    app.register_blueprint(auth)
    app.register_blueprint(main)

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))