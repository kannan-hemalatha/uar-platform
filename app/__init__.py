# app/__init__.py
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db            = SQLAlchemy()
login_manager = LoginManager()
mail          = Mail()


def create_app():
    app = Flask(__name__)

    is_gcp = os.environ.get('GOOGLE_CLOUD_PROJECT') is not None

    if is_gcp:
        # Running on Cloud Run - read secrets from Secret Manager
        from google.cloud import secretmanager
        env    = os.environ.get('ENV', 'test')
        prefix = f'{env}-'

        def get_secret(name):
            client  = secretmanager.SecretManagerServiceClient()
            project = os.environ.get('GOOGLE_CLOUD_PROJECT')
            path    = f'projects/{project}/secrets/{name}/versions/latest'
            return client.access_secret_version(
                request={'name': path}).payload.data.decode('UTF-8')

        app.config['SECRET_KEY']             = get_secret(f'{prefix}FLASK_SECRET_KEY')
        app.config['SQLALCHEMY_DATABASE_URI'] = get_secret(f'{prefix}DATABASE_URL')
        app.config['MAIL_SERVER']             = get_secret('MAIL_SERVER')
        app.config['MAIL_USERNAME']           = get_secret('MAIL_USERNAME')
        app.config['MAIL_PASSWORD']           = get_secret('MAIL_PASSWORD')
    else:
        # Running locally - read from .env file
        from dotenv import load_dotenv
        load_dotenv()
        app.config['SECRET_KEY']             = os.getenv('FLASK_SECRET_KEY')
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
        app.config['MAIL_SERVER']             = os.getenv('MAIL_SERVER')
        app.config['MAIL_USERNAME']           = os.getenv('MAIL_USERNAME')
        app.config['MAIL_PASSWORD']           = os.getenv('MAIL_PASSWORD')

    app.config['MAIL_PORT']            = 587
    app.config['MAIL_USE_TLS']         = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialise extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    mail.init_app(app)

    # Register blueprints
    from app.auth   import auth
    from app.routes import main
    app.register_blueprint(auth)
    app.register_blueprint(main)

    return app

