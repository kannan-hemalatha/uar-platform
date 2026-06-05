from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_mail import Mail
from google.cloud import secretmanager
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from fastapi import FastAPI, Header, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
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
        env = os.environ.get("ENV")

        if env is None:
            raise RuntimeError(
                "ENV environment variable is not set in GC. "
                "Expected 'test' or 'prod'."
            )

        env = env.lower()

        if env == "prod":
            secret_key_name = "prod-FLASK_SECRET_KEY"
            database_url_name = "prod-DATABASE_URL"
        elif env == "test":
            secret_key_name = "FLASK_SECRET_KEY"
            database_url_name = "DATABASE_URL"
        else:
           raise RuntimeError(
                f"Invalid ENV value '{env}'. Expected 'test' or 'prod'."
            )

        app.config['SECRET_KEY'] = get_secret(secret_key_name)
        app.config['SQLALCHEMY_DATABASE_URI'] = get_secret(database_url_name)

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

    # DEF-026 FIX: the approve / reject / decide routes can be submitted by a
    # reviewer or approver who arrived via a signed email-token link and has
    # NO login session. Flask-WTF CSRF needs a session, so those POSTs failed
    # with a Forbidden (CSRF) error. These endpoints are authenticated by the
    # JWT token instead, so we exempt them from CSRF specifically.
    csrf.exempt(app.view_functions['main.approve_review'])
    csrf.exempt(app.view_functions['main.reject_review'])
    csrf.exempt(app.view_functions['main.review_decide'])

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Replace with your actual PostgreSQL connection string
# Note: Use asyncpg driver for async SQLAlchemy
DATABASE_URL = "postgresql+psycopg2://uar_app_user:ChangeThisPassword123%21@/uar_db_test?host=/cloudsql/uar-platform-493904:us-central1:uar-db-instance"
engine = create_async_engine(DATABASE_URL, echo=False)

@app.post("/tasks/purge-old-data", status_code=status.HTTP_200_OK)
async def purge_old_data(authorization: str = Header(None)):
    # 1. Security Check: Cloud Scheduler sends an OIDC Token in the Auth Header
    if not authorization or not authorization.startswith("Bearer "):
        logger.warning("Unauthorized attempt to access purge endpoint.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Unauthorized access token missing"
        )

    # 2. Database Purge Execution
    total_rows_deleted = 0
    batch_size = 5000  # Kept small to prevent row/table locking

    # Raw SQL query utilizing a CTE for chunked deletion
    purge_query = text("""
        WITH deleted AS (
            DELETE FROM audit_log
            WHERE id IN (
                SELECT id FROM audit_log
                WHERE created_at < NOW() - INTERVAL '7 years'
                LIMIT :limit_val
            )
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted;
    """)

    try:
        async with engine.begin() as conn:
            while True:
                # Execute batch query
                result = await conn.execute(purge_query, {"limit_val": batch_size})
                batch_count = result.scalar() or 0
                
                total_rows_deleted += batch_count
                logger.info(f"Batched purge deleted {batch_count} records.")

                # If a batch returned 0 rows, we have cleared all data older than 7 years
                if batch_count == 0:
                    break

        logger.info(f"Purge complete. Total deleted items: {total_rows_deleted}")
        return {"status": "success", "rows_deleted": total_rows_deleted}

    except Exception as e:
        logger.error(f"Database purge failure: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal database processing error"
        )

# Optional clean shutdown of DB engine pool
@app.on_event("shutdown")
async def shutdown():
    await engine.dispose()



