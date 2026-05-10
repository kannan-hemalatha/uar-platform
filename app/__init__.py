# app/__init__.py — app factory (key section)
import os from flask
import Flask from flask_sqlalchemy
import SQLAlchemy from flash_login
import LoginManager from flask mail
import Mail from google.com
import secret manager

env    = os.environ.get('ENV', 'test')   # 'test' or 'prod'
prefix = f'{env}-'                        # 'test-' or 'prod-'
# In GCP: secrets are read as test-DATABASE_URL or prod-DATABASE_URL
# Locally: .env file is used — always SQLite, no Cloud SQL needed

