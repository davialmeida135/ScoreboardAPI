from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import secrets



from flask import Flask
from .database import db
import secrets

def create_app():
    app = Flask(__name__)
    app.config.from_object('config')
    app.secret_key = secrets.token_hex(16)
    app.config.from_prefixed_env()
    from .routes import match_bp
    app.register_blueprint(match_bp)
    db.init_app(app)

    return app