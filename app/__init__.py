from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
import secrets
from flask_socketio import SocketIO, emit
from config import jwt_sec



from flask import Flask
from .database import db
import secrets
socketio = SocketIO()
jwt = JWTManager()
def create_app():
    app = Flask(__name__)
    app.config.from_object('config')
    app.config['JWT_SECRET_KEY'] = jwt_sec
    app.secret_key = secrets.token_hex(16)
    app.config.from_prefixed_env()
    from .routes import app_bp
    app.register_blueprint(app_bp)
    jwt.init_app(app)
    socketio.init_app(app) 
    db.init_app(app)

    return app