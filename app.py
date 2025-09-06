from dotenv import load_dotenv
from routes import register_routes
from flask import Flask
import os
from extensions import db, migrate, bcrypt, mail
import logging

load_dotenv()

def create_app():
    app = Flask(__name__)

    @app.route("/healthz")
    def health_check():
        return "OK", 200

    # Configuration
    app = Flask(__name__)
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///local.db")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Logging
    logging.basicConfig(level=logging.DEBUG)
    print("MAIL_USERNAME:", app.config['MAIL_USERNAME'])
    print("MAIL_PASSWORD:", app.config['MAIL_PASSWORD'])

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    mail.init_app(app)

    from models import User, Transaction, Notification, Note

    # --- Register routes ---
    register_routes(app)
    
    return app

# --- Run Locally ---
if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))  # Default 5000 locally
    app.run(host="0.0.0.0", debug=True, use_reloader=False, port=port)  # use_reloader=False to prevent double initialization