from flask import Flask
from flask_cors import CORS
from database import db
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def create_app():
    app = Flask(__name__)
    CORS(app)

    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
    db_url = os.environ.get('DB_URL')
    
    if not db_url:
        raise ValueError("No DB_URL set for Flask application. Check your .env file or environment variables.")

    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Blueprint registration
    from blueprints.auth_bp import auth_bp
    from blueprints.user_bp import user_bp
    from blueprints.transaction_bp import transaction_bp
    from blueprints.admin_bp import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(transaction_bp, url_prefix='/transaction')
    app.register_blueprint(admin_bp, url_prefix='/admin')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)