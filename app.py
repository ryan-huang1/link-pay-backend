from flask import Flask
from blueprints.auth_bp import auth_bp
from blueprints.user_bp import user_bp
from blueprints.transaction_bp import transaction_bp
from blueprints.admin_bp import admin_bp

app = Flask(__name__)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(user_bp, url_prefix='/user')
app.register_blueprint(transaction_bp, url_prefix='/transaction')
app.register_blueprint(admin_bp, url_prefix='/admin')

if __name__ == '__main__':
    app.run(debug=True)