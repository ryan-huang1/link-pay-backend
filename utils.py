import jwt
import hashlib
from flask import current_app, request
from models import db, User, AdminActionLog
from datetime import datetime

def hash_password(password: str) -> str:
    return hashlib.sha256((password + current_app.config['SECRET_KEY']).encode()).hexdigest()

def verify_password(stored_password_hash: str, provided_password: str) -> bool:
    return stored_password_hash == hash_password(provided_password)

def generate_jwt_token(user_id: int, is_admin: bool) -> str:
    payload = {
        'user_id': user_id,
        'is_admin': is_admin
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def get_user_from_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None, 'No authorization header provided', 401

    try:
        token = auth_header.split(" ")[1]
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None, 'Token is invalid', 401
    except IndexError:
        return None, 'Invalid authorization header format', 401

    user_id = data.get('user_id')
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return None, 'User not found', 404

    return user, None, None

def log_admin_action(admin_id: int | None, action_type: str, action_description: str, affected_user_id: int | None):
    log_entry = AdminActionLog(
        admin_id=admin_id,
        action_type=action_type,
        action_description=action_description,
        affected_user_id=affected_user_id,
        timestamp=datetime.utcnow()
    )
    db.session.add(log_entry)
    db.session.commit()
