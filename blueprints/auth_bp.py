from flask import Blueprint, request, jsonify, current_app
from models import db, User
from utils import hash_password, verify_password, generate_jwt_token, get_user_from_token, log_admin_action
from sqlalchemy.exc import IntegrityError
from decimal import Decimal

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        if existing_user.is_deleted:
            return jsonify({'error': 'This username belongs to a deleted account and cannot be reused'}), 400
        else:
            return jsonify({'error': 'Username already exists'}), 400

    try:
        new_user = User(
            username=username,
            password_hash=hash_password(password),
            balance=1000.0,  # Initial balance
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        
        # Log the user registration action
        log_admin_action(
            admin_id=None,  # No admin for self-registration
            action_type="USER_REGISTRATION",
            action_description=f"New user registered: {username}",
            affected_user_id=new_user.id
        )
        
        return jsonify({'message': 'User registered successfully', 'user_id': new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error registering user: {str(e)}")
        return jsonify({'error': 'An error occurred while registering the user'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'error': 'Missing username or password'}), 400

    user = User.query.filter_by(username=username).first()

    if user:
        if verify_password(user.password_hash, password):
            token = generate_jwt_token(user.id, user.is_admin)
            
            # Log successful login
            log_admin_action(
                admin_id=None,
                action_type="USER_LOGIN",
                action_description=f"User logged in: {username}",
                affected_user_id=user.id
            )
            
            return jsonify({
                'token': token,
                'user_id': user.id,
                'is_admin': user.is_admin
            }), 200
        else:
            # Log failed login attempt with affected user id
            log_admin_action(
                admin_id=None,
                action_type="FAILED_LOGIN",
                action_description=f"Failed login attempt for username: {username}",
                affected_user_id=user.id
            )
    else:
        # Log failed login attempt for non-existent user
        log_admin_action(
            admin_id=None,
            action_type="FAILED_LOGIN",
            action_description=f"Failed login attempt for non-existent username: {username}",
            affected_user_id=None
        )

    return jsonify({'error': 'Invalid username or password'}), 401