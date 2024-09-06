from flask import Blueprint, request, jsonify, current_app
from models import db, User
from utils import hash_password, verify_password, generate_jwt_token, get_user_from_token
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

    try:
        new_user = User(
            username=username,
            password_hash=hash_password(password),
            balance=1000.0,  # Initial balance
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully', 'user_id': new_user.id}), 201
    except IntegrityError as e:
        db.session.rollback()
        # Print the full error message to the console
        print(f"IntegrityError: {str(e)}")
        if "username" in str(e).lower():
            return jsonify({'error': 'Username already exists'}), 400
        else:
            return jsonify({'error': 'An integrity error occurred'}), 400
    except Exception as e:
        db.session.rollback()
        # Print the full error message to the console
        print(f"Exception: {str(e)}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'error': 'Missing username or password'}), 400

    user = User.query.filter_by(username=username).first()

    if user and verify_password(user.password_hash, password):
        token = generate_jwt_token(user.id, user.is_admin)
        return jsonify({
            'token': token,
            'user_id': user.id,
            'is_admin': user.is_admin
        }), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    user, error_message, error_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), error_code
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'is_admin': user.is_admin,
        'balance': float(user.balance) if isinstance(user.balance, Decimal) else user.balance
    }), 200