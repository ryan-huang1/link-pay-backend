from flask import Blueprint, request, jsonify, current_app
from models import db, User, RegistrationCode
from utils import hash_password, verify_password, generate_jwt_token, get_user_from_token, log_admin_action
from sqlalchemy.exc import IntegrityError
from decimal import Decimal
import secrets
from random_word import RandomWords

auth_bp = Blueprint('auth', __name__)

r = RandomWords()

def generate_word_code():
    words = []
    while len(words) < 3:
        word = r.get_random_word()
        if word and 3 <= len(word) <= 8:
            words.append(word.lower())
    return "-".join(words)

@auth_bp.route('/get-valid-codes', methods=['GET'])
def get_valid_codes():
    admin_user, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    if not admin_user.is_admin:
        return jsonify({'error': 'Access denied. Admin privileges required.'}), 403

    valid_codes = RegistrationCode.query.filter_by(is_used=False).all()
    
    codes_list = [
        {
            'id': code.id,
            'code': code.code,
            'created_at': code.created_at.isoformat() if code.created_at else None
        }
        for code in valid_codes
    ]

    log_admin_action(
        admin_id=admin_user.id,
        action_type="RETRIEVE_VALID_CODES",
        action_description=f"Admin {admin_user.username} retrieved list of valid registration codes",
        affected_user_id=None
    )

    return jsonify({
        'valid_codes': codes_list,
        'count': len(codes_list)
    }), 200

@auth_bp.route('/generate-registration-code', methods=['POST'])
def generate_registration_code():
    admin_user, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    if not admin_user.is_admin:
        return jsonify({'error': 'Access denied. Admin privileges required.'}), 403

    data = request.json
    num_codes = data.get('num_codes', 1)  # Default to 1 if not specified

    try:
        num_codes = int(num_codes)
        if num_codes < 1:
            return jsonify({'error': 'Number of codes must be at least 1'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid number of codes'}), 400

    generated_codes = []
    
    try:
        for _ in range(num_codes):
            code = generate_word_code()
            while RegistrationCode.query.filter_by(code=code).first():
                # Regenerate if code already exists
                code = generate_word_code()
            new_code = RegistrationCode(code=code)
            db.session.add(new_code)
            generated_codes.append(code)
        
        db.session.commit()

        log_admin_action(
            admin_id=admin_user.id,
            action_type="GENERATE_REGISTRATION_CODE",
            action_description=f"Generated {num_codes} new word-based registration code(s)",
            affected_user_id=None
        )

        return jsonify({
            'message': f'{num_codes} registration code(s) generated successfully',
            'codes': generated_codes
        }), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error generating registration code: {str(e)}")
        return jsonify({'error': 'An error occurred while generating the registration code(s)'}), 500

@auth_bp.route('/delete-all-codes', methods=['DELETE'])
def delete_all_codes():
    admin_user, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    if not admin_user.is_admin:
        return jsonify({'error': 'Access denied. Admin privileges required.'}), 403

    try:
        # Count the number of codes before deletion
        code_count = RegistrationCode.query.count()
        
        # Delete all registration codes
        RegistrationCode.query.delete()
        
        db.session.commit()

        log_admin_action(
            admin_id=admin_user.id,
            action_type="DELETE_ALL_REGISTRATION_CODES",
            action_description=f"Admin {admin_user.username} deleted all registration codes",
            affected_user_id=None
        )

        return jsonify({
            'message': f'Successfully deleted all registration codes',
            'deleted_count': code_count
        }), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting registration codes: {str(e)}")
        return jsonify({'error': 'An error occurred while deleting registration codes'}), 500
    
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'error': 'Missing username or password'}), 400

    user = User.query.filter_by(username=username).first()

    if user:
        if user.is_deleted:
            # Log failed login attempt for deleted user
            log_admin_action(
                admin_id=None,
                action_type="FAILED_LOGIN",
                action_description=f"Failed login attempt for deleted user: {username}",
                affected_user_id=user.id
            )
            return jsonify({'error': 'Invalid username or password'}), 401

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