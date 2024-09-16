from flask import Blueprint, request, jsonify, current_app
from models import db, User, RegistrationCode
from utils import hash_password, verify_password, generate_jwt_token, get_user_from_token, log_admin_action
from sqlalchemy.exc import IntegrityError
from decimal import Decimal
import secrets
import random
import time
import json
import os
import logging

auth_bp = Blueprint('auth', __name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load word list from JSON file
script_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(script_dir, 'word_list.json')

try:
    with open(json_path, 'r') as f:
        WORD_POOL = json.load(f)
    logger.info(f"Loaded {len(WORD_POOL)} words from word_list.json")
except FileNotFoundError:
    logger.error("word_list.json not found. Please run generate_word_list.py first.")
    WORD_POOL = ["error", "file", "missing"]  # Fallback to a simple list in case of error

# Ensure we have at least 3 words
if len(WORD_POOL) < 3:
    logger.error(f"Not enough words in the word list. Found only {len(WORD_POOL)} words.")
    WORD_POOL.extend(["not", "enough", "words"])

WORD_POOL = list(set(WORD_POOL))  # Ensure uniqueness
logger.info(f"Word pool contains {len(WORD_POOL)} unique words.")

def generate_word_code():
    return "-".join(random.sample(WORD_POOL, 3))

def generate_unique_codes(num_codes, existing_codes):
    codes = set()
    max_attempts = num_codes * 10  # Limit the number of attempts to avoid infinite loop
    attempts = 0
    while len(codes) < num_codes and attempts < max_attempts:
        new_code = generate_word_code()
        if new_code not in existing_codes and new_code not in codes:
            codes.add(new_code)
        attempts += 1
    
    if len(codes) < num_codes:
        logger.warning(f"Could only generate {len(codes)} unique codes out of {num_codes} requested.")
    
    return list(codes)

@auth_bp.route('/generate-registration-code', methods=['POST'])
def generate_registration_code():
    start_time = time.time()
    
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

    auth_time = time.time() - start_time
    logger.info(f"Time for authentication and validation: {auth_time:.4f} seconds")

    try:
        # Fetch existing codes
        fetch_start = time.time()
        existing_codes = set(code[0] for code in RegistrationCode.query.with_entities(RegistrationCode.code).all())
        fetch_time = time.time() - fetch_start
        logger.info(f"Time for fetching existing codes: {fetch_time:.4f} seconds")

        # Generate unique codes
        generation_start = time.time()
        generated_codes = generate_unique_codes(num_codes, existing_codes)
        generation_time = time.time() - generation_start
        logger.info(f"Time for code generation: {generation_time:.4f} seconds")

        # Bulk insert
        insert_start = time.time()
        new_codes = [RegistrationCode(code=code) for code in generated_codes]
        db.session.bulk_save_objects(new_codes)
        db.session.commit()
        insert_time = time.time() - insert_start
        logger.info(f"Time for bulk insert: {insert_time:.4f} seconds")

        log_start = time.time()
        log_admin_action(
            admin_id=admin_user.id,
            action_type="GENERATE_REGISTRATION_CODE",
            action_description=f"Generated {len(generated_codes)} new word-based registration code(s)",
            affected_user_id=None
        )
        log_time = time.time() - log_start
        logger.info(f"Time for logging admin action: {log_time:.4f} seconds")

        total_time = time.time() - start_time
        logger.info(f"Total time for request: {total_time:.4f} seconds")

        return jsonify({
            'message': f'{len(generated_codes)} registration code(s) generated successfully',
            'codes': generated_codes,
            'timing': {
                'authentication': auth_time,
                'fetching_existing_codes': fetch_time,
                'code_generation': generation_time,
                'bulk_insert': insert_time,
                'admin_log': log_time,
                'total': total_time
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error generating registration code: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while generating the registration code(s)'}), 500
    
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
    
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    registration_code = data.get('registration_code')

    if not all([username, password, registration_code]):
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        if existing_user.is_deleted:
            return jsonify({'error': 'This username belongs to a deleted account and cannot be reused'}), 400
        else:
            return jsonify({'error': 'Username already exists'}), 400

    # Check if the registration code is valid
    code = RegistrationCode.query.filter_by(code=registration_code, is_used=False).first()
    if not code:
        return jsonify({'error': 'Invalid or already used registration code'}), 400

    try:
        new_user = User(
            username=username,
            password_hash=hash_password(password),
            balance=1000.0,  # Initial balance
            is_admin=False
        )
        db.session.add(new_user)

        # Mark the registration code as used
        code.is_used = True
        code.used_by = new_user.id

        db.session.commit()
        
        # Generate JWT token for the new user
        token = generate_jwt_token(new_user.id, new_user.is_admin)
        
        # Log the user registration action
        log_admin_action(
            admin_id=None,  # No admin for self-registration
            action_type="USER_REGISTRATION",
            action_description=f"New user registered: {username}",
            affected_user_id=new_user.id
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': new_user.id,
            'token': token,
            'is_admin': new_user.is_admin
        }), 201
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