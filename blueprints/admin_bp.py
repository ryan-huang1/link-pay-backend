from flask import Blueprint, jsonify, request, current_app
from models import db, User, Transaction, AdminActionLog
from utils import get_user_from_token, hash_password
from sqlalchemy.exc import IntegrityError
from decimal import Decimal
import traceback

admin_bp = Blueprint('admin', __name__)

def admin_required(func):
    def wrapper(*args, **kwargs):
        user, error_message, status_code = get_user_from_token()
        if error_message:
            return jsonify({'error': error_message}), status_code
        if not user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403
        return func(user, *args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@admin_bp.route('/users/<string:username>/balance', methods=['PUT'])
@admin_required
def admin_user_balance(admin, username):
    data = request.json
    new_balance = data.get('new_balance')

    if new_balance is None:
        return jsonify({'error': 'New balance is required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        old_balance = user.balance
        user.balance = Decimal(str(new_balance))
        log = AdminActionLog(
            admin_id=admin.id,
            action_type="BALANCE_CHANGE",
            action_description=f"Changed balance for user {username} from {old_balance} to {new_balance}",
            affected_user_id=user.id
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'username': user.username, 'new_balance': float(user.balance)}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating balance: {str(e)}")
        return jsonify({'error': 'An error occurred while updating the balance'}), 500

@admin_bp.route('/users/<string:username>', methods=['DELETE'])
@admin_required
def admin_user_delete(admin, username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.is_deleted:
        return jsonify({'error': 'User has already been deleted'}), 400

    try:
        user.is_deleted = True
        user.balance = 0  # Set balance to 0 for deleted users

        log = AdminActionLog(
            admin_id=admin.id,
            action_type="USER_DELETE",
            action_description=f"Marked user {username} as deleted",
            affected_user_id=user.id
        )
        db.session.add(log)
        
        db.session.commit()
        
        return jsonify({'message': 'User marked as deleted successfully. All associated transactions have been preserved.'}), 200
    except Exception as e:
        db.session.rollback()
        error_traceback = traceback.format_exc()
        current_app.logger.error(f"Error deleting user: {str(e)}\n{error_traceback}")
        print(f"Error deleting user: {str(e)}\n{error_traceback}")
        return jsonify({'error': 'An error occurred while deleting the user'}), 500

@admin_bp.route('/users', methods=['GET'])
@admin_required
def admin_user_list(admin):
    users = User.query.all()
    return jsonify({
        'users': [user.to_dict() for user in users]
    }), 200

@admin_bp.route('/transactions/all', methods=['GET'])
@admin_required
def all_transaction_history(admin):
    transactions = Transaction.query.all()
    return jsonify({
        'transactions': [
            {
                'transaction_id': t.id,
                'sender': User.query.get(t.sender_id).username if User.query.get(t.sender_id) else "Deleted User",
                'recipient': User.query.get(t.recipient_id).username if User.query.get(t.recipient_id) else "Deleted User",
                'amount': float(t.amount),
                'description': t.description,
                'timestamp': t.timestamp.isoformat() if t.timestamp else None
            } for t in transactions
        ]
    }), 200

@admin_bp.route('/action-logs', methods=['GET'])
@admin_required
def admin_action_logs(admin):
    logs = AdminActionLog.query.all()
    return jsonify({
        'logs': [log.to_dict() for log in logs]
    }), 200

@admin_bp.route('/admin/create', methods=['POST'])
def create_admin():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'No authorization header provided'}), 401

    try:
        # Expecting the header to be in the format: "Bearer <flask_secret_key>"
        _, flask_secret_key = auth_header.split()
    except ValueError:
        return jsonify({'error': 'Invalid authorization header format'}), 401

    if flask_secret_key != current_app.config['SECRET_KEY']:
        return jsonify({'error': 'Invalid Flask secret key'}), 403

    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        new_admin = User(
            username=username,
            password_hash=hash_password(password),
            is_admin=True,
            balance=Decimal('0')
        )
        db.session.add(new_admin)
        
        log = AdminActionLog(
            admin_id=None,  # No admin_id since this is initial admin creation
            action_type="ADMIN_CREATE",
            action_description=f"Created new admin user {username}",
            affected_user_id=new_admin.id
        )
        db.session.add(log)
        
        db.session.commit()
        return jsonify({'message': 'Admin created successfully', 'admin_id': new_admin.id}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username already exists'}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating admin: {str(e)}")
        return jsonify({'error': 'An error occurred while creating the admin'}), 500