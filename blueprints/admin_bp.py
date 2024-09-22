from flask import Blueprint, jsonify, request, current_app
from models import db, User, Transaction, AdminActionLog
from utils import get_user_from_token, hash_password
from sqlalchemy.exc import IntegrityError
from decimal import Decimal
import traceback
from sqlalchemy.orm import joinedload
from sqlalchemy import func
from sqlalchemy.orm import aliased
import re

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
    sent_alias = aliased(Transaction, name='sent')
    received_alias = aliased(Transaction, name='received')

    users = db.session.query(
        User,
        func.count(sent_alias.id) + func.count(received_alias.id)
    ).outerjoin(
        sent_alias, User.sent_transactions
    ).outerjoin(
        received_alias, User.received_transactions
    ).filter(
        User.is_business == False,
        User.is_admin == False,
        User.is_deleted == False
    ).group_by(User.id).all()

    user_data = [{
        **user.to_dict(),
        'transaction_count': transaction_count
    } for user, transaction_count in users]

    return jsonify({'users': user_data}), 200

@admin_bp.route('/businesses', methods=['GET'])
@admin_required
def admin_business_list(admin):
    sent_alias = aliased(Transaction, name='sent')
    received_alias = aliased(Transaction, name='received')

    businesses = db.session.query(
        User,
        func.count(sent_alias.id) + func.count(received_alias.id)
    ).outerjoin(
        sent_alias, User.sent_transactions
    ).outerjoin(
        received_alias, User.received_transactions
    ).filter(
        User.is_business == True,
        User.is_deleted == False
    ).group_by(User.id).all()

    business_data = [{
        **business.to_dict(),
        'transaction_count': transaction_count
    } for business, transaction_count in businesses]

    return jsonify({'businesses': business_data}), 200

@admin_bp.route('/transactions/all', methods=['GET'])
@admin_required
def all_transaction_history(admin):
    sender_alias = aliased(User, name='sender')
    recipient_alias = aliased(User, name='recipient')

    transactions = db.session.query(
        Transaction.id,
        Transaction.amount,
        Transaction.description,
        Transaction.timestamp,
        sender_alias.username.label('sender_username'),
        recipient_alias.username.label('recipient_username')
    ).join(
        sender_alias, Transaction.sender_id == sender_alias.id
    ).join(
        recipient_alias, Transaction.recipient_id == recipient_alias.id
    ).order_by(Transaction.timestamp.desc()).all()

    return jsonify({
        'transactions': [
            {
                'transaction_id': t.id,
                'sender': t.sender_username or "Deleted User",
                'recipient': t.recipient_username or "Deleted User",
                'amount': float(t.amount),
                'description': t.description,
                'timestamp': t.timestamp.isoformat() if t.timestamp else None
            } for t in transactions
        ]
    }), 200

@admin_bp.route('/action-logs', methods=['GET'])
@admin_required
def admin_action_logs(admin):
    admin_alias = aliased(User, name='admin')
    affected_user_alias = aliased(User, name='affected_user')

    logs = db.session.query(
        AdminActionLog.id,
        AdminActionLog.action_type,
        AdminActionLog.action_description,
        AdminActionLog.timestamp,
        admin_alias.username.label('admin_username'),
        affected_user_alias.username.label('affected_username')
    ).outerjoin(
        admin_alias, AdminActionLog.admin_id == admin_alias.id
    ).outerjoin(
        affected_user_alias, AdminActionLog.affected_user_id == affected_user_alias.id
    ).order_by(AdminActionLog.timestamp.desc()).all()

    logs_data = [{
        'id': log.id,
        'admin_username': log.admin_username or "System",
        'action_type': log.action_type,
        'action_description': log.action_description,
        'affected_username': log.affected_username or "Unknown User",
        'timestamp': log.timestamp.isoformat() if log.timestamp else None
    } for log in logs]

    return jsonify({'logs': logs_data}), 200

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
    
@admin_bp.route('/business/create', methods=['POST'])
@admin_required
def create_business_account(admin):
    data = request.json
    business_name = data.get('business_name')
    password = data.get('password')
    teacher = data.get('teacher')
    class_period = data.get('class_period')
    business_type = data.get('business_type')

    if not all([business_name, password, teacher, class_period, business_type]):
        return jsonify({'error': 'Missing required fields'}), 400

    # Validate business name (no spaces, alphanumeric)
    if not re.match(r'^[a-zA-Z0-9]+$', business_name):
        return jsonify({'error': 'Business name must be alphanumeric with no spaces'}), 400

    try:
        new_business = User(
            username=business_name,
            password_hash=hash_password(password),
            is_business=True,
            balance=Decimal('0'),
            teacher=teacher,
            class_period=class_period,
            business_type=business_type
        )
        db.session.add(new_business)
        
        log = AdminActionLog(
            admin_id=admin.id,
            action_type="BUSINESS_CREATE",
            action_description=f"Created new business account {business_name}",
            affected_user_id=new_business.id
        )
        db.session.add(log)
        
        db.session.commit()
        return jsonify({
            'message': 'Business account created successfully',
            'business_id': new_business.id,
            'business_name': new_business.username
        }), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Business name already exists'}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating business account: {str(e)}")
        return jsonify({'error': 'An error occurred while creating the business account'}), 500