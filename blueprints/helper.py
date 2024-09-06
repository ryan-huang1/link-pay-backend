from flask import Blueprint, jsonify
from models import db, User, AdminActionLog
from decimal import Decimal

helper_bp = Blueprint('helper', __name__)

@helper_bp.route('/test/users', methods=['GET'])
def list_users():
    users = User.query.all()
    user_list = [
        {
            'id': user.id,
            'username': user.username,
            'is_admin': user.is_admin,
            'balance': float(user.balance) if isinstance(user.balance, Decimal) else user.balance
        } for user in users
    ]
    return jsonify(user_list), 200

@helper_bp.route('/test/users/delete-all', methods=['POST'])
def delete_all_users():
    try:
        num_deleted = db.session.query(User).delete()
        db.session.commit()
        return jsonify({'message': f'Deleted {num_deleted} users'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@helper_bp.route('/test/admin-log', methods=['GET'])
def list_admin_log():
    logs = AdminActionLog.query.order_by(AdminActionLog.timestamp.desc()).all()
    log_list = [
        {
            'id': log.id,
            'admin_id': log.admin_id,
            'action_type': log.action_type,
            'action_description': log.action_description,
            'affected_user_id': log.affected_user_id,
            'timestamp': log.timestamp.isoformat()
        } for log in logs
    ]
    return jsonify(log_list), 200