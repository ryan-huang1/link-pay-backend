from flask import Blueprint, jsonify, request
from models import User
from utils import get_user_from_token

user_bp = Blueprint('user', __name__)

@user_bp.route('/profile', methods=['GET'])
def get_user_profile():
    user, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'balance': float(user.balance),
        'is_admin': user.is_admin
    }), 200

@user_bp.route('/usernames', methods=['GET'])
def get_all_usernames():
    user, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    usernames = [user.username for user in User.query.filter_by(is_admin=False).all()]
    return jsonify({'usernames': usernames}), 200

@user_bp.route('/users/<string:username>/balance', methods=['GET'])
def get_user_balance(username):
    user, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'username': target_user.username,
        'balance': float(target_user.balance)
    }), 200