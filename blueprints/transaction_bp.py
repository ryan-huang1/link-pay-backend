from flask import Blueprint, jsonify, request, current_app
from models import db, User, Transaction
from utils import get_user_from_token
from sqlalchemy.exc import IntegrityError
from decimal import Decimal, InvalidOperation
import logging

transaction_bp = Blueprint('transaction', __name__)

@transaction_bp.route('/create', methods=['POST'])
def create_transaction():
    sender, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    data = request.json
    recipient_username = data.get('recipient_username')
    amount = data.get('amount')
    description = data.get('description')

    if recipient_username is None or amount is None or description is None:
        return jsonify({'error': 'Missing required fields'}), 400

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404

    if sender.username == recipient.username:
        return jsonify({'error': 'Cannot send money to yourself'}), 400

    try:
        amount = Decimal(str(amount))
    except InvalidOperation:
        return jsonify({'error': 'Invalid amount format'}), 400

    if amount < Decimal('0.01'):
        return jsonify({'error': 'Amount must be at least $0.01'}), 400

    if sender.balance < amount:
        return jsonify({'error': 'Insufficient funds'}), 400

    try:
        new_transaction = Transaction(
            sender_id=sender.id,
            recipient_id=recipient.id,
            amount=amount,
            description=description
        )
        db.session.add(new_transaction)

        sender.balance -= amount
        recipient.balance += amount

        db.session.commit()

        current_app.logger.info(f"Transaction created: {new_transaction.id}")

        return jsonify({
            'transaction_id': new_transaction.id,
            'sender': sender.username,
            'recipient': recipient.username,
            'amount': float(new_transaction.amount),
            'description': new_transaction.description,
            'timestamp': new_transaction.timestamp.isoformat() if new_transaction.timestamp else None
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Transaction failed: {str(e)}")
        return jsonify({'error': 'Transaction failed'}), 500

@transaction_bp.route('/history', methods=['GET'])
def get_transaction_history():
    user, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    transactions = Transaction.query.filter(
        (Transaction.sender_id == user.id) | (Transaction.recipient_id == user.id)
    ).order_by(Transaction.timestamp.desc()).all()

    current_app.logger.info(f"Fetched {len(transactions)} transactions for user {user.id}")
    
    return jsonify({
        'transactions': [
            {
                'transaction_id': t.id,
                'type': 'sent' if t.sender_id == user.id else 'received',
                'counterparty': User.query.get(t.recipient_id if t.sender_id == user.id else t.sender_id).username,
                'amount': float(t.amount),
                'description': t.description,
                'timestamp': t.timestamp.isoformat() if t.timestamp else None
            } for t in transactions
        ]
    }), 200