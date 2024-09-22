from flask import Blueprint, jsonify, request, current_app
from models import db, User, Transaction
from utils import get_user_from_token
from sqlalchemy.exc import IntegrityError
from decimal import Decimal, InvalidOperation
from sqlalchemy import or_, and_, case
from sqlalchemy.orm import aliased

transaction_bp = Blueprint('transaction', __name__)

@transaction_bp.route('/create', methods=['POST'])
def create_transaction():
    sender, error_message, status_code = get_user_from_token()
    if error_message:
        return jsonify({'error': error_message}), status_code

    # Reject all actions for admins
    if sender.is_admin:
        return jsonify({'error': 'Admin accounts are not allowed to perform transactions'}), 403

    data = request.json
    recipient_username = data.get('recipient_username')
    amount = data.get('amount')
    description = data.get('description')
    item_count = data.get('item_count', 1)

    if recipient_username is None or amount is None or description is None:
        return jsonify({'error': 'Missing required fields'}), 400

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404

    # Check if sender is a personal account (not business and not admin)
    if sender.is_business:
        return jsonify({'error': 'Business accounts can only receive money, not send'}), 403

    # Check if recipient is a business account
    if not recipient.is_business:
        return jsonify({'error': 'Personal accounts can only send money to business accounts'}), 403

    if sender.username == recipient.username:
        return jsonify({'error': 'Cannot send money to yourself'}), 400

    try:
        amount = Decimal(str(amount))
        item_count = int(item_count)
    except (InvalidOperation, ValueError):
        return jsonify({'error': 'Invalid amount or item count format'}), 400

    if amount < Decimal('0.01'):
        return jsonify({'error': 'Amount must be at least $0.01'}), 400

    if item_count < 1:
        return jsonify({'error': 'Item count must be at least 1'}), 400

    if sender.balance < amount:
        return jsonify({'error': 'Insufficient funds'}), 400

    try:
        new_transaction = Transaction(
            sender_id=sender.id,
            recipient_id=recipient.id,
            amount=amount,
            description=description,
            item_count=item_count
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
            'timestamp': new_transaction.timestamp.isoformat() if new_transaction.timestamp else None,
            'item_count': new_transaction.item_count
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

    # Create aliases for the User model
    CounterpartyUser = aliased(User)

    transactions = db.session.query(
        Transaction.id,
        Transaction.amount,
        Transaction.description,
        Transaction.timestamp,
        Transaction.item_count,
        Transaction.sender_id,
        case(
            (Transaction.sender_id == user.id, CounterpartyUser.username),
            else_=User.username
        ).label('counterparty_name')
    ).outerjoin(
        User, User.id == Transaction.sender_id
    ).outerjoin(
        CounterpartyUser, CounterpartyUser.id == Transaction.recipient_id
    ).filter(
        or_(Transaction.sender_id == user.id, Transaction.recipient_id == user.id)
    ).order_by(Transaction.timestamp.desc()).all()

    current_app.logger.info(f"Fetched {len(transactions)} transactions for user {user.id}")
    
    return jsonify({
        'transactions': [
            {
                'transaction_id': t.id,
                'type': 'sent' if t.sender_id == user.id else 'received',
                'counterparty': t.counterparty_name,
                'amount': float(t.amount),
                'description': t.description,
                'timestamp': t.timestamp.isoformat() if t.timestamp else None,
                'item_count': t.item_count
            } for t in transactions
        ]
    }), 200