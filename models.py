from database import db
from sqlalchemy.sql import func

class User(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Numeric(10, 2), nullable=False, default=1000.00)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    sent_transactions = db.relationship("Transaction", foreign_keys="Transaction.sender_id", back_populates="sender")
    received_transactions = db.relationship("Transaction", foreign_keys="Transaction.recipient_id", back_populates="recipient")
    admin_actions = db.relationship("AdminActionLog", back_populates="admin")

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'balance': float(self.balance),
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Transaction(db.Model):
    __tablename__ = 'Transactions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, server_default=func.now())

    sender = db.relationship("User", foreign_keys=[sender_id], back_populates="sent_transactions")
    recipient = db.relationship("User", foreign_keys=[recipient_id], back_populates="received_transactions")

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'amount': float(self.amount),
            'description': self.description,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class AdminActionLog(db.Model):
    __tablename__ = 'AdminActionLog'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    action_description = db.Column(db.Text)
    affected_user_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
    timestamp = db.Column(db.DateTime, server_default=func.now())

    admin = db.relationship("User", foreign_keys=[admin_id], back_populates="admin_actions")
    affected_user = db.relationship("User", foreign_keys=[affected_user_id])

    def to_dict(self):
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'action_type': self.action_type,
            'action_description': self.action_description,
            'affected_user_id': self.affected_user_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }