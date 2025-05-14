from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import datetime

# Inicjalizacja bazy danych
db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    public_key = db.Column(db.String(500), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.String(6), nullable=True, unique=True)
  

    # Relacje z wyraźnym określeniem kluczy obcych
    initiated_sessions = db.relationship('ChatSession', 
                                       foreign_keys='ChatSession.initiator_id',
                                       backref='initiator', 
                                       lazy='dynamic')
    
    received_sessions = db.relationship('ChatSession', 
                                       foreign_keys='ChatSession.recipient_id',
                                       backref='recipient', 
                                       lazy='dynamic')
    
    messages = db.relationship('Message', 
                              foreign_keys='Message.sender_id',
                              backref='sender', 
                              lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_user_id(self):
        self.user_id = generate_unique_user_id()
        return self.user_id


# Funkcja do generowania unikalnego ID
def generate_unique_user_id():
    while True:
        user_id = str(random.randint(100000, 999999))
        if User.query.filter_by(user_id=user_id).first() is None:
            return user_id


class ChatSession(db.Model):
    __tablename__ = 'chat_session'
    
    id = db.Column(db.Integer, primary_key=True)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relacja do wiadomości
    messages = db.relationship('Message', backref='session', lazy='dynamic')
    
    # Metoda do sprawdzania czy sesja jest aktywna
    @property
    def is_valid(self):
        return self.is_active and self.expires_at > datetime.datetime.utcnow()
    
    # Metoda do tworzenia nowej sesji
    @classmethod
    def create_session(cls, initiator_id, recipient_id, duration_hours=24):
        # Generuj token
        import secrets
        token = secrets.token_urlsafe(32)
        
        # Utwórz sesję
        session = cls(
            initiator_id=initiator_id,
            recipient_id=recipient_id,
            session_token=token,
            expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=duration_hours)
        )
        db.session.add(session)
        db.session.commit()
        return session
    
    def refresh_session(self, duration_hours=24):
        """Odświeża sesję, przedłużając czas jej ważności"""
        self.expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=duration_hours)
        self.last_activity = datetime.datetime.utcnow()
        db.session.commit()
    
    def invalidate(self):
        """Unieważnia sesję"""
        self.is_active = False
        db.session.commit()


class Message(db.Model):
    __tablename__ = 'message'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_delivered = db.Column(db.Boolean, default=False)
    
    @classmethod
    def create(cls, session_id, sender_id, encrypted_data):
        message = cls(
            session_id=session_id,
            sender_id=sender_id,
            encrypted_data=encrypted_data
        )
        db.session.add(message)
        db.session.commit()
        return message
    
    def mark_as_delivered(self):
        self.is_delivered = True
        db.session.commit()
