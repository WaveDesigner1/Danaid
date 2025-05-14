from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string
import datetime
import hashlib
import uuid

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.String(6), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=True)
    is_online = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def generate_user_id(self):
        """Generuje unikalny 6-cyfrowy identyfikator użytkownika"""
        # Sprawdź, czy ID już istnieje
        if self.user_id:
            return
            
        # Generuj ID, dopóki nie będzie unikalny
        while True:
            user_id = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            if User.query.filter_by(user_id=user_id).first() is None:
                self.user_id = user_id
                return

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    initiator = db.relationship('User', foreign_keys=[initiator_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    messages = db.relationship('Message', backref='session', lazy='dynamic')
    
    @property
    def is_valid(self):
        """Sprawdza, czy sesja jest ważna (aktywna i nie wygasła)"""
        return self.is_active and self.expires_at > datetime.datetime.utcnow()
    
    def refresh_session(self):
        """Odświeża sesję, przedłużając jej ważność"""
        self.last_activity = datetime.datetime.utcnow()
        # Ustaw nowy czas wygaśnięcia (np. +24h od teraz)
        self.expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        db.session.commit()
    
    def invalidate(self):
        """Unieważnia sesję"""
        self.is_active = False
        db.session.commit()
    
    @classmethod
    def create_session(cls, initiator_id, recipient_id):
        """Tworzy nową sesję czatu między dwoma użytkownikami"""
        # Generuj unikalny token sesji
        token = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
        
        # Ustaw czas wygaśnięcia (np. +24h)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        
        # Utwórz nową sesję
        session = cls(
            session_token=token,
            initiator_id=initiator_id,
            recipient_id=recipient_id,
            expires_at=expires_at
        )
        
        db.session.add(session)
        db.session.commit()
        
        return session

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Zaszyfrowana wiadomość
    iv = db.Column(db.String(64), nullable=False)  # Wektor inicjalizacyjny
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User')
