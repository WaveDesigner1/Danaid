from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string
import datetime
import hashlib
import uuid
import time

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.String(6), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_online = db.Column(db.Boolean, default=False)
    last_active = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def set_password(self, password):
        # Uproszczona walidacja hasła
        if len(password) < 8:
            raise ValueError("Hasło musi mieć co najmniej 8 znaków")
            
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def generate_user_id(self):
        """Generuje unikalny 6-cyfrowy identyfikator użytkownika"""
        # Sprawdź, czy ID już istnieje
        if self.user_id:
            return
            
        # Generuj ID, dopóki nie będzie unikalny
        attempts = 0
        max_attempts = 100  # Zabezpieczenie przed nieskończoną pętlą
        
        while attempts < max_attempts:
            user_id = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            if User.query.filter_by(user_id=user_id).first() is None:
                self.user_id = user_id
                return
            attempts += 1
            
        # Jeśli dojdziemy tutaj, oznacza to, że nie udało się wygenerować unikalnego ID
        # w sensownej liczbie prób - dodajemy timestamp na końcu
        timestamp = str(int(time.time()))[-3:]
        user_id = ''.join([str(secrets.randbelow(10)) for _ in range(3)]) + timestamp
        self.user_id = user_id
        
    def update_last_active(self):
        """Aktualizuje czas ostatniej aktywności użytkownika"""
        self.last_active = datetime.datetime.utcnow()
        db.session.commit()

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    # Nowe pole do przechowywania zaszyfrowanego klucza sesji
    encrypted_session_key = db.Column(db.Text, nullable=True)
    # Pole określające, czy odbiorca potwierdził odebranie klucza
    key_acknowledged = db.Column(db.Boolean, default=False)
    
    initiator = db.relationship('User', foreign_keys=[initiator_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    messages = db.relationship('Message', backref='session', lazy='dynamic')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Zaszyfrowana wiadomość
    iv = db.Column(db.String(64), nullable=False)  # Wektor inicjalizacyjny
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User')
    
    @classmethod
    def get_unread_count(cls, user_id):
        """Pobiera liczbę nieprzeczytanych wiadomości dla użytkownika"""
        # Znajdź wszystkie aktywne sesje, w których użytkownik jest odbiorcą
        sessions = ChatSession.query.filter(
            (ChatSession.recipient_id == user_id) &
            (ChatSession.is_active == True) &
            (ChatSession.expires_at > datetime.datetime.utcnow())
        ).all()
        
        session_ids = [session.id for session in sessions]
        
        # Jeśli nie ma aktywnych sesji, zwróć 0
        if not session_ids:
            return 0
            
        # Policz nieprzeczytane wiadomości w tych sesjach
        return cls.query.filter(
            (cls.session_id.in_(session_ids)) &
            (cls.sender_id != user_id) &
            (cls.read == False)
        ).count()
