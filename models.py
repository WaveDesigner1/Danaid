import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
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
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        """Ustawia hasło z walidacją"""
        if len(password) < 8:
            raise ValueError("Hasło musi mieć co najmniej 8 znaków")
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Sprawdza hasło"""
        return check_password_hash(self.password_hash, password)
        
    def generate_user_id(self):
        """Generuje unikalny 6-cyfrowy identyfikator użytkownika"""
        if self.user_id:
            return
            
        attempts = 0
        max_attempts = 100
        
        while attempts < max_attempts:
            user_id = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            if User.query.filter_by(user_id=user_id).first() is None:
                self.user_id = user_id
                return
            attempts += 1
            
        # Fallback z timestamp
        timestamp = str(int(time.time()))[-3:]
        user_id = ''.join([str(secrets.randbelow(10)) for _ in range(3)]) + timestamp
        self.user_id = user_id
        
    def update_last_active(self):
        """Aktualizuje czas ostatniej aktywności"""
        self.last_active = datetime.utcnow()
        db.session.commit()
        
    def get_friends(self):
        """Pobiera listę znajomych użytkownika"""
        try:
            friend_records = Friend.query.filter_by(user_id=self.id).all()
            friend_ids = [friend.friend_id for friend in friend_records]
            return User.query.filter(User.id.in_(friend_ids)).all() if friend_ids else []
        except Exception as e:
            print(f"Błąd podczas pobierania znajomych: {e}")
            return []

    def is_friend_with(self, user_id):
        """Sprawdza czy użytkownik jest znajomym"""
        try:
            return Friend.query.filter(
                ((Friend.user_id == self.id) & (Friend.friend_id == user_id)) |
                ((Friend.user_id == user_id) & (Friend.friend_id == self.id))
            ).first() is not None
        except Exception as e:
            print(f"Błąd podczas sprawdzania relacji znajomości: {e}")
            return False

    def add_friend(self, friend_id):
        """Dodaje użytkownika do znajomych"""
        try:
            existing = Friend.query.filter_by(user_id=self.id, friend_id=friend_id).first()
            if existing:
                return False
            
            friend1 = Friend(user_id=self.id, friend_id=friend_id)
            friend2 = Friend(user_id=friend_id, friend_id=self.id)
            
            db.session.add(friend1)
            db.session.add(friend2)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Błąd podczas dodawania znajomego: {e}")
            return False

    def remove_friend(self, friend_id):
        """Usuwa użytkownika ze znajomych"""
        try:
            Friend.query.filter(
                ((Friend.user_id == self.id) & (Friend.friend_id == friend_id)) |
                ((Friend.user_id == friend_id) & (Friend.friend_id == self.id))
            ).delete()
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Błąd podczas usuwania znajomego: {e}")
            return False

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # NOWY SYSTEM: Dual encryption support - klucze dla każdego użytkownika osobno
    encrypted_keys_json = db.Column(db.Text, nullable=True)
    key_generator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    key_acknowledged = db.Column(db.Boolean, default=False)
    
    # STARY SYSTEM: Backward compatibility
    encrypted_session_key = db.Column(db.Text, nullable=True)
    
    # Relationships
    initiator = db.relationship('User', foreign_keys=[initiator_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    key_generator = db.relationship('User', foreign_keys=[key_generator_id])
    messages = db.relationship('Message', backref='session', lazy='dynamic')
    
    # NOWE METODY - Dual encryption
    def get_encrypted_key_for_user(self, user_id):
        """Pobiera zaszyfrowany klucz dla konkretnego użytkownika (NOWY SYSTEM)"""
        if not self.encrypted_keys_json:
            # Fallback do starego systemu
            if self.encrypted_session_key:
                return self.encrypted_session_key
            return None
        try:
            keys_dict = json.loads(self.encrypted_keys_json)
            return keys_dict.get(str(user_id))
        except:
            return None
    
    def set_encrypted_keys(self, keys_dict, generator_id):
        """Ustawia klucze dla wszystkich użytkowników sesji (NOWY SYSTEM)"""
        self.encrypted_keys_json = json.dumps(keys_dict)
        self.key_generator_id = generator_id
        self.last_activity = datetime.utcnow()
    
    def has_key_for_user(self, user_id):
        """Sprawdza czy użytkownik ma klucz"""
        return self.get_encrypted_key_for_user(user_id) is not None
    
    def clear_keys(self):
        """Czyści wszystkie klucze szyfrowania (bezpieczeństwo przy wylogowaniu)"""
        self.encrypted_keys_json = None
        self.key_generator_id = None
        self.key_acknowledged = False
        # Zachowaj backward compatibility
        self.encrypted_session_key = None
    
    # STARE METODY - Backward compatibility
    def has_key(self):
        """Sprawdza czy sesja ma klucz (backward compatibility)"""
        return (self.encrypted_keys_json is not None) or (self.encrypted_session_key is not None)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Zaszyfrowana wiadomość
    iv = db.Column(db.String(64), nullable=False)  # Wektor inicjalizacyjny
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    is_encrypted = db.Column(db.Boolean, default=True)  # NOWE: znacznik szyfrowania
    
    sender = db.relationship('User')
    
    @classmethod
    def get_unread_count(cls, user_id):
        """Pobiera liczbę nieprzeczytanych wiadomości dla użytkownika"""
        sessions = ChatSession.query.filter(
            (ChatSession.recipient_id == user_id) &
            (ChatSession.is_active == True) &
            (ChatSession.expires_at > datetime.utcnow())
        ).all()
        
        session_ids = [session.id for session in sessions]
        
        if not session_ids:
            return 0
            
        return cls.query.filter(
            (cls.session_id.in_(session_ids)) &
            (cls.sender_id != user_id) &
            (cls.read == False)
        ).count()

class Friend(db.Model):
    """Model relacji znajomości"""
    __tablename__ = 'friend'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'friend_id', name='uq_friend_user_friend'),
    )
    
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('friends_rel', lazy='dynamic'))
    friend = db.relationship('User', foreign_keys=[friend_id], backref=db.backref('friended_by_rel', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Friend {self.user_id} -> {self.friend_id}>'

class FriendRequest(db.Model):
    """Model zaproszeń do znajomych"""
    __tablename__ = 'friend_request'
    
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('from_user_id', 'to_user_id', name='uq_request_from_to'),
    )
    
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref=db.backref('sent_requests', lazy='dynamic'))
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref=db.backref('received_requests', lazy='dynamic'))
    
    def __repr__(self):
        return f'<FriendRequest {self.from_user_id} -> {self.to_user_id} [{self.status}]>'
