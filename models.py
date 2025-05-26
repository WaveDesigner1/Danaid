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
    
    # === POLA DLA KEY EXCHANGE ===
    encrypted_session_key = db.Column(db.Text, nullable=True)  # Zaszyfrowany klucz AES
    key_acknowledged = db.Column(db.Boolean, default=False)    # Czy recipient potwierdził odbiór
    key_created_at = db.Column(db.DateTime, nullable=True)     # Kiedy klucz został utworzony
    key_acknowledged_at = db.Column(db.DateTime, nullable=True) # Kiedy klucz został potwierdzony
    
    initiator = db.relationship('User', foreign_keys=[initiator_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    messages = db.relationship('Message', backref='session', lazy='dynamic')
    
    def is_key_ready(self):
        """Sprawdza czy klucz sesji jest gotowy do użycia"""
        return (self.encrypted_session_key is not None and 
                self.encrypted_session_key != 'ACK' and 
                len(self.encrypted_session_key) > 100)
    
    def mark_key_acknowledged(self):
        """Oznacza klucz jako potwierdzony"""
        self.key_acknowledged = True
        self.key_acknowledged_at = datetime.datetime.utcnow()
        db.session.commit()

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

class Friend(db.Model):
    """Friends relationship model"""
    __tablename__ = 'friend'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'friend_id', name='uq_friend_user_friend'),
    )
    
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('friends_rel', lazy='dynamic'))
    friend = db.relationship('User', foreign_keys=[friend_id], backref=db.backref('friended_by_rel', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Friend {self.user_id} -> {self.friend_id}>'

class FriendRequest(db.Model):
    """Friend request model"""
    __tablename__ = 'friend_request'
    
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('from_user_id', 'to_user_id', name='uq_request_from_to'),
    )
    
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref=db.backref('sent_requests', lazy='dynamic'))
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref=db.backref('received_requests', lazy='dynamic'))
    
    def __repr__(self):
        return f'<FriendRequest {self.from_user_id} -> {self.to_user_id} [{self.status}]>'

# Dodaj te metody do klasy User

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
    """Sprawdza czy użytkownik jest znajomym z danym użytkownikiem"""
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
        # Sprawdź czy relacja już istnieje
        existing = Friend.query.filter_by(user_id=self.id, friend_id=friend_id).first()
        if existing:
            return False
        
        # Dodaj znajomego (w obie strony)
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

# Dodaj metody do klasy User
User.get_friends = get_friends
User.is_friend_with = is_friend_with
User.add_friend = add_friend
User.remove_friend = remove_friend
