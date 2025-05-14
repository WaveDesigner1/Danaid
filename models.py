from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.String(6), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
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
