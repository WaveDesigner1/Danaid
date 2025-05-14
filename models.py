from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random

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