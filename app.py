from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from datetime import timedelta

# Bezpośrednie importy
from models import db, User
from admin import init_admin
from auth import auth_bp
from chat import chat_bp
# Import nowego blueprintu chat_api
from chat_api import chat_api

# Inicjalizacja login managera
login_manager = LoginManager()

# Ładowanie użytkownika
@login_manager.user_loader
def load_user(user_id):
    # KLUCZOWA ZMIANA: dodaj przechwytywanie i logowanie błędów
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Błąd ładowania użytkownika: {e}")
        return None

# Główna funkcja tworząca aplikację
def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)  # KLUCZOWA ZMIANA: dodaj supports_credentials=True

    # Konfiguracja bazy danych
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Konfiguracja bezpieczeństwa
    app.config['SECRET_KEY'] = 'your_secret_key'
    
    # KLUCZOWA ZMIANA: Popraw konfigurację sesji
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)
    app.config['REMEMBER_COOKIE_SECURE'] = False
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['SESSION_PROTECTION'] = 'basic'  # KLUCZOWA ZMIANA: zmień z 'strong' na 'basic'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_SECURE'] = False

    # Inicjalizacja
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'

    # Rejestracja blueprintów
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(chat_api)  # Rejestracja blueprintu chat_api

    # Inicjalizacja panelu admina
    init_admin(app)

    return app
