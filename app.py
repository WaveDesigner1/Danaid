from flask import Flask, render_template
from flask_cors import CORS
from flask_login import LoginManager, current_user
from datetime import timedelta
import os
# Bezpośrednie importy
from models import db, User
from admin import init_admin
from auth import auth_bp
from chat import chat_bp

# Inicjalizacja login managera
login_manager = LoginManager()

# Ładowanie użytkownika
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Błąd ładowania użytkownika: {e}")
        return None

# Główna funkcja tworząca aplikację
def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)
    
    # Konfiguracja bazy danych
    if 'RENDER' in os.environ:
        # Na platformie Render używamy katalogu /tmp
        db_path = '/tmp/database.db'
    else:
        # Upewnij się, że katalog instance istnieje
        instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
        if not os.path.exists(instance_path):
            os.makedirs(instance_path, exist_ok=True)
        db_path = os.path.join(instance_path, 'database.db')
    
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}?isolation_level=READ_UNCOMMITTED'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 5,
        'max_overflow': 10
    }
    
    # Konfiguracja bezpieczeństwa
    app.config['SECRET_KEY'] = 'your_secret_key'
    
    # Konfiguracja sesji
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)
    app.config['REMEMBER_COOKIE_SECURE'] = False
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['SESSION_PROTECTION'] = 'basic'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_SECURE'] = False
    
    # Inicjalizacja
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'
    
    # Inicjalizacja bazy danych
    with app.app_context():
        try:
            db.create_all()
            print("Baza danych została utworzona/zweryfikowana pomyślnie")
        except Exception as e:
            print(f"Błąd podczas inicjalizacji bazy danych: {e}")
            import traceback
            traceback.print_exc()
    
    # Rejestracja blueprintów
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    
    # Inicjalizacja panelu admina
    init_admin(app)
    
    # Dodaj zarządzanie sesją
    @app.before_request
    def before_request():
        try:
            app.permanent_session_lifetime = timedelta(hours=24)
            if current_user.is_authenticated and hasattr(current_user, 'is_online'):
                current_user.is_online = True
                db.session.commit()
        except Exception as e:
            print(f"Błąd w before_request: {e}")
            db.session.rollback()
    
    # Dodaj obsługę błędów 404 i 500
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    return app
