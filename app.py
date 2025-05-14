from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_login import LoginManager
from datetime import timedelta
import os
import json

# Bezpośrednie importy
from models import db, User
from admin import init_admin
from auth import auth_bp
from chat import chat_bp

# Próba importu chat_api, zabezpieczona przed błędem
try:
    from chat_api import chat_api
    chat_api_imported = True
except ImportError:
    chat_api_imported = False

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
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
    
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
    
    # Rejestracja chat_api blueprintu jeśli został pomyślnie zaimportowany
    if chat_api_imported:
        app.register_blueprint(chat_api)
        print("Blueprint chat_api został zarejestrowany.")
    else:
        print("Blueprint chat_api nie został zaimportowany. Pomijam rejestrację.")

    # Inicjalizacja panelu admina
    init_admin(app)
    
    # Dodanie endpointów diagnostycznych
    @app.route('/diagnostics', methods=['GET'])
    def diagnostics():
        """Endpoint diagnostyczny do sprawdzenia stanu bazy danych"""
        try:
            result = {
                'status': 'checking',
                'app_config': {},
                'tables': [],
                'admin_exists': False,
                'user_count': 0,
                'errors': []
            }
            
            # Sprawdź konfigurację aplikacji
            for key in ['SQLALCHEMY_DATABASE_URI', 'SECRET_KEY', 'SESSION_PROTECTION']:
                if key in app.config:
                    result['app_config'][key] = 'MASKED' if 'SECRET' in key else app.config[key]
            
            # Sprawdź tabele w bazie danych
            tables = []
            try:
                tables_query = db.session.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
                tables = [table[0] for table in tables_query]
                result['tables'] = tables
            except Exception as e:
                result['errors'].append(f"Błąd podczas sprawdzania tabel: {str(e)}")
            
            # Sprawdź, czy tabela user istnieje
            if 'user' in tables:
                # Sprawdź, czy istnieje administrator
                try:
                    admin = User.query.filter_by(username='admin').first()
                    result['admin_exists'] = admin is not None
                    if admin:
                        result['admin_username'] = admin.username
                        result['admin_is_admin'] = admin.is_admin
                        result['admin_has_public_key'] = admin.public_key is not None
                    
                    # Sprawdź liczbę użytkowników
                    result['user_count'] = User.query.count()
                    
                    # Sprawdź strukturę tabeli user
                    user_columns = db.session.execute("PRAGMA table_info(user);").fetchall()
                    result['user_columns'] = [col[1] for col in user_columns]
                except Exception as e:
                    result['errors'].append(f"Błąd podczas sprawdzania użytkowników: {str(e)}")
            
            # Sprawdź, czy tabele czatu istnieją
            for table in ['chat_session', 'message']:
                if table in tables:
                    try:
                        count = db.session.execute(f"SELECT COUNT(*) FROM {table};").scalar()
                        result[f'{table}_count'] = count
                    except Exception as e:
                        result['errors'].append(f"Błąd podczas sprawdzania tabeli {table}: {str(e)}")
            
            # Sprawdź czy plik blokujący istnieje
            init_lock_file = 'db_initialized.lock'
            result['lock_file_exists'] = os.path.exists(init_lock_file)
            if result['lock_file_exists']:
                try:
                    with open(init_lock_file, 'r') as f:
                        result['lock_file_content'] = f.read()
                except:
                    result['lock_file_content'] = 'Cannot read file'
            
            result['status'] = 'ok' if not result['errors'] else 'errors'
            return jsonify(result)
        except Exception as e:
            return jsonify({
                'status': 'critical_error',
                'message': str(e)
            }), 500

        @app.route('/diagnostics', methods=['GET'])
        def diagnostics():
    """Endpoint diagnostyczny do sprawdzenia stanu bazy danych"""
    try:
        result = {
            'status': 'checking',
            'app_config': {},
            'tables': [],
            'admin_exists': False,
            'user_count': 0,
            'errors': []
        }
        
        # Sprawdź konfigurację aplikacji
        for key in ['SQLALCHEMY_DATABASE_URI', 'SECRET_KEY', 'SESSION_PROTECTION']:
            if key in app.config:
                result['app_config'][key] = 'MASKED' if 'SECRET' in key else app.config[key]
        
        # Sprawdź tabele w bazie danych
        tables = []
        try:
            # Poprawiona wersja z jawnym deklarowaniem tekstu SQL
            from sqlalchemy import text
            tables_query = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table';")).fetchall()
            tables = [table[0] for table in tables_query]
            result['tables'] = tables
        except Exception as e:
            result['errors'].append(f"Błąd podczas sprawdzania tabel: {str(e)}")
        
        # Sprawdź, czy tabela user istnieje
        if 'user' in tables:
            # Sprawdź, czy istnieje administrator
            try:
                from models import User
                admin = User.query.filter_by(username='admin').first()
                result['admin_exists'] = admin is not None
                if admin:
                    result['admin_username'] = admin.username
                    result['admin_is_admin'] = admin.is_admin
                
                # Sprawdź liczbę użytkowników
                result['user_count'] = User.query.count()
                
                # Sprawdź strukturę tabeli user
                user_columns = db.session.execute(text("PRAGMA table_info(user);")).fetchall()
                result['user_columns'] = [col[1] for col in user_columns]
            except Exception as e:
                result['errors'].append(f"Błąd podczas sprawdzania użytkowników: {str(e)}")
        
        # Sprawdź, czy tabele czatu istnieją
        for table in ['chat_session', 'message']:
            if table in tables:
                try:
                    count = db.session.execute(text(f"SELECT COUNT(*) FROM {table};")).scalar()
                    result[f'{table}_count'] = count
                except Exception as e:
                    result['errors'].append(f"Błąd podczas sprawdzania tabeli {table}: {str(e)}")
        
        # Sprawdź czy plik blokujący istnieje
        import os
        init_lock_file = 'db_initialized.lock'
        result['lock_file_exists'] = os.path.exists(init_lock_file)
        if result['lock_file_exists']:
            try:
                with open(init_lock_file, 'r') as f:
                    result['lock_file_content'] = f.read()
            except:
                result['lock_file_content'] = 'Cannot read file'
        
        result['status'] = 'ok' if not result['errors'] else 'errors'
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'critical_error',
            'message': str(e)
        }), 500

    return app
