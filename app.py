from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_required
from datetime import timedelta
import os
import shutil
import datetime
import time
from sqlalchemy import text
from sqlalchemy import inspect, text
import traceback
# Bezpośrednie importy
from models import db, User, ChatSession, Message
from admin import init_admin
from auth import auth_bp
from chat import chat_bp
from chat_api import chat_api

# Inicjalizacja login managera
login_manager = LoginManager()

# Funkcje pomocnicze do określania typu bazy danych
def is_sqlite():
    """Sprawdza, czy używamy bazy SQLite"""
    return db.engine.name == 'sqlite'

def is_postgresql():
    """Sprawdza, czy używamy bazy PostgreSQL"""
    return db.engine.name == 'postgresql'

# Ładowanie użytkownika
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Błąd ładowania użytkownika: {e}")
        return None

# Skrypt do usunięcia bazy danych (zakomentowany)
"""
def drop_database():
    with db.engine.connect() as conn:
        # Wyłączenie sesji połączeń do bazy
        trans = conn.begin()
        conn.execute(text('''
        SELECT pg_terminate_backend(pg_stat_activity.pid)
        FROM pg_stat_activity
        WHERE pg_stat_activity.datname = current_database()
        AND pid <> pg_backend_pid();
        '''))
        trans.commit()
        
        # Usunięcie wszystkich tabel
        db.drop_all()
        print("Baza danych została zresetowana")
"""

# Główna funkcja tworząca aplikację
def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)
    
    # Konfiguracja bazy danych
    database_url = os.environ.get('DATABASE_URL', 'postgresql://postgres:rtBMJqIvMvwNBJEvzskDMfQKtEfTanKt@postgres.railway.internal:5432/railway')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Generuj nowy sekret dla sesji przy każdym uruchomieniu aplikacji
    # To wymusi reset wszystkich sesji użytkowników
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    
    # Konfiguracja sesji
    app.config['SESSION_TYPE'] = 'filesystem'  # Przechowuj sesje w plikach, a nie w cookies
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Odświeżaj sesję przy każdym żądaniu
    
    # Inicjalizacja bazy danych i logowania
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'
    
    # Rejestracja blueprintów
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(chat_api)
    
    # Inicjalizacja panelu admina
    init_admin(app)
    
    # Endpoint diagnostyczny do sprawdzenia połączenia z bazą danych
    @app.route('/db-debug')
    def db_debug():
        try:
            from sqlalchemy import text, inspect
            
            # Sprawdź, jaki silnik bazy danych jest używany
            engine_name = db.engine.name
            
            # Wykonaj bezpieczne zapytanie działające w bazie
            result = db.session.execute(text("SELECT 1 as test")).fetchone()
            
            # Pobierz listę tabel w sposób niezależny od bazy
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            # Maskuj dane wrażliwe w connection string
            safe_connection = str(db.engine.url)
            if ":" in safe_connection and "@" in safe_connection:
                parts = safe_connection.split('@')
                credentials = parts[0].split(':')
                if len(credentials) > 2:
                    masked_url = f"{credentials[0]}:{credentials[1]}:******@{parts[1]}"
                    safe_connection = masked_url
            
            return jsonify({
                "status": "success",
                "engine": engine_name,
                "test_query": dict(result) if result else None,
                "tables": tables,
                "env_database_url": os.environ.get('DATABASE_URL', 'not_set').replace('danaid_database_owner:npg_LcawRkg3jpD2', 'danaid_database_owner:******'),
                "env_neon_database_url": os.environ.get('NEON_DATABASE_URL', 'not_set').replace('danaid_database_owner:npg_LcawRkg3jpD2', 'danaid_database_owner:******'),
                "connection_string": safe_connection
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_type": type(e).__name__,
                "env_vars": {
                    "DATABASE_URL": (os.environ.get('DATABASE_URL', 'not_set').replace('danaid_database_owner:npg_LcawRkg3jpD2', 'danaid_database_owner:******')),
                    "NEON_DATABASE_URL": (os.environ.get('NEON_DATABASE_URL', 'not_set').replace('danaid_database_owner:npg_LcawRkg3jpD2', 'danaid_database_owner:******'))
                }
            }), 500
    
    # Inicjalizacja bazy danych przy pierwszym uruchomieniu
    with app.app_context():
        try:
            # Sprawdź połączenie
            db.session.execute(text("SELECT 1"))
            print("Połączenie z bazą danych nawiązane pomyślnie")
            
            # Utwórz tabele (bezpieczna metoda)
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if not existing_tables:
                print("Baza danych jest pusta, tworzę schemat...")
                db.create_all()
            else:
                print(f"Znaleziono istniejące tabele: {existing_tables}")
                
                # Sprawdź, czy wszystkie modele mają odpowiadające tabele
                models = db.Model.__subclasses__()
                model_tables = [model.__tablename__ for model in models]
                
                missing_tables = [table for table in model_tables if table not in existing_tables]
                if missing_tables:
                    print(f"Brakujące tabele: {missing_tables}")
                    db.create_all()  # Utworzy tylko brakujące tabele
                    print("Dodano brakujące tabele")
            
        except Exception as e:
            print(f"Błąd podczas inicjalizacji bazy danych: {e}")
            traceback.print_exc()
            db.session.rollback()
    
    # Dodaj zarządzanie sesją
    @app.before_request
    def before_request():
        """Zarządzanie sesją przed każdym żądaniem"""
        try:
            # Ustawienie czasu życia sesji
            app.permanent_session_lifetime = timedelta(hours=24)
            
            # Optymalizacja aktualizacji statusu online
            if current_user.is_authenticated and hasattr(current_user, 'is_online'):
                # Aktualizuj status tylko raz na 5 minut zamiast przy każdym żądaniu
                last_update_key = f'last_online_update_{current_user.id}'
                last_update = request.cookies.get(last_update_key, 0)
                try:
                    last_update = int(last_update)
                except (TypeError, ValueError):
                    last_update = 0
                    
                now = int(time.time())
                
                if now - last_update > 300:  # 5 minut = 300 sekund
                    current_user.is_online = True
                    db.session.commit()
                    # Cookies do zarządzania czasem ostatniej aktualizacji są obsługiwane w odpowiedzi
        except Exception as e:
            print(f"Błąd w before_request: {e}")
            db.session.rollback()
    
    return app
