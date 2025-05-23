from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file, Response, session
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_required
from datetime import timedelta
import os
import shutil
import datetime
import time
import json
from sqlalchemy import text
from sqlalchemy import inspect, text
import traceback
import sys
# Bezpośrednie importy
from models import db, User, ChatSession, Message
from admin import init_admin
from auth import auth_bp
from chat import chat_bp
from chat_api import chat_api
from database_migrations import apply_migrations as apply_e2ee_migrations
from websocket_routes import init_websocket_routes

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

# Automatyczne migracje bazy danych
def apply_migrations(app):
    """Automatyczne migracje bazy danych"""
    with app.app_context():
        inspector = inspect(db.engine)
        
        # Migracja 1: Dodanie kolumny is_online do tabeli user (jeśli nie istnieje)
        apply_migration(inspector, 'user', 'is_online', 'ALTER TABLE "user" ADD COLUMN is_online BOOLEAN DEFAULT FALSE')
        
        # Migracja 2: Dodanie kolumny encrypted_session_key do tabeli chat_session
        apply_migration(inspector, 'chat_session', 'encrypted_session_key', 'ALTER TABLE "chat_session" ADD COLUMN encrypted_session_key TEXT')
        
        # Migracja 3: Dodanie kolumny key_acknowledged do tabeli chat_session
        apply_migration(inspector, 'chat_session', 'key_acknowledged', 'ALTER TABLE "chat_session" ADD COLUMN key_acknowledged BOOLEAN DEFAULT FALSE')

def apply_migration(inspector, table, column, sql_statement):
    """Wykonuje pojedynczą migrację, jeśli jest potrzebna"""
    if table in inspector.get_table_names():
        columns = [c['name'] for c in inspector.get_columns(table)]
        if column not in columns:
            try:
                print(f"Wykonywanie migracji: Dodawanie kolumny {column} do tabeli {table}")
                db.session.execute(text(sql_statement))
                db.session.commit()
                print(f"Migracja zakończona pomyślnie")
            except Exception as e:
                print(f"Błąd podczas migracji: {e}")
                db.session.rollback()

# Główna funkcja tworząca aplikację
def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)
    
    # Konfiguracja bazy danych
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        # Użyj bezpiecznego fallbacku lub zgłoś błąd
        database_url = 'postgresql://postgres:rtBMJqIvMvwNBJEvzskDMfQKtEfTanKt@turntable.proxy.rlwy.net:39432/railway'
        app.logger.warning('Używanie domyślnego URL bazy danych - to nie powinno być używane w produkcji!')
    
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Bezpieczniejsze zarządzanie kluczem sesji
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        app.config['SECRET_KEY'] = os.urandom(24).hex()
        app.logger.warning('Używanie wygenerowanego SECRET_KEY - to wyloguje wszystkich użytkowników przy restarcie!')
    
    # Konfiguracja sesji
    app.config['SESSION_TYPE'] = 'filesystem'  # Przechowuj sesje w plikach, a nie w cookies
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    
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
    # Inicjalizacja obsługi bezpiecznych wiadomości
    initialize_secure_messaging(app)
    # Uruchom migracje bazy danych
    apply_migrations(app)
    apply_e2ee_migrations(app)
    
    # Endpoint z konfiguracją WebSocket dla frontendu
    @app.route('/api/websocket/config')
    def websocket_config():
        """Dostarcza konfigurację WebSocket dla klienta"""
        # Pobierz URL z zmiennej środowiskowej lub użyj domyślnej
        websocket_url = os.environ.get('WEBSOCKET_URL','')
        if not websocket_url:
            # Użyj domyślnego hosta z request
            websocket_url = request.host
    
        return jsonify({
            'wsUrl': websocket_url
        })
    
    # Dodaj skrypt konfiguracyjny dla WebSocket
    @app.route('/ws-config.js')
    def ws_config_js():
        """Generuje skrypt JS z konfiguracją WebSocket"""
        websocket_host = os.environ.get('WEBSOCKET_HOST', request.host.split(':')[0])
        websocket_port = os.environ.get('WEBSOCKET_PORT', '8081')
        
        config = {
            'wsUrl': f"{websocket_host}:{websocket_port}"
        }
        
        # Generuj skrypt JS
        js_content = f"window._env = {json.dumps(config)};"
        
        return Response(js_content, mimetype='application/javascript')

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
                "env_database_url": "ZREDAGOWANO",
                "env_neon_database_url": "ZREDAGOWANO",
                "connection_string": safe_connection
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_type": type(e).__name__,
                "env_vars": {
                    "DATABASE_URL": "ZREDAGOWANO",
                    "NEON_DATABASE_URL": "ZREDAGOWANO"
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
                    # Używaj flagi modified zamiast bezpośredniego commita
                    current_user.is_online = True
                    # Commit zostanie wykonany po zakończeniu obsługi żądania przez Flask
        except Exception as e:
            app.logger.error(f"Błąd w before_request: {e}")
            db.session.rollback()
            
    @app.after_request
    def after_request(response):
        """Ustawia ciasteczko z czasem ostatniej aktualizacji statusu online"""
        if current_user.is_authenticated and hasattr(current_user, 'is_online'):
            last_update_key = f'last_online_update_{current_user.id}'
            response.set_cookie(last_update_key, str(int(time.time())), max_age=3600)
        return response
    
    return app
