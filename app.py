from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file, Response, session
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_required
from flask_socketio import SocketIO
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

# 🔄 ZOPTYMALIZOWANE IMPORTY (po scaleniu modułów)
from models import db, User, ChatSession, Message
from admin import init_admin
from auth import auth_bp
from chat import chat_bp  # ✅ chat.py zawiera teraz wszystko (chat + chat_api + socketio)
# ❌ USUNIĘTE: from chat_api import chat_api  # Scalono z chat.py
# ❌ USUNIĘTE: from database_migrations import apply_e2ee_migrations  # Wbudowano w chat.py
# 🔧 WARUNKOWO: init_socketio_handler może być w chat.py lub zintegrowane bezpośrednio

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
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    
    # Inicjalizacja Socket.IO
    socketio = SocketIO(app, 
                       cors_allowed_origins="*", 
                       logger=False, 
                       engineio_logger=False,
                       async_mode='threading')
    
    # Inicjalizacja bazy danych i logowania
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'
    
    # 🔄 ZOPTYMALIZOWANE BLUEPRINTY (po scaleniu)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)  # ✅ chat_bp zawiera teraz wszystkie endpointy z chat_api
    # ❌ USUNIĘTE: app.register_blueprint(chat_api)  # Scalono z chat_bp
    
    # Inicjalizacja panelu admina
    init_admin(app)
    
    # 🔄 ZOPTYMALIZOWANE SOCKET.IO (sprawdź czy funkcja istnieje)
    try:
        from chat import init_socketio_handler
        init_socketio_handler(socketio)
        print("✅ Socket.IO handler zainicjalizowany z chat.py")
    except ImportError:
        print("⚠️  init_socketio_handler nie znaleziono - może być zintegrowane bezpośrednio w chat.py")
        pass
 
    # 🔄 MIGRACJE TERAZ W CHAT.PY
    # Uruchom migracje bazy danych (scalono z chat.py)
    apply_migrations(app)
    # ❌ USUNIĘTE: apply_e2ee_migrations(app)  # Wbudowano w apply_migrations

    # Socket.IO konfiguracja dla frontendu
    @app.route('/api/websocket/config')
    def websocket_config():
        """Dostarcza konfigurację Socket.IO dla klienta"""
        host = request.host
        
        return jsonify({
            'socketUrl': f"https://{host}" if request.is_secure else f"http://{host}",
            'path': '/socket.io/'
        })
    
    # Socket.IO konfiguracyjny skrypt JS
    @app.route('/socket-config.js')
    def socket_config_js():
        """Generuje skrypt JS z konfiguracją Socket.IO"""
        host = request.host
        
        config = {
            'socketUrl': f"https://{host}" if request.is_secure else f"http://{host}",
            'path': '/socket.io/'
        }
        
        js_content = f"window._socketConfig = {json.dumps(config)};"
        return Response(js_content, mimetype='application/javascript')

    # Debug endpoint
    @app.route('/db-debug')
    def db_debug():
        try:
            from sqlalchemy import text, inspect
            
            engine_name = db.engine.name
            result = db.session.execute(text("SELECT 1 as test")).fetchone()
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
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
                "connection_string": safe_connection
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_type": type(e).__name__
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
                    db.create_all()
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
            app.permanent_session_lifetime = timedelta(hours=24)
            
            if current_user.is_authenticated and hasattr(current_user, 'is_online'):
                last_update_key = f'last_online_update_{current_user.id}'
                last_update = request.cookies.get(last_update_key, 0)
                try:
                    last_update = int(last_update)
                except (TypeError, ValueError):
                    last_update = 0
                    
                now = int(time.time())
                
                if now - last_update > 300:  # 5 minut = 300 sekund
                    current_user.is_online = True
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
    
    # 🔄 RETURN TUPLE (app, socketio) dla nowej architektury
    return app, socketio
