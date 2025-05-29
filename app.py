# ✅ FIXED VERSION - app.py with Socket.IO integration
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

# 🔄 ZMODERNIZOWANE IMPORTY (zgodnie z nową architekturą)
from models import db, User, ChatSession, Message, Friend, FriendRequest
from admin import init_admin
from auth import auth_bp
from chat import chat_bp, init_socketio_handlers  # ✅ ADDED Socket.IO import

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

# 🆕 NOWY SYSTEM MIGRACJI (zgodny z nową architekturą)
def apply_migrations(app):
    """Automatyczne migracje bazy danych - ZMODERNIZOWANE"""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            print("🔄 Sprawdzanie migracji bazy danych...")
            
            # === MIGRACJE TABELI USER ===
            apply_migration(inspector, 'user', 'is_online', 
                          'ALTER TABLE "user" ADD COLUMN is_online BOOLEAN DEFAULT FALSE')
            apply_migration(inspector, 'user', 'last_active', 
                          'ALTER TABLE "user" ADD COLUMN last_active TIMESTAMP')
            
            # === MIGRACJE TABELI CHAT_SESSION ===
            # STARY SYSTEM (backward compatibility)
            apply_migration(inspector, 'chat_session', 'encrypted_session_key', 
                          'ALTER TABLE "chat_session" ADD COLUMN encrypted_session_key TEXT')
            apply_migration(inspector, 'chat_session', 'key_acknowledged', 
                          'ALTER TABLE "chat_session" ADD COLUMN key_acknowledged BOOLEAN DEFAULT FALSE')
            
            # NOWY SYSTEM (dual encryption)
            apply_migration(inspector, 'chat_session', 'encrypted_keys_json', 
                          'ALTER TABLE "chat_session" ADD COLUMN encrypted_keys_json TEXT')
            apply_migration(inspector, 'chat_session', 'key_generator_id', 
                          'ALTER TABLE "chat_session" ADD COLUMN key_generator_id INTEGER')
            
            # === MIGRACJE TABELI MESSAGE ===
            apply_migration(inspector, 'message', 'is_encrypted', 
                          'ALTER TABLE "message" ADD COLUMN is_encrypted BOOLEAN DEFAULT TRUE')
            
            # === TWORZENIE NOWYCH TABEL ===
            existing_tables = inspector.get_table_names()
            
            # Tabela Friend
            if 'friend' not in existing_tables:
                create_friend_table()
                
            # Tabela FriendRequest  
            if 'friend_request' not in existing_tables:
                create_friend_request_table()
            
            print("✅ Migracje zakończone pomyślnie")
            
        except Exception as e:
            print(f"❌ Błąd podczas migracji: {e}")
            db.session.rollback()

def apply_migration(inspector, table, column, sql_statement):
    """Wykonuje pojedynczą migrację, jeśli jest potrzebna"""
    if table in inspector.get_table_names():
        columns = [c['name'] for c in inspector.get_columns(table)]
        if column not in columns:
            try:
                print(f"  📝 Dodawanie kolumny {column} do tabeli {table}")
                db.session.execute(text(sql_statement))
                db.session.commit()
                print(f"  ✅ Kolumna {column} dodana pomyślnie")
            except Exception as e:
                print(f"  ❌ Błąd podczas dodawania kolumny {column}: {e}")
                db.session.rollback()

def create_friend_table():
    """Tworzy tabelę Friend"""
    try:
        print("  📝 Tworzenie tabeli Friend")
        if is_postgresql():
            sql = """
                CREATE TABLE friend (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES "user"(id),
                    friend_id INTEGER NOT NULL REFERENCES "user"(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, friend_id)
                );
            """
        else:  # SQLite
            sql = """
                CREATE TABLE friend (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    friend_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES "user" (id),
                    FOREIGN KEY (friend_id) REFERENCES "user" (id),
                    UNIQUE(user_id, friend_id)
                );
            """
        
        db.session.execute(text(sql))
        db.session.commit()
        print("  ✅ Tabela Friend utworzona pomyślnie")
    except Exception as e:
        print(f"  ❌ Błąd podczas tworzenia tabeli Friend: {e}")
        db.session.rollback()

def create_friend_request_table():
    """Tworzy tabelę FriendRequest"""
    try:
        print("  📝 Tworzenie tabeli FriendRequest")
        if is_postgresql():
            sql = """
                CREATE TABLE friend_request (
                    id SERIAL PRIMARY KEY,
                    from_user_id INTEGER NOT NULL REFERENCES "user"(id),
                    to_user_id INTEGER NOT NULL REFERENCES "user"(id),
                    status VARCHAR(20) DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(from_user_id, to_user_id)
                );
            """
        else:  # SQLite
            sql = """
                CREATE TABLE friend_request (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user_id INTEGER NOT NULL,
                    to_user_id INTEGER NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (from_user_id) REFERENCES "user" (id),
                    FOREIGN KEY (to_user_id) REFERENCES "user" (id),
                    UNIQUE(from_user_id, to_user_id)
                );
            """
        
        db.session.execute(text(sql))
        db.session.commit()
        print("  ✅ Tabela FriendRequest utworzona pomyślnie")
    except Exception as e:
        print(f"  ❌ Błąd podczas tworzenia tabeli FriendRequest: {e}")
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
    
    # ✅ FIXED: ZMODERNIZOWANA INICJALIZACJA SOCKET.IO
    socketio = SocketIO(app, 
                       cors_allowed_origins="*", 
                       logger=False, 
                       engineio_logger=False,
                       async_mode='threading')
    
    # Inicjalizacja bazy danych i logowania
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'
    
    # 🔄 ZMODERNIZOWANE BLUEPRINTY (zgodnie z nową architekturą)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)  # ✅ Teraz zawiera wszystkie endpointy
    
    # Inicjalizacja panelu admina
    try:
        init_admin(app)
        print("✅ Panel administracyjny zainicjalizowany")
    except Exception as e:
        print(f"⚠️ Błąd inicjalizacji panelu admina: {e}")
    
    # ✅ FIXED: SOCKET.IO INTEGRATION - Teraz prawidłowo zintegrowane
    try:
        # Zainicjalizuj Socket.IO handlery z chat.py
        socketio = init_socketio_handler(socketio)
        print("✅ Socket.IO handlers zainicjalizowane")
        
        # Dodaj Socket.IO do globalnego kontekstu dla dostępu z innych modułów
        app.socketio = socketio
        
    except Exception as e:
        print(f"⚠️ Socket.IO initialization warning: {e}")
 
    # 🔄 URUCHOMIENIE MIGRACJI
    apply_migrations(app)

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

    # 🆕 NOWY DEBUG ENDPOINT z więcej informacji
    @app.route('/db-debug')
    def db_debug():
        try:
            from sqlalchemy import text, inspect
            
            engine_name = db.engine.name
            result = db.session.execute(text("SELECT 1 as test")).fetchone()
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            # Sprawdź strukturę kluczowych tabel
            table_info = {}
            for table in ['user', 'chat_session', 'message', 'friend', 'friend_request']:
                if table in tables:
                    columns = inspector.get_columns(table)
                    table_info[table] = [col['name'] for col in columns]
            
            # Bezpieczny connection string
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
                "table_columns": table_info,
                "connection_string": safe_connection,
                "modernization_status": {
                    "dual_encryption": 'encrypted_keys_json' in table_info.get('chat_session', []),
                    "friends_system": 'friend' in tables,
                    "enhanced_security": 'is_encrypted' in table_info.get('message', []),
                    "socket_io_integrated": hasattr(app, 'socketio')  # ✅ ADDED
                }
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_type": type(e).__name__
            }), 500
    
    # 🔄 ZMODERNIZOWANA INICJALIZACJA BAZY DANYCH
    with app.app_context():
        try:
            # Sprawdź połączenie
            db.session.execute(text("SELECT 1"))
            print("✅ Połączenie z bazą danych nawiązane pomyślnie")
            
            # Utwórz tabele (bezpieczna metoda)
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if not existing_tables:
                print("📊 Baza danych jest pusta, tworzę pełny schemat...")
                db.create_all()
                print("✅ Schemat bazy danych utworzony")
            else:
                print(f"📋 Znaleziono istniejące tabele: {existing_tables}")
                
                # Sprawdź, czy wszystkie modele mają odpowiadające tabele
                expected_tables = ['user', 'chat_session', 'message', 'friend', 'friend_request']
                missing_tables = [table for table in expected_tables if table not in existing_tables]
                
                if missing_tables:
                    print(f"📝 Brakujące tabele: {missing_tables}")
                    db.create_all()
                    print("✅ Dodano brakujące tabele")
                else:
                    print("✅ Wszystkie wymagane tabele istnieją")
            
        except Exception as e:
            print(f"❌ Błąd podczas inicjalizacji bazy danych: {e}")
            traceback.print_exc()
            db.session.rollback()

    # 🔄 ZMODERNIZOWANE ZARZĄDZANIE SESJĄ
    @app.before_request
    def before_request():
        """Zarządzanie sesją przed każdym żądaniem - УЛUCHSZONY"""
        try:
            app.permanent_session_lifetime = timedelta(hours=24)
            
            if current_user.is_authenticated and hasattr(current_user, 'is_online'):
                # Sprawdź czy user ma last_active (nowa kolumna)
                if not hasattr(current_user, 'last_active') or current_user.last_active is None:
                    current_user.last_active = datetime.datetime.utcnow()
                
                last_update_key = f'last_online_update_{current_user.id}'
                last_update = session.get(last_update_key, 0)
                
                try:
                    last_update = int(last_update)
                except (TypeError, ValueError):
                    last_update = 0
                    
                now = int(time.time())
                
                # Update status co 5 minut
                if now - last_update > 300:
                    current_user.is_online = True
                    current_user.last_active = datetime.datetime.utcnow()
                    session[last_update_key] = now
                    
                    try:
                        db.session.commit()
                    except:
                        db.session.rollback()
                        
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
    
    # 🔄 RETURN TUPLE dla nowej architektury
    return app, socketio

# 🆕 HELPER DO SPRAWDZANIA STATUSU MODERNIZACJI
def check_modernization_status(app):
    """Sprawdza status modernizacji aplikacji"""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            checks = {
                'dual_encryption': False,
                'friends_system': False,
                'enhanced_security': False,
                'all_tables': False,
                'socket_io_integrated': False  # ✅ ADDED
            }
            
            # Sprawdź dual encryption
            if 'chat_session' in tables:
                columns = [c['name'] for c in inspector.get_columns('chat_session')]
                checks['dual_encryption'] = 'encrypted_keys_json' in columns
            
            # Sprawdź friends system
            checks['friends_system'] = 'friend' in tables and 'friend_request' in tables
            
            # Sprawdź enhanced security
            if 'message' in tables:
                columns = [c['name'] for c in inspector.get_columns('message')]
                checks['enhanced_security'] = 'is_encrypted' in columns
            
            # Sprawdź wszystkie tabele
            expected = ['user', 'chat_session', 'message', 'friend', 'friend_request']
            checks['all_tables'] = all(table in tables for table in expected)
            
            # ✅ Sprawdź Socket.IO integration
            checks['socket_io_integrated'] = hasattr(app, 'socketio')
            
            return checks
            
        except Exception as e:
            print(f"❌ Błąd sprawdzania modernizacji: {e}")
            return {'error': str(e)}

if __name__ == '__main__':
    # Dla development
    app, socketio = create_app()
    
    # Sprawdź status modernizacji
    status = check_modernization_status(app)
    print(f"🔍 Status modernizacji: {status}")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
