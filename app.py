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

# === NAPRAWIONE AUTOMATYCZNE MIGRACJE BAZY DANYCH ===
def apply_migrations(app):
    """Automatyczne migracje bazy danych z obsługą key exchange"""
    with app.app_context():
        inspector = inspect(db.engine)
        print("🔄 Applying database migrations...")
        
        # Migracja 1: Dodanie kolumny is_online do tabeli user (jeśli nie istnieje)
        apply_migration(inspector, 'user', 'is_online', 
            'ALTER TABLE "user" ADD COLUMN is_online BOOLEAN DEFAULT FALSE')
        
        # === NOWE MIGRACJE DLA KEY EXCHANGE ===
        # Migracja 2: Dodanie kolumny encrypted_session_key do tabeli chat_session
        apply_migration(inspector, 'chat_session', 'encrypted_session_key', 
            'ALTER TABLE "chat_session" ADD COLUMN encrypted_session_key TEXT')
        
        # Migracja 3: Dodanie kolumny key_acknowledged do tabeli chat_session
        apply_migration(inspector, 'chat_session', 'key_acknowledged', 
            'ALTER TABLE "chat_session" ADD COLUMN key_acknowledged BOOLEAN DEFAULT FALSE')
        
        # Migracja 4: Dodanie kolumny key_created_at do tabeli chat_session
        apply_migration(inspector, 'chat_session', 'key_created_at', 
            'ALTER TABLE "chat_session" ADD COLUMN key_created_at TIMESTAMP')
        
        # Migracja 5: Dodanie kolumny key_acknowledged_at do tabeli chat_session
        apply_migration(inspector, 'chat_session', 'key_acknowledged_at', 
            'ALTER TABLE "chat_session" ADD COLUMN key_acknowledged_at TIMESTAMP')
        
        print("✅ Database migrations completed")

def apply_migration(inspector, table, column, sql_statement):
    """Wykonuje pojedynczą migrację, jeśli jest potrzebna"""
    if table in inspector.get_table_names():
        columns = [c['name'] for c in inspector.get_columns(table)]
        if column not in columns:
            try:
                print(f"🔄 Executing migration: Adding column {column} to table {table}")
                db.session.execute(text(sql_statement))
                db.session.commit()
                print(f"✅ Migration completed: {column} added to {table}")
            except Exception as e:
                print(f"❌ Migration error: {e}")
                db.session.rollback()
        else:
            print(f"✓ Column {column} already exists in table {table}")
    else:
        print(f"⚠️ Table {table} does not exist - will be created later")

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
    
    # 🔥 INICJALIZACJA SOCKET.IO Z POPRAWKAMI
    socketio = SocketIO(app, 
                       cors_allowed_origins="*", 
                       logger=False, 
                       engineio_logger=False,
                       async_mode='threading')
    
    # 🔥 MAKE SOCKETIO AVAILABLE GLOBALLY
    app.socketio = socketio
    
    # Inicjalizacja bazy danych i logowania
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'
    
    # 🔄 ZOPTYMALIZOWANE BLUEPRINTY (po scaleniu)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)  # ✅ chat_bp zawiera teraz wszystkie endpointy z chat_api
    
    # Inicjalizacja panelu admina
    init_admin(app)
    
    # 🔥 NAPRAWIONE SOCKET.IO HANDLERS Z FALLBACK
    with app.app_context():
        try:
            # Próbuj zaimportować handler z chat.py
            from chat import init_socketio_handler
            init_socketio_handler(socketio)
            print("✅ Socket.IO handler zainicjalizowany z chat.py")
        except Exception as e:
            print(f"⚠️ Socket.IO handler error: {e}")
            print("🔄 Inicjalizowanie fallback Socket.IO handler...")
            
            # === FALLBACK SOCKET.IO HANDLER ===
            @socketio.on('connect')
            def fallback_connect():
                print(f"🔌 Fallback: Client connected {request.sid}")
                socketio.emit('connection_ack', {
                    'message': 'Connected to server (fallback mode)',
                    'session_id': request.sid,
                    'timestamp': datetime.datetime.utcnow().isoformat()
                })
            
            @socketio.on('disconnect') 
            def fallback_disconnect():
                print(f"🔌 Fallback: Client disconnected {request.sid}")
            
            @socketio.on('register_user')
            def fallback_register_user(data):
                user_id = data.get('user_id')
                print(f"👤 Fallback: User {user_id} registered with session {request.sid}")
                # Simple acknowledgment
                socketio.emit('user_registered', {'status': 'registered'})
            
            @socketio.on('join_session')
            def fallback_join_session(data):
                session_token = data.get('session_token')
                print(f"🏠 Fallback: User joined session {session_token[:8] if session_token else 'None'}...")
                # Simple acknowledgment
                socketio.emit('session_joined', {'status': 'joined'})
            
            @socketio.on('message')
            def fallback_message(data):
                print(f"📨 Fallback: Received message data: {data}")
                # Echo back for testing
                socketio.emit('message', {
                    'type': 'fallback_echo',
                    'original_data': data,
                    'timestamp': datetime.datetime.utcnow().isoformat()
                })
            
            print("✅ Fallback Socket.IO handler initialized")
 
    # === NAPRAWIONE MIGRACJE - URUCHOM PRZED INICJALIZACJĄ TABEL ===
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

    # === ENHANCED DEBUG ENDPOINT ===
    @app.route('/db-debug')
    def db_debug():
        try:
            from sqlalchemy import text, inspect
            
            engine_name = db.engine.name
            result = db.session.execute(text("SELECT 1 as test")).fetchone()
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            # Get column info for key tables
            table_schemas = {}
            key_tables = ['user', 'chat_session', 'message', 'friend', 'friend_request']
            
            for table in key_tables:
                if table in tables:
                    try:
                        columns = inspector.get_columns(table)
                        table_schemas[table] = [{'name': col['name'], 'type': str(col['type'])} for col in columns]
                    except Exception as e:
                        table_schemas[table] = f"Error: {str(e)}"
            
            # Get record counts
            record_counts = {}
            for table in tables:
                try:
                    count = db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
                    record_counts[table] = count
                except Exception as e:
                    record_counts[table] = f"Error: {str(e)}"
            
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
                "table_schemas": table_schemas,
                "record_counts": record_counts,
                "connection_string": safe_connection,
                "key_exchange_fields": {
                    "chat_session": table_schemas.get('chat_session', 'Table not found')
                }
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_type": type(e).__name__
            }), 500
    
    # === KEY EXCHANGE DEBUG ENDPOINT ===
    @app.route('/api/debug/key_exchange')
    @login_required
    def debug_key_exchange():
        """Debug endpoint for key exchange status"""
        try:
            # Get user's active sessions
            sessions = ChatSession.query.filter(
                ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
                ChatSession.is_active == True,
                ChatSession.expires_at > datetime.datetime.utcnow()
            ).all()
            
            session_debug = []
            for session in sessions:
                is_initiator = (session.initiator_id == current_user.id)
                other_user_id = session.recipient_id if is_initiator else session.initiator_id
                other_user = User.query.get(other_user_id)
                
                session_debug.append({
                    'token': session.session_token[:8] + '...',
                    'role': 'INITIATOR' if is_initiator else 'RECIPIENT',
                    'other_user': other_user.username if other_user else 'Unknown',
                    'has_encrypted_key': bool(session.encrypted_session_key),
                    'key_length': len(session.encrypted_session_key) if session.encrypted_session_key else 0,
                    'key_is_ack': session.encrypted_session_key == 'ACK' if session.encrypted_session_key else False,
                    'key_acknowledged': session.key_acknowledged,
                    'key_ready': session.is_key_ready() if hasattr(session, 'is_key_ready') else 'Unknown',
                    'created_at': session.created_at.isoformat(),
                    'key_created_at': session.key_created_at.isoformat() if session.key_created_at else None,
                    'key_acknowledged_at': session.key_acknowledged_at.isoformat() if session.key_acknowledged_at else None
                })
            
            return jsonify({
                'status': 'success',
                'user_id': current_user.id,
                'username': current_user.username,
                'sessions': session_debug,
                'timestamp': datetime.datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    
    # === DODANE: SOCKET.IO STATUS ENDPOINT ===
    @app.route('/api/socketio/status')
    def socketio_status():
        """Status Socket.IO dla diagnostyki"""
        try:
            return jsonify({
                'status': 'active',
                'has_socketio': hasattr(app, 'socketio'),
                'socketio_mode': getattr(app.socketio, 'async_mode', 'unknown') if hasattr(app, 'socketio') else None,
                'connected_clients': len(getattr(app.socketio.server, 'manager', {}).get('rooms', {}).get('/', {})) if hasattr(app, 'socketio') else 0,
                'timestamp': datetime.datetime.utcnow().isoformat()
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    
    # Inicjalizacja bazy danych przy pierwszym uruchomieniu
    with app.app_context():
        try:
            # Sprawdź połączenie
            db.session.execute(text("SELECT 1"))
            print("✅ Database connection established successfully")
            
            # Utwórz tabele (bezpieczna metoda)
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if not existing_tables:
                print("🔄 Database is empty, creating schema...")
                db.create_all()
                print("✅ Database schema created")
            else:
                print(f"✅ Found existing tables: {existing_tables}")
                
                # Sprawdź, czy wszystkie modele mają odpowiadające tabele
                models = db.Model.__subclasses__()
                model_tables = [model.__tablename__ for model in models if hasattr(model, '__tablename__')]
                
                missing_tables = [table for table in model_tables if table not in existing_tables]
                if missing_tables:
                    print(f"🔄 Missing tables found: {missing_tables}")
                    db.create_all()
                    print("✅ Missing tables created")
                else:
                    print("✅ All required tables exist")
            
            # Verify key exchange fields exist
            if 'chat_session' in existing_tables:
                columns = [c['name'] for c in inspector.get_columns('chat_session')]
                key_fields = ['encrypted_session_key', 'key_acknowledged', 'key_created_at', 'key_acknowledged_at']
                missing_fields = [field for field in key_fields if field not in columns]
                if missing_fields:
                    print(f"⚠️ Missing key exchange fields: {missing_fields}")
                else:
                    print("✅ All key exchange fields present in chat_session table")
            
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
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
