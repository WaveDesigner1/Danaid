"""
app.py - Refactored Flask Application Factory
Clean SQLite-focused setup with integrated Socket.IO and admin panel
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response, session
from flask_cors import CORS
from flask_login import LoginManager, current_user,  login_required
from flask_socketio import SocketIO
from sqlalchemy import text, inspect
from flask_sqlalchemy import SQLAlchemy 
import traceback

# Import local modules
from models import db, User, ChatSession, Message, Friend, FriendRequest
from auth import auth_bp
from chat import chat_bp, init_socketio_handler

# ================================================
# LOGGING SETUP
# ================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ================================================
# LOGIN MANAGER SETUP
# ================================================

login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f"Error loading user: {e}")
        return None

# ================================================
# DATABASE UTILITY FUNCTIONS
# ================================================

def is_sqlite():
    """Check if using SQLite database"""
    return db.engine.name == 'sqlite'

def is_postgresql():
    """Check if using PostgreSQL database"""
    return db.engine.name == 'postgresql'

# ================================================
# DATABASE MIGRATIONS
# ================================================

def apply_migrations(app):
    """Apply database migrations automatically"""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            logger.info("Checking database migrations...")
            
            # Apply user table migrations
            apply_migration(inspector, 'user', 'is_online', 
                          'ALTER TABLE "user" ADD COLUMN is_online BOOLEAN DEFAULT FALSE')
            apply_migration(inspector, 'user', 'last_active', 
                          'ALTER TABLE "user" ADD COLUMN last_active TIMESTAMP')
            apply_migration(inspector, 'user', 'is_admin', 
                          'ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT FALSE NOT NULL')
            
            # Apply chat_session table migrations
            apply_migration(inspector, 'chat_session', 'encrypted_session_key', 
                          'ALTER TABLE "chat_session" ADD COLUMN encrypted_session_key TEXT')
            apply_migration(inspector, 'chat_session', 'key_acknowledged', 
                          'ALTER TABLE "chat_session" ADD COLUMN key_acknowledged BOOLEAN DEFAULT FALSE')
            apply_migration(inspector, 'chat_session', 'encrypted_keys_json', 
                          'ALTER TABLE "chat_session" ADD COLUMN encrypted_keys_json TEXT')
            apply_migration(inspector, 'chat_session', 'key_generator_id', 
                          'ALTER TABLE "chat_session" ADD COLUMN key_generator_id INTEGER')
            
            # Apply message table migrations
            apply_migration(inspector, 'message', 'is_encrypted', 
                          'ALTER TABLE "message" ADD COLUMN is_encrypted BOOLEAN DEFAULT TRUE')
            
            # Create new tables if needed
            existing_tables = inspector.get_table_names()
            
            if 'friend' not in existing_tables:
                create_friend_table()
                
            if 'friend_request' not in existing_tables:
                create_friend_request_table()
            
            # Create first admin if needed
            create_first_admin_if_needed()
            
            logger.info("Database migrations completed successfully")
            
        except Exception as e:
            logger.error(f"Error during migrations: {e}")
            db.session.rollback()

def apply_migration(inspector, table, column, sql_statement):
    """Apply single migration if needed"""
    if table in inspector.get_table_names():
        columns = [c['name'] for c in inspector.get_columns(table)]
        if column not in columns:
            try:
                logger.info(f"Adding column {column} to table {table}")
                db.session.execute(text(sql_statement))
                db.session.commit()
                logger.info(f"Column {column} added successfully")
                
                # Special cases after column addition
                if table == 'user' and column == 'is_admin':
                    db.session.execute(text('UPDATE "user" SET is_admin = FALSE WHERE is_admin IS NULL'))
                    db.session.commit()
                    logger.info("Updated NULL is_admin values to FALSE")
                    
            except Exception as e:
                logger.error(f"Error adding column {column}: {e}")
                db.session.rollback()

def create_friend_table():
    """Create Friend table"""
    try:
        logger.info("Creating Friend table")
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
        logger.info("Friend table created successfully")
    except Exception as e:
        logger.error(f"Error creating Friend table: {e}")
        db.session.rollback()

def create_friend_request_table():
    """Create FriendRequest table"""
    try:
        logger.info("Creating FriendRequest table")
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
        logger.info("FriendRequest table created successfully")
    except Exception as e:
        logger.error(f"Error creating FriendRequest table: {e}")
        db.session.rollback()

def create_first_admin_if_needed():
    """Create first admin if no admins exist"""
    try:
        inspector = inspect(db.engine)
        user_columns = [c['name'] for c in inspector.get_columns('user')]
        
        if 'is_admin' not in user_columns:
            logger.warning("is_admin column does not exist - will be added by migration")
            return
        
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count == 0:
            logger.info("No admins found, checking if we should create one...")
            
            # Check for user named 'admin'
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user:
                admin_user.is_admin = True
                db.session.commit()
                logger.info(f"User 'admin' granted admin privileges")
            else:
                # Grant admin to first user
                first_user = User.query.first()
                if first_user:
                    first_user.is_admin = True
                    db.session.commit()
                    logger.info(f"First user '{first_user.username}' granted admin privileges")
                else:
                    logger.info("No users in system yet - admin will be created during registration")
        else:
            logger.info(f"Found {admin_count} admin(s) in system")
                    
    except Exception as e:
        logger.error(f"Error creating first admin: {e}")
        db.session.rollback()

# ================================================
# APPLICATION FACTORY
# ================================================

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    CORS(app, supports_credentials=True)
    
    # ================================================
    # DATABASE CONFIGURATION
    # ================================================
    
    # SQLite-focused configuration
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        database_url = 'sqlite:///danaid_refactored.db'
        logger.info('Using default SQLite database')
    
    # Handle PostgreSQL URL format if provided
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # ================================================
    # SECURITY CONFIGURATION
    # ================================================
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        app.config['SECRET_KEY'] = 'danaid-dev-key-change-in-production'
        logger.warning('Using default SECRET_KEY - change in production!')
    
    # Session configuration
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    
    # ================================================
    # SOCKETIO INITIALIZATION
    # ================================================
    
    socketio = SocketIO(app, 
                       cors_allowed_origins="*", 
                       logger=False, 
                       engineio_logger=False,
                       async_mode='threading')
    
    # ================================================
    # DATABASE AND LOGIN INITIALIZATION
    # ================================================
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'
    
    # ================================================
    # BLUEPRINT REGISTRATION
    # ================================================
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    
    # ================================================
    # ADMIN PANEL INITIALIZATION
    # ================================================
    
    try:
        from admin import init_admin
        init_admin(app)
        logger.info("Admin panel initialized")
    except Exception as e:
        logger.warning(f"Admin panel initialization failed: {e}")
    
    # ================================================
    # SOCKETIO HANDLER INITIALIZATION
    # ================================================
    
    try:
        socketio = init_socketio_handler(socketio)
        app.socketio = socketio
        logger.info("Socket.IO handlers initialized")
    except Exception as e:
        logger.warning(f"Socket.IO initialization failed: {e}")
 
    # ================================================
    # DATABASE SETUP
    # ================================================
    
    with app.app_context():
        try:
            # Test database connection
            db.session.execute(text("SELECT 1"))
            logger.info("Database connection established successfully")
            
            # Create tables if needed
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if not existing_tables:
                logger.info("Database is empty, creating full schema...")
                db.create_all()
                logger.info("Database schema created")
            else:
                logger.info(f"Found existing tables: {existing_tables}")
                
                # Check for missing tables
                expected_tables = ['user', 'chat_session', 'message', 'friend', 'friend_request']
                missing_tables = [table for table in expected_tables if table not in existing_tables]
                
                if missing_tables:
                    logger.info(f"Creating missing tables: {missing_tables}")
                    db.create_all()
                    logger.info("Missing tables created")
                else:
                    logger.info("All required tables exist")
                    
            # Apply migrations
            apply_migrations(app)
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            traceback.print_exc()
            db.session.rollback()

    # ================================================
    # SESSION MANAGEMENT
    # ================================================
    
    @app.before_request
    def before_request():
        """Manage session before each request"""
        try:
            app.permanent_session_lifetime = timedelta(hours=24)
            
            if current_user.is_authenticated and hasattr(current_user, 'is_online'):
                # Update last_active if column exists
                if not hasattr(current_user, 'last_active') or current_user.last_active is None:
                    current_user.last_active = datetime.utcnow()
                
                last_update_key = f'last_online_update_{current_user.id}'
                last_update = session.get(last_update_key, 0)
                
                try:
                    last_update = int(last_update)
                except (TypeError, ValueError):
                    last_update = 0
                    
                now = int(time.time())
                
                # Update status every 5 minutes
                if now - last_update > 300:
                    current_user.is_online = True
                    current_user.last_active = datetime.utcnow()
                    session[last_update_key] = now
                    
                    try:
                        db.session.commit()
                    except:
                        db.session.rollback()
                        
        except Exception as e:
            logger.error(f"Error in before_request: {e}")
            db.session.rollback()
            
    @app.after_request
    def after_request(response):
        """Set cookie with last online update time"""
        if current_user.is_authenticated and hasattr(current_user, 'is_online'):
            last_update_key = f'last_online_update_{current_user.id}'
            response.set_cookie(last_update_key, str(int(time.time())), max_age=3600)
        return response
    
    # ================================================
    # API ENDPOINTS
    # ================================================
    
    @app.route('/api/websocket/config')
    def websocket_config():
        """Provide Socket.IO configuration for client"""
        host = request.host
        
        return jsonify({
            'socketUrl': f"https://{host}" if request.is_secure else f"http://{host}",
            'path': '/socket.io/'
        })
    
    @app.route('/socket-config.js')
    def socket_config_js():
        """Generate JavaScript configuration for Socket.IO"""
        host = request.host
        
        config = {
            'socketUrl': f"https://{host}" if request.is_secure else f"http://{host}",
            'path': '/socket.io/'
        }
        
        js_content = f"window._socketConfig = {json.dumps(config)};"
        return Response(js_content, mimetype='application/javascript')

    # ================================================
    # DEBUG ENDPOINTS
    # ================================================
    
    @app.route('/db-debug')
    def db_debug():
        """Database debug information"""
        try:
            engine_name = db.engine.name
            result = db.session.execute(text("SELECT 1 as test")).fetchone()
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            # Check table structures
            table_info = {}
            for table in ['user', 'chat_session', 'message', 'friend', 'friend_request']:
                if table in tables:
                    columns = inspector.get_columns(table)
                    table_info[table] = [col['name'] for col in columns]
            
            # Admin information
            admin_info = {}
            try:
                admin_count = User.query.filter_by(is_admin=True).count()
                admins = User.query.filter_by(is_admin=True).all()
                admin_info = {
                    'admin_count': admin_count,
                    'admins': [{'username': a.username, 'user_id': a.user_id} for a in admins],
                    'has_is_admin_column': 'is_admin' in table_info.get('user', [])
                }
            except Exception as e:
                admin_info = {'error': str(e)}
            
            # Safe connection string
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
                "admin_info": admin_info,
                "refactor_status": {
                    "dual_encryption": 'encrypted_keys_json' in table_info.get('chat_session', []),
                    "friends_system": 'friend' in tables,
                    "enhanced_security": 'is_encrypted' in table_info.get('message', []),
                    "socket_io_integrated": hasattr(app, 'socketio'),
                    "admin_system": 'is_admin' in table_info.get('user', []),
                    "auto_switch_ready": True  # New feature indicator
                }
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_type": type(e).__name__
            }), 500
    
    # ================================================
    # ADMIN MANAGEMENT API
    # ================================================
    
    @app.route('/api/admin/manage')
    @login_required
    def admin_manage():
        """Admin management endpoint"""
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            return jsonify({
                'status': 'success',
                'admin_functions': {
                    'debug_admin_users': '/api/admin/debug-users',
                    'list_admins': '/api/admin/list',
                    'database_info': '/db-debug'
                },
                'current_admin': {
                    'username': current_user.username,
                    'user_id': current_user.user_id
                }
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ================================================
    # SESSION CHECK
    # ================================================
    
    @app.route('/check_session')
    def check_session():
        """Check user session status"""
        try:
            if current_user and current_user.is_authenticated:
                return jsonify({
                    'authenticated': True,
                    'user_id': getattr(current_user, 'user_id', None) or getattr(current_user, 'id', None),
                    'username': getattr(current_user, 'username', 'unknown'),
                    'is_admin': getattr(current_user, 'is_admin', False),
                    'session_valid': True
                })
            else:
                return jsonify({
                    'authenticated': False,
                    'session_valid': False
                })
                
        except Exception as e:
            logger.error(f"Session check error: {e}")
            return jsonify({
                'authenticated': False,
                'session_valid': False,
                'error': str(e)
            }), 200
    
    # ================================================
    # SECURITY HEADERS
    # ================================================
    
    @app.after_request
    def add_security_headers(response):
        """Add security headers to responses"""
        try:
            if request.path.startswith(('/api/', '/admin_dashboard')):
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
        except:
            pass
        return response

    logger.info("Flask application created successfully")
    return app, socketio

# ================================================
# UTILITY FUNCTIONS
# ================================================

def check_refactor_status(app):
    """Check refactor completion status"""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            checks = {
                'dual_encryption': False,
                'friends_system': False,
                'enhanced_security': False,
                'all_tables': False,
                'socket_io_integrated': False,
                'admin_system': False,
                'auto_switch_ready': False
            }
            
            # Check dual encryption
            if 'chat_session' in tables:
                columns = [c['name'] for c in inspector.get_columns('chat_session')]
                checks['dual_encryption'] = 'encrypted_keys_json' in columns
            
            # Check friends system
            checks['friends_system'] = 'friend' in tables and 'friend_request' in tables
            
            # Check enhanced security
            if 'message' in tables:
                columns = [c['name'] for c in inspector.get_columns('message')]
                checks['enhanced_security'] = 'is_encrypted' in columns
            
            # Check admin system
            if 'user' in tables:
                columns = [c['name'] for c in inspector.get_columns('user')]
                checks['admin_system'] = 'is_admin' in columns
            
            # Check all tables
            expected = ['user', 'chat_session', 'message', 'friend', 'friend_request']
            checks['all_tables'] = all(table in tables for table in expected)
            
            # Check Socket.IO integration
            checks['socket_io_integrated'] = hasattr(app, 'socketio')
            
            # Auto-switch is ready if chat.py has the emit_auto_switch_message function
            checks['auto_switch_ready'] = True  # Implemented in refactored chat.py
            
            return checks
            
        except Exception as e:
            logger.error(f"Error checking refactor status: {e}")
            return {'error': str(e)}

# ================================================
# ADMIN CONSOLE FUNCTIONS
# ================================================

def make_user_admin(username):
    """Console function to make user admin"""
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            db.session.commit()
            logger.info(f"User '{username}' is now admin")
            return True
        else:
            logger.error(f"User '{username}' not found")
            return False
    except Exception as e:
        logger.error(f"Error making user admin: {e}")
        db.session.rollback()
        return False

def list_all_admins():
    """Console function to list all admins"""
    try:
        admins = User.query.filter_by(is_admin=True).all()
        logger.info(f"Current admins ({len(admins)}):")
        for admin in admins:
            logger.info(f"  - {admin.username} (ID: {admin.user_id})")
        return admins
    except Exception as e:
        logger.error(f"Error listing admins: {e}")
        return []

if __name__ == '__main__':
    # For development testing
    app, socketio = create_app()
    
    # Check refactor status
    status = check_refactor_status(app)
    logger.info(f"Refactor status: {status}")
    
    # Admin info on startup
    with app.app_context():
        try:
            logger.info("ADMIN SYSTEM STATUS")
            list_all_admins()
        except Exception as e:
            logger.warning(f"Admin check failed: {e}")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)