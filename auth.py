"""
auth.py - Danaid Chat Authentication Backend v3
Dostosowany do istniejących ścieżek bazy danych Railway
Kompatybilny z istniejącymi formularzami HTML + routing
"""
import json
import secrets
import base64
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import or_
from models import db, User, ChatSession
import time
import re

# RSA imports dla weryfikacji podpisu
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    RSA_AVAILABLE = True
    print("✅ PyCryptodome available - RSA verification enabled")
except ImportError:
    RSA_AVAILABLE = False
    print("⚠️ PyCryptodome not available - RSA verification disabled")

auth_bp = Blueprint('auth', __name__)

# === KONFIGURACJA ===

# Wymagania dla hasła
PASSWORD_MIN_LENGTH = 8
PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]')

# === VIEWS (HTML PAGES) - WYMAGANE DLA ROUTING'U ===

@auth_bp.route('/')
def index():
    """Strona główna - login (index.html)"""
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('chat.chat'))
    return render_template('index.html')

@auth_bp.route('/register')
def register_page():
    """Strona rejestracji"""
    if current_user.is_authenticated:
        return redirect(url_for('chat.chat'))
    return render_template('register.html')

@auth_bp.route('/login')
def login_page():
    """Redirect do strony głównej"""
    return redirect(url_for('auth.index'))

# === UTILITY FUNCTIONS ===

def validate_password(password):
    """Waliduje hasło zgodnie z wymaganiami bezpieczeństwa"""
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f'Password must be at least {PASSWORD_MIN_LENGTH} characters long'
    
    if not PASSWORD_PATTERN.match(password):
        return False, 'Password must contain uppercase letter, lowercase letter, number and special character'
    
    return True, 'Password is valid'

def validate_username(username):
    """Waliduje nazwę użytkownika"""
    if not username or len(username.strip()) < 3:
        return False, 'Username must be at least 3 characters long'
    
    if len(username) > 50:
        return False, 'Username must be less than 50 characters'
    
    # Sprawdź czy zawiera tylko dozwolone znaki
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, 'Username can only contain letters, numbers, dots, hyphens and underscores'
        
    return True, 'Username is valid'

def validate_rsa_public_key(public_key_pem):
    """Waliduje klucz publiczny RSA"""
    if not RSA_AVAILABLE:
        print("⚠️ RSA validation skipped - PyCryptodome not available")
        return True, 'RSA validation skipped'
    
    try:
        # Import klucza publicznego
        key = RSA.import_key(public_key_pem)
        
        # Sprawdź długość klucza (minimum 2048 bitów)
        if key.size_in_bits() < 2048:
            return False, 'RSA key must be at least 2048 bits'
        
        # Sprawdź czy to klucz publiczny
        if key.has_private():
            return False, 'Provided key appears to be private key, not public key'
            
        return True, 'RSA public key is valid'
        
    except (ValueError, TypeError) as e:
        return False, f'Invalid RSA public key format: {str(e)}'

def verify_password_signature(password, signature_base64, public_key_pem):
    """Weryfikuje podpis cyfrowy hasła"""
    if not RSA_AVAILABLE:
        print("⚠️ RSA signature verification skipped - PyCryptodome not available")
        return True
    
    try:
        # Dekoduj podpis z Base64
        signature = base64.b64decode(signature_base64)
        
        # Import klucza publicznego
        public_key = RSA.import_key(public_key_pem)
        
        # Przygotuj dane do weryfikacji (bajty hasła)
        password_bytes = password.encode('utf-8')
        h = SHA256.new(password_bytes)
        
        # Weryfikuj podpis
        verifier = pkcs1_15.new(public_key)
        verifier.verify(h, signature)
        
        print("✅ RSA signature verified successfully")
        return True
        
    except Exception as e:
        print(f"❌ RSA signature verification failed: {e}")
        return False

def generate_unique_user_id():
    """Generuje unikalny 6-cyfrowy identyfikator użytkownika"""
    max_attempts = 100
    
    for attempt in range(max_attempts):
        user_id = str(secrets.randbelow(900000) + 100000)  # 100000-999999
        
        if not User.query.filter_by(user_id=user_id).first():
            return user_id
    
    # Fallback z timestamp
    timestamp = str(int(time.time()))[-3:]
    random_part = str(secrets.randbelow(1000)).zfill(3)
    return random_part + timestamp

# === API ENDPOINTS ===

@auth_bp.route('/api/register', methods=['POST'])
def register():
    """
    Rejestracja użytkownika z weryfikacją kryptograficzną
    Endpoint: POST /api/register
    JSON: {username, password, public_key}
    """
    try:
        # Sprawdź Content-Type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        public_key = data.get('public_key', '').strip()
        
        # Walidacja podstawowych danych
        if not all([username, password, public_key]):
            return jsonify({'error': 'Missing required fields: username, password, public_key'}), 400
        
        # Walidacja nazwy użytkownika
        username_valid, username_msg = validate_username(username)
        if not username_valid:
            return jsonify({'error': username_msg}), 400
        
        # Walidacja hasła
        password_valid, password_msg = validate_password(password)
        if not password_valid:
            return jsonify({'error': password_msg}), 400
        
        # Walidacja klucza publicznego RSA
        key_valid, key_msg = validate_rsa_public_key(public_key)
        if not key_valid:
            return jsonify({'error': key_msg}), 400
        
        # Sprawdź czy użytkownik już istnieje
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 409
        
        # Generuj unikalny user_id
        user_id = generate_unique_user_id()
        
        # Utwórz nowego użytkownika
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            public_key=public_key,
            user_id=user_id,
            is_admin=False
        )
        
        # Ustaw wartości domyślne dla nowych kolumn (jeśli istnieją)
        if hasattr(user, 'is_online'):
            user.is_online = False
        if hasattr(user, 'last_active'):
            user.last_active = datetime.utcnow()
        
        # Zapisz do bazy danych
        db.session.add(user)
        db.session.commit()
        
        print(f"✅ User registered successfully: {username} (ID: {user_id})")
        
        return jsonify({
            'status': 'success',
            'user_id': user_id,
            'message': 'Registration successful',
            'registration_ok': True
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Registration error: {str(e)}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login():
    """
    Logowanie użytkownika z weryfikacją podpisu RSA
    Endpoint: POST /api/login  
    JSON: {username, password, signature}
    """
    try:
        # Sprawdź Content-Type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        signature_base64 = data.get('signature', '')
        
        # Walidacja podstawowych danych
        if not all([username, password]):
            return jsonify({'error': 'Missing credentials: username and password required'}), 400
        
        # Znajdź użytkownika
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"❌ Login failed: User not found - {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Sprawdź hasło
        if not check_password_hash(user.password_hash, password):
            print(f"❌ Login failed: Invalid password - {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Weryfikacja podpisu RSA (jeśli podano)
        if signature_base64:
            if not verify_password_signature(password, signature_base64, user.public_key):
                print(f"❌ Login failed: RSA signature verification failed - {username}")
                return jsonify({'error': 'RSA signature verification failed'}), 401
        elif RSA_AVAILABLE:
            # Jeśli RSA jest dostępne ale nie podano podpisu, wymagaj go
            return jsonify({'error': 'RSA signature required for authentication'}), 400
        
        # Logowanie użytkownika do Flask-Login
        login_user(user, remember=True)
        
        # Aktualizuj status online (jeśli kolumna istnieje)
        try:
            if hasattr(user, 'is_online'):
                user.is_online = True
            if hasattr(user, 'last_active'):
                user.last_active = datetime.utcnow()
            db.session.commit()
            print(f"✅ User status updated: {username} is now online")
        except Exception as e:
            print(f"⚠️ Status update failed for {username}: {e}")
            db.session.rollback()
        
        # Ustaw sesję
        session.permanent = True
        session[f'last_online_update_{user.id}'] = int(time.time())
        
        print(f"✅ Login successful: {username} (ID: {user.user_id})")
        
        return jsonify({
            'status': 'success',
            'user_id': user.user_id,
            'username': user.username,
            'is_admin': user.is_admin,
            'message': 'Login successful',
            'login_ok': True
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Login error: {str(e)}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@auth_bp.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """
    Wylogowanie użytkownika z czyszczeniem sesji
    Endpoint: POST /api/logout
    """
    try:
        username = current_user.username
        user_id = current_user.user_id
        
        print(f"🔓 Starting logout for user: {username}")
        
        # Aktualizuj status offline (jeśli kolumna istnieje)
        try:
            if hasattr(current_user, 'is_online'):
                current_user.is_online = False
            if hasattr(current_user, 'last_active'):
                current_user.last_active = datetime.utcnow()
            db.session.commit()
            print(f"✅ User status updated: {username} is now offline")
        except Exception as e:
            print(f"⚠️ Status update failed during logout: {e}")
            db.session.rollback()
        
        # Wyloguj użytkownika z Flask-Login
        logout_user()
        
        # Wyczyść sesję
        session.clear()
        
        print(f"✅ Logout successful: {username}")
        
        return jsonify({
            'status': 'success',
            'message': 'Logged out successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Logout error: {str(e)}")
        
        # Mimo błędu, wyloguj użytkownika
        logout_user()
        session.clear()
        
        return jsonify({
            'status': 'warning',
            'message': 'Logged out but status update may have failed',
            'error': str(e)
        }), 200

@auth_bp.route("/logout")
def logout_redirect():
    """
    Przekierowanie wylogowania z czyszczeniem cache
    """
    try:
        if current_user.is_authenticated and hasattr(current_user, 'is_online'):
            current_user.is_online = False
            db.session.commit()
    except Exception:
        db.session.rollback()
    
    logout_user()
    session.clear()
    
    response = redirect(url_for('/'))
    
    # Wyczyść wszystkie ciasteczka związane z sesją
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    response.delete_cookie('session_id')
    
    # Ustaw ciasteczka na wygasłe
    response.set_cookie('session', '', expires=0)
    response.set_cookie('remember_token', '', expires=0)
    
    # Nagłówki zapobiegające cache'owaniu
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    return response

@auth_bp.route('/api/check_auth')
@login_required
def check_auth():
    """
    Sprawdza status autoryzacji - KLUCZOWY ENDPOINT
    Endpoint: GET /api/check_auth
    """
    try:
        user_data = {
            'authenticated': True,
            'user_id': current_user.user_id,
            'username': current_user.username,
            'is_admin': current_user.is_admin,
            'id': current_user.id,  # Potrzebne dla kompatybilności z chat.js
        }
        
        # Dodaj dodatkowe pola jeśli istnieją
        if hasattr(current_user, 'is_online'):
            user_data['is_online'] = current_user.is_online
        else:
            user_data['is_online'] = False
            
        if hasattr(current_user, 'last_active') and current_user.last_active:
            user_data['last_active'] = current_user.last_active.isoformat()
        else:
            user_data['last_active'] = None
            
        return jsonify(user_data)
        
    except Exception as e:
        print(f"❌ Auth check error: {str(e)}")
        return jsonify({'error': 'Authentication check failed'}), 500

# === ENDPOINTY ZARZĄDZANIA UŻYTKOWNIKAMI ===

@auth_bp.route('/api/user/<user_id>/public_key')
@login_required
def get_user_public_key(user_id):
    """
    Pobiera klucz publiczny użytkownika
    Endpoint: GET /api/user/<user_id>/public_key
    """
    try:
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'status': 'success',
            'user_id': user.user_id,
            'username': user.username,
            'public_key': user.public_key
        })
        
    except Exception as e:
        print(f"❌ Error getting public key for user {user_id}: {str(e)}")
        return jsonify({'error': 'Failed to retrieve public key'}), 500

@auth_bp.route('/api/users')
@login_required  
def get_users():
    """
    Lista wszystkich użytkowników (poza aktualnym)
    Endpoint: GET /api/users
    """
    try:
        users = User.query.filter(User.id != current_user.id).all()
        
        user_list = []
        for user in users:
            user_data = {
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username
            }
            
            # Dodaj status online jeśli kolumna istnieje
            if hasattr(user, 'is_online'):
                user_data['is_online'] = user.is_online
            else:
                user_data['is_online'] = False
                
            # Dodaj last_active jeśli istnieje
            if hasattr(user, 'last_active') and user.last_active:
                user_data['last_active'] = user.last_active.isoformat()
            else:
                user_data['last_active'] = None
                
            user_list.append(user_data)
        
        return jsonify({
            'status': 'success', 
            'users': user_list,
            'count': len(user_list)
        })
        
    except Exception as e:
        print(f"❌ Error getting users list: {str(e)}")
        return jsonify({'error': 'Failed to retrieve users list'}), 500

@auth_bp.route('/api/online_users')
@login_required
def get_online_users():
    """
    Lista użytkowników online
    Endpoint: GET /api/online_users
    """
    try:
        if hasattr(User, 'is_online'):
            online_users = User.query.filter(
                User.is_online == True, 
                User.id != current_user.id
            ).all()
            
            online_list = []
            for user in online_users:
                user_data = {
                    'id': user.id, 
                    'user_id': user.user_id, 
                    'username': user.username
                }
                
                if hasattr(user, 'last_active') and user.last_active:
                    user_data['last_active'] = user.last_active.isoformat()
                    
                online_list.append(user_data)
            
            return jsonify({
                'status': 'success',
                'online_users': online_list,
                'count': len(online_list)
            })
        else:
            # Fallback gdy kolumna is_online nie istnieje
            return jsonify({
                'status': 'success', 
                'online_users': [],
                'count': 0,
                'note': 'Online status tracking not available'
            })
            
    except Exception as e:
        print(f"❌ Error getting online users: {str(e)}")
        return jsonify({'error': 'Failed to retrieve online users'}), 500

# === ENDPOINTY POMOCNICZE ===

@auth_bp.route('/api/auth/status')
def auth_status():
    """
    Publiczny endpoint sprawdzający dostępność systemu uwierzytelniania
    """
    return jsonify({
        'auth_system': 'Danaid Chat E2EE Authentication',
        'version': '3.0',
        'rsa_available': RSA_AVAILABLE,
        'deployment': 'Railway',
        'features': {
            'registration': True,
            'login': True,
            'rsa_signature_verification': RSA_AVAILABLE,
            'session_management': True,
            'online_status': True
        },
        'endpoints': {
            'register': '/api/register',
            'login': '/api/login',
            'logout': '/api/logout',
            'check_auth': '/api/check_auth',
            'users': '/api/users',
            'online_users': '/api/online_users'
        }
    })

# === ERROR HANDLERS ===

@auth_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@auth_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@auth_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

@auth_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@auth_bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

print("✅ Danaid Auth Backend v3 loaded - E2EE Authentication API Ready - Railway Compatible")
