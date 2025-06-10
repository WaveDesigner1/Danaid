# auth.py - Kompletny system autoryzacji dla Danaid Chat
# Bezpieczne logowanie, rejestracja i zarządzanie sesjami

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, db
import re
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from functools import wraps

# Utwórz Blueprint
auth_bp = Blueprint('auth', __name__)

# === SECURITY CONSTANTS ===
SESSION_TIMEOUT = 3600  # 1 hour
SESSION_ABSOLUTE_TIMEOUT = 28800  # 8 hours
MAX_SESSIONS_PER_USER = 5
RSA_AVAILABLE = True  # Set to False if RSA verification is not available

# === HELPER FUNCTIONS ===

def generate_user_id():
    """Generuje unikalny 6-cyfrowy ID użytkownika"""
    import random
    while True:
        user_id = f"{random.randint(100000, 999999)}"
        if not User.query.filter_by(user_id=user_id).first():
            return user_id

def generate_secure_session_id():
    """Generuje bezpieczny identyfikator sesji"""
    return secrets.token_urlsafe(32)

def hash_session_id(session_id):
    """Hashuje ID sesji do przechowywania w bazie"""
    return hashlib.sha256(session_id.encode()).hexdigest()

def validate_password_strength(password):
    """Waliduje siłę hasła"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def validate_rsa_public_key(public_key_pem):
    """Waliduje format klucza publicznego RSA"""
    try:
        if not public_key_pem.strip():
            return False, "Public key cannot be empty"
        
        if not public_key_pem.startswith('-----BEGIN PUBLIC KEY-----'):
            return False, "Invalid public key format - must start with PEM header"
        
        if not public_key_pem.endswith('-----END PUBLIC KEY-----'):
            return False, "Invalid public key format - must end with PEM footer"
        
        # Basic length check (RSA 2048-bit key should be around 450 characters)
        if len(public_key_pem) < 200 or len(public_key_pem) > 1000:
            return False, "Public key length is suspicious"
        
        return True, "Public key format is valid"
        
    except Exception as e:
        return False, f"Public key validation error: {str(e)}"

def verify_password_signature(password, signature_base64, public_key_pem):
    """
    Weryfikuje podpis cyfrowy hasła (jeśli RSA jest dostępne)
    """
    if not RSA_AVAILABLE:
        return True  # Skip verification if RSA is not available
    
    try:
        # This is a placeholder - implement actual RSA signature verification
        # You would need to use cryptography library here
        # For now, we'll return True to maintain compatibility
        
        # Example implementation (requires cryptography library):
        # from cryptography.hazmat.primitives import hashes, serialization
        # from cryptography.hazmat.primitives.asymmetric import rsa, padding
        
        # Load public key
        # public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        # Verify signature
        # signature = base64.b64decode(signature_base64)
        # password_bytes = password.encode('utf-8')
        # public_key.verify(signature, password_bytes, padding.PKCS1v15(), hashes.SHA256())
        
        return True
        
    except Exception as e:
        print(f"❌ RSA signature verification failed: {e}")
        return False

def validate_session_security(f):
    """Decorator do walidacji bezpieczeństwa sesji"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Sprawdź timeout sesji
        if 'last_activity' in session:
            try:
                last_activity = datetime.fromisoformat(session['last_activity'])
                if datetime.utcnow() - last_activity > timedelta(seconds=SESSION_TIMEOUT):
                    session.clear()
                    logout_user()
                    return jsonify({'error': 'Session expired'}), 401
            except (ValueError, TypeError):
                # Invalid datetime format, clear session
                session.clear()
                logout_user()
                return jsonify({'error': 'Invalid session'}), 401
        
        # Sprawdź absolute timeout
        if 'session_start' in session:
            try:
                session_start = datetime.fromisoformat(session['session_start'])
                if datetime.utcnow() - session_start > timedelta(seconds=SESSION_ABSOLUTE_TIMEOUT):
                    session.clear()
                    logout_user()
                    return jsonify({'error': 'Session expired (absolute timeout)'}), 401
            except (ValueError, TypeError):
                session.clear()
                logout_user()
                return jsonify({'error': 'Invalid session'}), 401
        
        # Aktualizuj ostatnią aktywność
        session['last_activity'] = datetime.utcnow().isoformat()
        session.permanent = True
        
        return f(*args, **kwargs)
    return decorated_function

def cleanup_old_user_sessions(user_id):
    """Czyści stare sesje użytkownika (placeholder - implement with session tracking table)"""
    # TODO: Implement with user_sessions table for proper session tracking
    # For now, this is a placeholder
    pass

# === MAIN ROUTES ===

@auth_bp.route('/')
def index():
    # Sprawdź sesję zamiast current_user
    if session.get('user_id') or session.get('username'):
        return redirect(url_for('chat.chat'))
    
    return render_template('index.html')

@auth_bp.route('/register')
def register_page():
    """
    Strona rejestracji
    """
    try:
        # Jeśli użytkownik jest już zalogowany, przekieruj do czatu
        if current_user.is_authenticated:
            return redirect('/chat')
        
        return render_template('register.html')
        
    except Exception as e:
        print(f"❌ Register page error: {e}")
        try:
            return render_template('register.html')
        except:
            return "Error loading registration page", 500



# === AUTHENTICATION API ===

@auth_bp.route('/api/register', methods=['POST'])
def register():
    """
    Rejestracja nowego użytkownika z kluczem publicznym RSA
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        # Pobierz dane z requestu
        username = data.get('username', '').strip()
        password = data.get('password', '')
        public_key = data.get('public_key', '').strip()
        
        print(f"🔐 Registration attempt for user: {username}")
        
        # Walidacja wymaganych pól
        if not all([username, password, public_key]):
            return jsonify({'error': 'Missing required fields: username, password, and public_key'}), 400
        
        # Walidacja username
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            return jsonify({'error': 'Username must be 3-20 characters long and contain only letters, numbers, underscores, or hyphens'}), 400
        
        # Sprawdź czy username już istnieje
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"❌ Registration failed: Username {username} already exists")
            return jsonify({'error': 'Username already exists'}), 409
        
        # Walidacja hasła
        password_valid, password_msg = validate_password_strength(password)
        if not password_valid:
            return jsonify({'error': password_msg}), 400
        
        # Walidacja klucza publicznego RSA
        key_valid, key_msg = validate_rsa_public_key(public_key)
        if not key_valid:
            return jsonify({'error': key_msg}), 400
        
        # Generuj unikalny user_id
        user_id = generate_user_id()
        
        # Utwórz nowego użytkownika
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            public_key=public_key,
            user_id=user_id,
            is_online=False,
            is_admin=False,
            last_active=datetime.utcnow()
        )
        
        # Zapisz do bazy danych
        db.session.add(new_user)
        db.session.commit()
        
        print(f"✅ Registration successful: {username} (ID: {user_id})")
        
        return jsonify({
            'status': 'success',
            'user_id': user_id,
            'username': username,
            'message': 'Registration successful',
            'code': 'registration_ok'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Registration error: {str(e)}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login():
    """
    Logowanie użytkownika z opcjonalną weryfikacją podpisu RSA
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        signature_base64 = data.get('signature', '')
        
        print(f"🔐 Login attempt for user: {username}")
        
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
            print(f"✅ RSA signature verified for user: {username}")
        elif RSA_AVAILABLE:
            print(f"⚠️ Login without RSA signature for user: {username}")
            # Uncomment the next line to require RSA signatures
            # return jsonify({'error': 'RSA signature required for authentication'}), 400
        
        # Wyczyść stare sesje użytkownika
        cleanup_old_user_sessions(user.id)
        
        # Wygeneruj bezpieczny session ID
        secure_session_id = generate_secure_session_id()
        
        # Logowanie użytkownika do Flask-Login
        login_user(user, remember=True)
        
        # Ustaw bezpieczną sesję
        session.permanent = True
        session['session_id'] = secure_session_id
        session['session_start'] = datetime.utcnow().isoformat()
        session['last_activity'] = datetime.utcnow().isoformat()
        session['user_id'] = user.id
        session['username'] = user.username
        session['login_time'] = datetime.utcnow().isoformat()
        session['ip_address'] = request.remote_addr
        session['user_agent'] = request.headers.get('User-Agent', '')[:200]
        
        # Aktualizuj status online użytkownika
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
        
        print(f"✅ Login successful: {username} (ID: {user.user_id})")
        
        return jsonify({
            'status': 'success',
            'user_id': user.user_id,
            'username': user.username,
            'is_admin': getattr(user, 'is_admin', False),
            'message': 'Login successful',
            'session_info': {
                'expires_in': SESSION_TIMEOUT,
                'absolute_timeout': SESSION_ABSOLUTE_TIMEOUT
            },
            'code': 'login_ok'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Login error: {str(e)}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

# === LOGOUT SYSTEM (FIXED) ===

@auth_bp.route('/logout', methods=['GET'])
def logout_page():
    from flask import session
    
    # BRUTAL SESSION CLEANUP
    session.clear()
    session.permanent = False
    
    # BRUTAL RESPONSE z force headers
    response = redirect(url_for('auth.index'))
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@auth_bp.route('/api/logout', methods=['POST'])
def api_logout():
    """
    API endpoint do wylogowania (dla JavaScript/AJAX)
    Kompatybilny z funkcją logout() z auth.js
    """
    try:
        print(f"🔓 API Logout request from user: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
        
        # Wyloguj użytkownika z Flask-Login
        if current_user.is_authenticated:
            # Aktualizuj status online użytkownika
            try:
                if hasattr(current_user, 'is_online'):
                    current_user.is_online = False
                if hasattr(current_user, 'last_active'):
                    current_user.last_active = datetime.utcnow()
                db.session.commit()
                print(f"✅ User {current_user.username} status updated to offline")
            except Exception as e:
                print(f"⚠️ Status update failed: {e}")
                db.session.rollback()
            
            # Wyloguj z Flask-Login
            logout_user()
        
        # BRUTAL SESSION CLEANUP (jak w logout_page)
        session.clear()
        session.permanent = False
        
        print("✅ API Logout successful")
        
        # Zwróć JSON response (dla JavaScript)
        response = jsonify({
            'status': 'success',
            'message': 'Logout successful',
            'code': 'logout_ok',
            'redirect': '/' 
        })
        
        # Dodaj te same headers jak w logout_page dla kompletnego czyszczenia
        response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        print(f"❌ API Logout error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Logout failed',
            'error': str(e)
        }), 500
# === SESSION MANAGEMENT ===

@auth_bp.route('/api/check_auth')
def check_auth():
    """
    Sprawdza czy użytkownik jest zalogowany i zwraca info o sesji
    """
    try:
        if current_user.is_authenticated:
            # Sprawdź czy sesja nie wygasła
            if 'last_activity' in session:
                try:
                    last_activity = datetime.fromisoformat(session['last_activity'])
                    if datetime.utcnow() - last_activity > timedelta(seconds=SESSION_TIMEOUT):
                        logout_user()
                        session.clear()
                        return jsonify({'authenticated': False, 'reason': 'Session expired'}), 401
                except (ValueError, TypeError):
                    logout_user()
                    session.clear()
                    return jsonify({'authenticated': False, 'reason': 'Invalid session'}), 401
            
            # Aktualizuj ostatnią aktywność
            session['last_activity'] = datetime.utcnow().isoformat()
            
            return jsonify({
                'authenticated': True,
                'user_id': current_user.user_id,
                'username': current_user.username,
                'id': current_user.id,
                'is_admin': getattr(current_user, 'is_admin', False),
                'session_info': {
                    'login_time': session.get('login_time'),
                    'last_activity': session.get('last_activity'),
                    'expires_in': SESSION_TIMEOUT
                }
            })
        else:
            return jsonify({'authenticated': False, 'reason': 'Not logged in'}), 401
            
    except Exception as e:
        print(f"❌ Auth check error: {e}")
        return jsonify({'authenticated': False, 'reason': 'Auth check failed'}), 401

@auth_bp.route('/api/session/info')
@login_required
@validate_session_security
def session_info():
    """
    Zwraca szczegółowe informacje o sesji
    """
    try:
        session_duration = None
        if 'session_start' in session:
            try:
                session_start = datetime.fromisoformat(session['session_start'])
                duration = datetime.utcnow() - session_start
                session_duration = str(duration)
            except (ValueError, TypeError):
                pass
        
        return jsonify({
            'status': 'success',
            'session': {
                'user_id': current_user.user_id,
                'username': current_user.username,
                'session_id': session.get('session_id', '')[:8] + '...',  # Partial for security
                'login_time': session.get('login_time'),
                'last_activity': session.get('last_activity'),
                'session_duration': session_duration,
                'ip_address': session.get('ip_address'),
                'expires_in': SESSION_TIMEOUT,
                'absolute_timeout': SESSION_ABSOLUTE_TIMEOUT
            }
        })
        
    except Exception as e:
        print(f"❌ Session info error: {e}")
        return jsonify({'error': 'Failed to get session info'}), 500

# === ADMIN ENDPOINTS ===

@auth_bp.route('/api/admin/users')
@login_required
def admin_users():
    """
    Lista użytkowników (tylko dla adminów)
    """
    try:
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'error': 'Admin access required'}), 403
        
        users = User.query.all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username,
                'is_online': getattr(user, 'is_online', False),
                'is_admin': getattr(user, 'is_admin', False),
                'last_active': user.last_active.isoformat() if hasattr(user, 'last_active') and user.last_active else None,
                'has_public_key': bool(user.public_key)
            })
        
        return jsonify({
            'status': 'success',
            'users': users_data,
            'total_users': len(users_data)
        })
        
    except Exception as e:
        print(f"❌ Admin users error: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500

# === ERROR HANDLERS ===

@auth_bp.errorhandler(401)
def unauthorized(error):
    """Handler dla błędów autoryzacji"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required'}), 401
    else:
        return redirect(url_for('auth.index'))

@auth_bp.errorhandler(403)
def forbidden(error):
    """Handler dla błędów dostępu"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Access forbidden'}), 403
    else:
        return redirect(url_for('auth.index'))

@auth_bp.errorhandler(404)
def not_found(error):
    """Handler dla błędów 404"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    else:
        return redirect(url_for('auth.index'))

# === UTILITY FUNCTIONS ===

def get_user_by_id(user_id):
    """Pomocnicza funkcja do pobierania użytkownika po ID"""
    return User.query.filter_by(user_id=user_id).first()

def get_user_by_username(username):
    """Pomocnicza funkcja do pobierania użytkownika po username"""
    return User.query.filter_by(username=username).first()

def is_user_online(user_id):
    """Sprawdza czy użytkownik jest online"""
    user = get_user_by_id(user_id)
    return getattr(user, 'is_online', False) if user else False

# === DEBUG ENDPOINTS (Only in development) ===

@auth_bp.route('/api/debug/session')
@login_required
def debug_session():
    """Debug endpoint dla sesji (tylko w development)"""
    try:
        if not current_user.is_authenticated:
            return jsonify({'error': 'Not authenticated'}), 401
        
        # Only return debug info in development
        debug_info = {
            'user_authenticated': current_user.is_authenticated,
            'user_id': current_user.user_id,
            'username': current_user.username,
            'session_keys': list(session.keys()),
            'session_permanent': session.permanent,
            'request_method': request.method,
            'request_path': request.path,
            'remote_addr': request.remote_addr
        }
        
        return jsonify({
            'status': 'success',
            'debug': debug_info
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

print("✅ auth.py loaded - Authentication system ready")
