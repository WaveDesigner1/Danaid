from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import or_
from models import db, User, ChatSession
import secrets
import base64
import time
# Import dla RSA verification (backward compatibility)
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    RSA_AVAILABLE = True
except ImportError:
    RSA_AVAILABLE = False

auth_bp = Blueprint('auth', __name__)

# === VIEWS (STARE) ===
@auth_bp.route('/')
def index():
    """Strona główna z przekierowaniem"""
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        elif current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('chat.chat'))
    return render_template('index.html')

@auth_bp.route('/register')
def register_page():
    """Strona rejestracji"""
    return render_template('register.html')

# === API ENDPOINTS (NOWE + STARE) ===

@auth_bp.route('/api/register', methods=['POST'])
def register():
    """Rejestracja użytkownika - ZMODERNIZOWANE"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        public_key = data.get('public_key')
        
        # Walidacja danych
        if not all([username, password, public_key]):
            return jsonify({'error': 'Missing required fields', 'code': 'missing_data'}), 400
        
        # Walidacja hasła
        if len(password) < 8:
            return jsonify({'error': 'Password too short', 'code': 'password_too_short'}), 400
        
        # Sprawdź czy użytkownik istnieje
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists', 'code': 'user_exists'}), 409
        
        # Walidacja klucza publicznego (jeśli RSA dostępne)
        if RSA_AVAILABLE:
            try:
                RSA.import_key(public_key)
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid key format', 'code': 'invalid_key_format'}), 400
        
        # Generuj unikalny 6-cyfrowy user ID
        while True:
            user_id = str(secrets.randbelow(900000) + 100000)
            if not User.query.filter_by(user_id=user_id).first():
                break
        
        # Utwórz użytkownika
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            public_key=public_key,
            user_id=user_id
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'user_id': user_id,
            'code': 'registration_ok'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Server error', 'code': 'server_error', 'message': str(e)}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login():
    """Logowanie użytkownika - ZMODERNIZOWANE (obsługuje starą i nową wersję)"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        signature_base64 = data.get('signature')  # Opcjonalne dla backward compatibility
        
        if not all([username, password]):
            return jsonify({'error': 'Missing credentials', 'code': 'missing_data'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid credentials', 'code': 'invalid_credentials'}), 401
        
        # RSA signature verification (STARY SYSTEM - opcjonalne)
        if signature_base64 and RSA_AVAILABLE:
            try:
                signature = base64.b64decode(signature_base64)
                public_key = RSA.import_key(user.public_key)
                raw_password = password.encode('utf-8')
                h = SHA256.new(raw_password)
                verifier = pkcs1_15.new(public_key)
                verifier.verify(h, signature)
                print("✅ RSA signature verified")
            except Exception as e:
                print(f"⚠️ RSA verification failed: {e}")
                # W nowym systemie nie blokujemy logowania przy błędzie RSA
                pass
        
        # Zaloguj użytkownika
        login_user(user, remember=True)
        session.permanent = True
        
        # Aktualizuj status online
        user.is_online = True
        user.last_active = datetime.utcnow()
        db.session.commit()
        
        # Zapisz czas dla session heartbeat
        session[f'last_online_update_{user.id}'] = int(time.time())
        session.modified = True
        
        # Sprawdź next URL
        next_page = request.args.get('next')
        
        return jsonify({
            'status': 'success',
            'user_id': user.user_id,
            'is_admin': user.is_admin,
            'code': 'login_ok',
            'next_url': next_page
        })
        
    except Exception as e:
        return jsonify({'error': 'Server error', 'code': 'server_error', 'message': str(e)}), 500

@auth_bp.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Wylogowanie użytkownika - NOWE z bezpiecznym czyszczeniem kluczy"""
    try:
        print(f"🔓 Logging out user: {current_user.username}")
        
        # Znajdź wszystkie sesje użytkownika
        user_sessions = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            ),
            or_(
                ChatSession.encrypted_keys_json.isnot(None),
                ChatSession.encrypted_session_key.isnot(None)  # Backward compatibility
            )
        ).all()
        
        cleared_count = 0
        
        # Wyczyść klucze szyfrowania dla bezpieczeństwa
        for session in user_sessions:
            if session.encrypted_keys_json or session.encrypted_session_key:
                session.clear_keys()
                cleared_count += 1
        
        # Aktualizuj status użytkownika
        current_user.is_online = False
        
        # Zatwierdź zmiany
        db.session.commit()
        
        print(f"🧹 SECURITY: Cleared encryption keys for {cleared_count} sessions")
        
        # Wyloguj użytkownika
        logout_user()
        session.clear()
        
        return jsonify({
            'status': 'success',
            'message': 'Logged out successfully',
            'encryption_keys_cleared': cleared_count
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Logout error: {str(e)}")
        
        # Mimo błędu, wyloguj użytkownika
        logout_user()
        session.clear()
        
        return jsonify({
            'status': 'warning',
            'message': 'Logged out but key clearing may have failed',
            'error': str(e)
        }), 200

@auth_bp.route("/logout")
def logout_redirect():
    """Stary endpoint wylogowania z przekierowaniem"""
    try:
        if current_user.is_authenticated:
            current_user.is_online = False
            db.session.commit()
    except Exception:
        db.session.rollback()
    
    logout_user()
    session.clear()
    
    response = redirect('/')
    
    # Wyczyść ciasteczka
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    response.delete_cookie('session_id')
    
    response.set_cookie('session', '', expires=0)
    response.set_cookie('remember_token', '', expires=0)
    
    # Cache headers
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    return response

@auth_bp.route('/api/check_auth')
@login_required
def check_auth():
    """Sprawdza status autoryzacji - NOWE"""
    return jsonify({
        'authenticated': True,
        'user_id': current_user.user_id,
        'username': current_user.username,
        'is_admin': current_user.is_admin,
        'is_online': current_user.is_online,
        'last_active': current_user.last_active.isoformat() if current_user.last_active else None
    })


