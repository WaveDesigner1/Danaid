"""
auth.py - Kompletny plik autoryzacji
Oryginalny sposób logowania + niezbędne endpointy dla kompatybilności
"""
import json
import secrets
import base64
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import or_
from models import db, User, ChatSession
import time

# RSA imports (backward compatibility)
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    RSA_AVAILABLE = True
except ImportError:
    RSA_AVAILABLE = False
    print("⚠️ PyCryptodome not available - RSA verification disabled")

auth_bp = Blueprint('auth', __name__)

# === VIEWS (STRONY HTML) ===

@auth_bp.route('/')
def index():
    """Strona główna z przekierowaniem"""
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('chat.chat'))
    return render_template('index.html')

@auth_bp.route('/register')
def register_page():
    """Strona rejestracji"""
    return render_template('register.html')

@auth_bp.route('/login')
def login_page():
    """Strona logowania"""
    return render_template('login.html')

# === API ENDPOINTS ===

@auth_bp.route('/api/register', methods=['POST'])
def register():
    """Rejestracja użytkownika"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        public_key = data.get('public_key')
        
        if not all([username, password, public_key]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Walidacja hasła
        if len(password) < 8:
            return jsonify({'error': 'Password too short (minimum 8 characters)'}), 400
        
        # Sprawdź czy użytkownik istnieje
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        # Walidacja klucza publicznego
        if RSA_AVAILABLE:
            try:
                RSA.import_key(public_key)
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid public key format'}), 400
        
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
            'user_id': user_id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login():
    """Logowanie użytkownika"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        signature_base64 = data.get('signature')
        
        if not all([username, password]):
            return jsonify({'error': 'Missing credentials'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # RSA signature verification (ORYGINALNY SPOSÓB)
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
                print(f"❌ RSA verification failed: {e}")
                return jsonify({'error': 'RSA signature verification failed'}), 401
        elif signature_base64:
            print("⚠️ RSA verification requested but PyCryptodome not available")
            return jsonify({'error': 'RSA verification not available'}), 500
        
        # Logowanie użytkownika
        login_user(user, remember=True)
        
        # Aktualizuj nowe kolumny (jeśli istnieją) - MINIMALNA POPRAWKA
        try:
            if hasattr(user, 'is_online'):
                user.is_online = True
            if hasattr(user, 'last_active'):
                user.last_active = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            print(f"⚠️ Status update failed: {e}")
            db.session.rollback()
        
        # Zapisz czas dla session heartbeat
        session[f'last_online_update_{user.id}'] = int(time.time())
        session.permanent = True
        
        return jsonify({
            'status': 'success',
            'user_id': user.user_id,
            'is_admin': user.is_admin
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Wylogowanie użytkownika"""
    try:
        print(f"🔓 Logging out user: {current_user.username}")
        
        # Aktualizuj status offline (jeśli kolumna istnieje) - MINIMALNA POPRAWKA
        try:
            if hasattr(current_user, 'is_online'):
                current_user.is_online = False
            db.session.commit()
        except Exception as e:
            print(f"⚠️ Status update failed: {e}")
            db.session.rollback()
        
        # Wyloguj użytkownika
        logout_user()
        session.clear()
        
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
    """Przekierowanie wylogowania"""
    try:
        if current_user.is_authenticated and hasattr(current_user, 'is_online'):
            current_user.is_online = False
            db.session.commit()
    except Exception:
        db.session.rollback()
    
    logout_user()
    session.clear()
    
    response = redirect(url_for('auth.index'))
    
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

# 🚨 BRAKUJĄCY ENDPOINT - GŁÓWNA PRZYCZYNA BŁĘDU
@auth_bp.route('/api/check_auth')
@login_required
def check_auth():
    """Sprawdza status autoryzacji - ENDPOINT WYMAGANY PRZEZ auth.js"""
    return jsonify({
        'authenticated': True,
        'user_id': current_user.user_id,
        'username': current_user.username,
        'is_admin': current_user.is_admin,
        'id': current_user.id,  # Potrzebne dla chat.js
        'is_online': getattr(current_user, 'is_online', False),
        'last_active': current_user.last_active.isoformat() if hasattr(current_user, 'last_active') and current_user.last_active else None
    })

# === ENDPOINTY DLA ZARZĄDZANIA UŻYTKOWNIKAMI ===

@auth_bp.route('/api/user/<user_id>/public_key')
@login_required
def get_user_public_key(user_id):
    """Pobiera klucz publiczny użytkownika"""
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'status': 'success',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key
    })

@auth_bp.route('/api/users')
@login_required  
def get_users():
    """Lista wszystkich użytkowników (poza sobą)"""
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
                
            user_list.append(user_data)
        
        return jsonify({'status': 'success', 'users': user_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/user/<user_id>/info')
@login_required
def get_user_info(user_id):
    """Informacje o użytkowniku"""
    try:
        user = User.query.filter_by(user_id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
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
            
        return jsonify({
            'status': 'success',
            'user': user_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/online_users')
@login_required
def get_online_users():
    """Lista użytkowników online"""
    try:
        if hasattr(User, 'is_online'):
            online_users = User.query.filter(
                User.is_online == True, 
                User.id != current_user.id
            ).all()
            
            return jsonify({
                'status': 'success',
                'online_users': [{
                    'id': u.id, 
                    'user_id': u.user_id, 
                    'username': u.username
                } for u in online_users]
            })
        else:
            # Fallback gdy kolumna nie istnieje
            return jsonify({'status': 'success', 'online_users': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
