from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from models import User, db
import datetime
import time

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    # Sprawdź, czy użytkownik jest zalogowany i przekieruj odpowiednio
    if current_user.is_authenticated:
        # Sprawdź, czy jest parametr next w URL
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
    return render_template('register.html')

@auth_bp.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        public_key = data.get('public_key')

        if not username or not password or not public_key:
            return jsonify({'status': 'error', 'code': 'missing_data'}), 400

        # Podstawowa walidacja hasła
        if len(password) < 8:
            return jsonify({'status': 'error', 'code': 'password_too_short'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'status': 'error', 'code': 'user_exists'}), 400

        try:
            RSA.import_key(public_key)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'code': 'invalid_key_format'}), 400

        try:
            new_user = User(username=username, public_key=public_key)
            new_user.set_password(password)
            new_user.generate_user_id()
            
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({'status': 'success', 'code': 'registration_ok', 'user_id': new_user.user_id}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'code': 'db_error', 'message': str(e)}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'code': 'server_error', 'message': str(e)}), 500

@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        signature_base64 = data.get('signature')
        
        if not username or not password:
            return jsonify({'status': 'error', 'code': 'missing_data'}), 400
            
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'status': 'error', 'code': 'invalid_credentials'}), 401
            
        if not user.check_password(password):
            return jsonify({'status': 'error', 'code': 'invalid_password'}), 401
        
        # Weryfikacja podpisu
        if not signature_base64:
            return jsonify({'status': 'error', 'code': 'missing_signature'}), 400
                
        try:
            # Dekodowanie podpisu z base64
            signature = base64.b64decode(signature_base64)
            
            # Import klucza publicznego
            public_key = RSA.import_key(user.public_key)
            
            # Tworzymy hash z surowego hasła
            raw_password = password.encode('utf-8')
            h = SHA256.new(raw_password)
            
            # Weryfikujemy podpis
            verifier = pkcs1_15.new(public_key)
            verifier.verify(h, signature)
            
        except Exception as e:
            return jsonify({'status': 'error', 'code': 'verification_error', 'message': str(e)}), 500
        
        # Aktualizacja statusu online
        try:
            if hasattr(user, 'is_online'):
                user.is_online = True
                db.session.commit()
        except Exception:
            db.session.rollback()
        
        # Zaloguj użytkownika
        login_result = login_user(user, remember=True)
        session.permanent = True
        
        # Zapisz czas ostatniej aktualizacji statusu online
        session[f'last_online_update_{user.id}'] = int(time.time())
        session.modified = True  # Upewnij się, że sesja zostanie zapisana
        
        # Sprawdź, czy jest parametr next w URL
        next_page = request.args.get('next')
        
        return jsonify({
            'status': 'success', 
            'code': 'login_ok', 
            'user_id': user.user_id,
            'is_admin': user.is_admin,
            'next_url': next_page,
            'login_success': login_result  # Dodaj informację, czy logowanie się powiodło
        }), 200
            
    except Exception as e:
        return jsonify({'status': 'error', 'code': 'server_error', 'message': str(e)}), 500

@auth_bp.route("/logout")
def logout():
    """Wylogowanie użytkownika"""
    try:
        # Aktualizacja statusu online
        if current_user.is_authenticated and hasattr(current_user, 'is_online'):
            current_user.is_online = False
            db.session.commit()
    except Exception:
        db.session.rollback()
    
    # Wyloguj użytkownika i wyczyść sesję
    logout_user()
    session.clear()
    
    # Przygotuj odpowiedź z wyczyszczonymi ciasteczkami
    response = redirect('/')
    
    # Wyczyść wszystkie ciasteczka związane z sesją
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    response.delete_cookie('session_id')
    
    # Ustaw ciasteczka z ujemnym czasem ważności
    response.set_cookie('session', '', expires=0)
    response.set_cookie('remember_token', '', expires=0)
    
    # Ustaw nagłówki cache
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    return response
