from flask import Blueprint, render_template, request, jsonify, send_file, redirect, url_for, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import io
from models import User, db
from sqlalchemy import text, inspect
import os
import traceback
import time
import subprocess
import shlex

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
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

        print(f"Próba rejestracji użytkownika: {username}")

        if not username or not password or not public_key:
            return jsonify({'status': 'error', 'code': 'missing_data'}), 400

        # Podstawowa walidacja hasła
        if len(password) < 8:
            return jsonify({'status': 'error', 'code': 'password_too_short'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'status': 'error', 'code': 'user_exists'}), 400

        try:
            RSA.import_key(public_key)
        except (ValueError, TypeError) as e:
            print(f"Błąd formatu klucza: {e}")
            return jsonify({'status': 'error', 'code': 'invalid_key_format'}), 400

        try:
            new_user = User(username=username, public_key=public_key)
            new_user.set_password(password)
            new_user.generate_user_id()
            
            print(f"Utworzono obiekt użytkownika: {new_user.username}")
            db.session.add(new_user)
            print(f"Dodano użytkownika do sesji")
            db.session.commit()
            print(f"Zatwierdzono transakcję - użytkownik zarejestrowany")
            
            return jsonify({'status': 'success', 'code': 'registration_ok', 'user_id': new_user.user_id}), 200
        except Exception as e:
            print(f"Błąd bazy danych podczas rejestracji: {e}")
            db.session.rollback()
            traceback.print_exc()
            return jsonify({'status': 'error', 'code': 'db_error', 'message': str(e)}), 500
    except Exception as e:
        print(f"Ogólny błąd serwera podczas rejestracji: {e}")
        traceback.print_exc()
        return jsonify({'status': 'error', 'code': 'server_error', 'message': str(e)}), 500


@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    # Bez zmian, już nie używa SQLite
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
        
        # Specjalna obsługa dla admina z tymczasowym kluczem
        if user.is_admin and user.public_key == "TEMPORARY_ADMIN_KEY":
            # Dla tymczasowego admina pomijamy weryfikację podpisu
            if signature_base64:
                # Jeśli mamy podpis, zaktualizuj klucz publiczny
                try:
                    user.public_key = data.get('public_key', user.public_key)
                    db.session.commit()
                except Exception as e:
                    print(f"Błąd aktualizacji klucza publicznego: {e}")
                    db.session.rollback()
        else:
            # Standardowa weryfikacja podpisu dla normalnych użytkowników
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
        except Exception as e:
            print(f"Ostrzeżenie: nie można zaktualizować statusu online: {e}")
            db.session.rollback()
        
        # Zaloguj użytkownika
        login_user(user, remember=True)
        session.permanent = True
        
        # Zapisz czas ostatniej aktualizacji statusu online
        session[f'last_online_update_{user.id}'] = int(time.time())
        
        return jsonify({
            'status': 'success', 
            'code': 'login_ok', 
            'user_id': user.user_id,
            'is_admin': user.is_admin
        }), 200
            
    except Exception as e:
        return jsonify({'status': 'error', 'code': 'server_error', 'message': str(e)}), 500

# Pozostałe funkcje bez zmian, nie używają SQLite

# Usunięte lub zmodyfikowane funkcje związane z SQLite:

@auth_bp.route('/db-diagnostic')
@login_required
def db_diagnostic():
    """Funkcja diagnostyczna dla bazy danych - tylko dla admina"""
    if not current_user.is_admin:
        return "Dostęp zabroniony", 403
        
    try:
        # Kod tylko dla PostgreSQL
        inspector = inspect(db.engine)
        columns_data = inspector.get_columns('user')
        columns = [{"id": i, "name": col['name'], "type": str(col['type']), 
                     "notnull": not col.get('nullable', True), 
                     "default": col.get('default'), "pk": col.get('primary_key', False)} 
                   for i, col in enumerate(columns_data)]
        
        # Informacje o bazie danych
        db_name = db.engine.url.database
        db_files = [{"name": db_name, "file": "postgresql"}]
        
        # Sprawdź, czy kolumna is_online istnieje
        has_is_online = 'is_online' in [col["name"] for col in columns]
        
        # Sprawdź dane zalogowanego użytkownika
        user_info = {
            "id": current_user.id,
            "username": current_user.username,
            "is_admin": current_user.is_admin,
            "has_is_online_attr": hasattr(current_user, 'is_online')
        }
        
        # Stwórz prosty HTML z wynikami
        return render_template('db_diagnostic.html', 
                              columns=columns,
                              db_files=db_files,
                              user_info=user_info,
                              has_is_online=has_is_online)
    except Exception as e:
        return f"Błąd podczas diagnostyki: {str(e)}"

@auth_bp.route('/api/add_is_online_column', methods=['POST'])
@login_required
def add_is_online_column():
    """API do dodania kolumny is_online do tabeli user"""
    if not current_user.is_admin:
        return jsonify({"status": "error", "message": "Dostęp zabroniony"}), 403
    
    try:
        # Sprawdź, czy kolumna już istnieje
        inspector = inspect(db.engine)
        columns_data = inspector.get_columns('user')
        columns = [col['name'] for col in columns_data]
        
        if 'is_online' in columns:
            return jsonify({
                "status": "info", 
                "message": "Kolumna is_online już istnieje w tabeli user"
            })
        
        # Dodaj kolumnę
        db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_online BOOLEAN DEFAULT FALSE'))
        db.session.commit()
        
        # Ustaw wszystkich użytkowników jako offline
        try:
            db.session.execute(text('UPDATE "user" SET is_online = false'))
            db.session.commit()
            print("Wszyscy użytkownicy oznaczeni jako offline")
        except Exception as e:
            print(f"Ostrzeżenie: nie można zaktualizować statusów online: {e}")
            db.session.rollback()
        
        return jsonify({
            "status": "success", 
            "message": "Kolumna is_online została pomyślnie dodana do tabeli user"
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error", 
            "message": f"Błąd: {str(e)}"
        }), 500

@auth_bp.route('/api/check_is_online_column', methods=['GET'])
@login_required
def check_is_online_column():
    """Sprawdza, czy kolumna is_online istnieje w tabeli user"""
    if not current_user.is_admin:
        return jsonify({"status": "error", "message": "Dostęp zabroniony"}), 403
    
    try:
        # Sprawdź, czy kolumna już istnieje
        inspector = inspect(db.engine)
        columns_data = inspector.get_columns('user')
        columns = [col['name'] for col in columns_data]
        
        has_column = 'is_online' in columns
        
        return jsonify({
            "status": "success", 
            "has_is_online": has_column
        })
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": f"Błąd podczas sprawdzania struktury tabeli: {str(e)}"
        }), 500

@auth_bp.route("/logout")
def logout():
    """Ulepszone i uproszczone wylogowanie użytkownika"""
    print("\n=== ROZPOCZĘCIE PROCESU WYLOGOWANIA ===")
    print(f"Czas: {datetime.datetime.now()}")
    
    user_id = None
    
    try:
        # Zapisz ID użytkownika przed wylogowaniem
        if current_user.is_authenticated:
            user_id = current_user.id
            print(f"Wylogowywanie użytkownika: ID={user_id}")
            
            # Zaktualizuj status online użytkownika
            if hasattr(current_user, 'is_online'):
                current_user.is_online = False
                db.session.commit()
                print("Status offline ustawiony pomyślnie")
    except Exception as e:
        print(f"Błąd podczas aktualizacji statusu: {e}")
        db.session.rollback()
    
    # Wyloguj użytkownika i wyczyść sesję
    try:
        logout_user()
        session.clear()
        print(f"Użytkownik {user_id} wylogowany pomyślnie")
    except Exception as e:
        print(f"Błąd podczas wylogowywania: {e}")
    
    # Przygotuj odpowiedź z wyczyszczonymi ciasteczkami
    response = redirect(url_for('auth.index'))
    
    # Wyczyść wszystkie ciasteczka związane z sesją
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    response.delete_cookie('session_id')
    
    # Ustaw ciasteczka z ujemnym czasem ważności jako dodatkowe zabezpieczenie
    response.set_cookie('session', '', expires=0)
    response.set_cookie('remember_token', '', expires=0)
    
    # Ustaw nagłówki cache, aby zapobiec cachowaniu
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    print("=== WYLOGOWANIE ZAKOŃCZONE ===\n")
    return response
