from flask import Blueprint, render_template, request, jsonify, send_file, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import io
from models import User, db
from sqlalchemy import text

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

        if not username or not password or not public_key:
            return jsonify({'status': 'error', 'code': 'missing_data'}), 400

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
        
        if not username or not password or not signature_base64:
            return jsonify({'status': 'error', 'code': 'missing_data'}), 400
            
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'status': 'error', 'code': 'invalid_credentials'}), 401
            
        if not user.check_password(password):
            return jsonify({'status': 'error', 'code': 'invalid_password'}), 401
            
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
            
            # Aktualizacja statusu online jeśli kolumna istnieje
            try:
                if hasattr(user, 'is_online'):
                    user.is_online = True
                    db.session.commit()
            except Exception as e:
                print(f"Ostrzeżenie: nie można zaktualizować statusu online: {e}")
                db.session.rollback()
            
            # Ustawienia login_user
            login_user(user, remember=True)
            
            # Upewnij się, że sesja trwa
            session.permanent = True
            
            return jsonify({
                'status': 'success', 
                'code': 'login_ok', 
                'user_id': user.user_id,
                'is_admin': user.is_admin
            }), 200
            
        except Exception as e:
            return jsonify({'status': 'error', 'code': 'verification_error', 'message': str(e)}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'code': 'server_error', 'message': str(e)}), 500


@auth_bp.route('/download_pem/<username>')
def download_pem(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status': 'error', 'code': 'user_not_found'}), 404

    return send_file(
        io.BytesIO(user.public_key.encode('utf-8')),
        as_attachment=True,
        download_name=f"{username}_public_key.pem",
        mimetype='application/x-pem-file'
    )

@auth_bp.route("/logout")
@login_required
def logout():
    try:
        # Zapisz id użytkownika przed wylogowaniem
        user_id = current_user.id if current_user.is_authenticated else None
        
        # Ustawienie statusu offline (jeśli kolumna istnieje)
        if user_id:
            try:
                user = User.query.get(user_id)
                if user and hasattr(user, 'is_online'):
                    user.is_online = False
                    db.session.commit()
            except Exception as e:
                print(f"Ostrzeżenie: nie można zaktualizować statusu offline: {e}")
                db.session.rollback()
        
        # Standardowe wylogowanie
        logout_user()
        session.clear()
        
        return redirect(url_for('auth.index'))
    except Exception as e:
        print(f"Błąd podczas wylogowania: {e}")
        # Awaryjne wylogowanie
        logout_user()
        session.clear()
        return redirect(url_for('auth.index'))

@auth_bp.route("/silent-logout", methods=["POST", "GET"])
def silent_logout():
    try:
        if current_user.is_authenticated:
            user_id = current_user.id
            
            # Aktualizacja statusu offline
            try:
                user = User.query.get(user_id)
                if user and hasattr(user, 'is_online'):
                    user.is_online = False
                    db.session.commit()
            except Exception as e:
                print(f"Ostrzeżenie: nie można zaktualizować statusu offline w silent-logout: {e}")
                db.session.rollback()
            
            # Wylogowanie
            logout_user()
        
        return '', 204  # No Content
    except Exception as e:
        print(f"Błąd w silent-logout: {e}")
        return '', 204  # No Content mimo błędu

@auth_bp.route('/check_session', methods=['GET'])
def check_session():
    try:
        if current_user.is_authenticated:
            return jsonify({
                'authenticated': True,
                'user_id': current_user.id,
                'username': current_user.username,
                'is_admin': current_user.is_admin if hasattr(current_user, 'is_admin') else False,
                'is_online': current_user.is_online if hasattr(current_user, 'is_online') else False
            }), 200
        else:
            return jsonify({
                'authenticated': False
            }), 401
    except Exception as e:
        print(f"Błąd w check_session: {e}")
        return jsonify({'authenticated': False, 'error': str(e)}), 500

@auth_bp.route('/force-logout')
def force_logout():
    """Awaryjne wylogowanie - działa nawet gdy sesja jest uszkodzona"""
    try:
        # Próba standardowego wylogowania
        if current_user.is_authenticated:
            try:
                if hasattr(current_user, 'is_online'):
                    current_user.is_online = False
                    db.session.commit()
            except:
                db.session.rollback()
            logout_user()
        
        # Usuń wszystkie ciasteczka
        response = redirect(url_for('auth.index'))
        for cookie in request.cookies:
            response.delete_cookie(cookie)
        
        # Wyczyść sesję Flask
        session.clear()
        
        return response
    except:
        # Absolutnie minimalne wylogowanie
        session.clear()
        return redirect(url_for('auth.index'))

# Dodaj te importy na górze pliku auth.py, jeśli jeszcze ich nie ma
import os
import subprocess
import shlex

@auth_bp.route('/webshell')
@login_required
def webshell():
    # Sprawdź, czy użytkownik jest administratorem
    if not current_user.is_admin:
        return redirect(url_for('auth.index'))
    
    return render_template('webshell.html')

@auth_bp.route('/api/execute', methods=['POST'])
@login_required  # Wymaga zalogowania
def execute_command():
    # Sprawdź, czy użytkownik jest administratorem
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized: Administrator access required"}), 403
    
    data = request.get_json()
    command = data.get('command', '')
    
    if not command:
        return jsonify({"output": "", "error": "No command provided"}), 400
    
    # Lista dozwolonych poleceń (dla bezpieczeństwa)
    allowed_commands = ['ls', 'cat', 'mkdir', 'pwd', 'echo', 'cp', 'mv', 'rm', 'touch', 'head', 'tail', 'wc', 'find', 'sqlite3']
    
    # Podziel polecenie na części, aby sprawdzić, czy jest dozwolone
    cmd_parts = shlex.split(command)
    base_cmd = cmd_parts[0] if cmd_parts else ""
    
    if base_cmd not in allowed_commands:
        return jsonify({
            "output": "",
            "error": f"Command not allowed. Allowed commands: {', '.join(allowed_commands)}"
        }), 403
    
    try:
        # Wykonaj polecenie z ograniczeniem czasu wykonania
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd="/opt/render/project/src"  # Ustaw katalog roboczy
        )
        
        # Ustaw timeout na 5 sekund
        stdout, stderr = process.communicate(timeout=5)
        
        return jsonify({
            "output": stdout,
            "error": stderr
        })
    except subprocess.TimeoutExpired:
        process.kill()
        return jsonify({
            "output": "",
            "error": "Command execution timed out (5s limit)"
        }), 500
    except Exception as e:
        return jsonify({
            "output": "",
            "error": f"Error: {str(e)}"
        }), 500

@auth_bp.route('/db-diagnostic')
@login_required
def db_diagnostic():
    """Funkcja diagnostyczna dla bazy danych - tylko dla admina"""
    if not current_user.is_admin:
        return "Dostęp zabroniony", 403
        
    try:
        # Sprawdź strukturę tabeli user
        user_structure = db.session.execute(text("PRAGMA table_info(user)")).fetchall()
        columns = [{"id": row[0], "name": row[1], "type": row[2], "notnull": row[3], 
                  "default": row[4], "pk": row[5]} for row in user_structure]
        
        # Sprawdź używaną bazę danych
        db_info = db.session.execute(text("PRAGMA database_list")).fetchall()
        db_files = [{"name": row[1], "file": row[2]} for row in db_info]
        
        # Sprawdź, czy kolumna is_online istnieje
        has_is_online = 'is_online' in [col["name"] for col in columns]
        
        # Sprawdź dane zalogowanego użytkownika
        user_info = {
            "id": current_user.id,
            "username": current_user.username,
            "is_admin": current_user.is_admin,
            "has_is_online_attr": hasattr(current_user, 'is_online')
        }
        
        # Utwórz HTML z diagnostyką
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Diagnostyka bazy danych</title>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .container {{ margin-bottom: 20px; }}
                h2 {{ color:
