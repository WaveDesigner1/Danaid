from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_login import LoginManager
from datetime import timedelta
import os
import json

# Bezpośrednie importy
from models import db, User
from admin import init_admin
from auth import auth_bp
from chat import chat_bp

# Próba importu chat_api, zabezpieczona przed błędem
try:
    from chat_api import chat_api
    chat_api_imported = True
except ImportError:
    chat_api_imported = False

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
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
    
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
    
    # Rejestracja chat_api blueprintu jeśli został pomyślnie zaimportowany
    if chat_api_imported:
        app.register_blueprint(chat_api)
        print("Blueprint chat_api został zarejestrowany.")
    else:
        print("Blueprint chat_api nie został zaimportowany. Pomijam rejestrację.")

    # Inicjalizacja panelu admina
    init_admin(app)
    
    # Dodanie endpointów diagnostycznych
    @app.route('/diagnostics', methods=['GET'])
    def diagnostics():
        """Endpoint diagnostyczny do sprawdzenia stanu bazy danych"""
        try:
            result = {
                'status': 'checking',
                'app_config': {},
                'tables': [],
                'admin_exists': False,
                'user_count': 0,
                'errors': []
            }
            
            # Sprawdź konfigurację aplikacji
            for key in ['SQLALCHEMY_DATABASE_URI', 'SECRET_KEY', 'SESSION_PROTECTION']:
                if key in app.config:
                    result['app_config'][key] = 'MASKED' if 'SECRET' in key else app.config[key]
            
            # Sprawdź tabele w bazie danych
            tables = []
            try:
                tables_query = db.session.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
                tables = [table[0] for table in tables_query]
                result['tables'] = tables
            except Exception as e:
                result['errors'].append(f"Błąd podczas sprawdzania tabel: {str(e)}")
            
            # Sprawdź, czy tabela user istnieje
            if 'user' in tables:
                # Sprawdź, czy istnieje administrator
                try:
                    admin = User.query.filter_by(username='admin').first()
                    result['admin_exists'] = admin is not None
                    if admin:
                        result['admin_username'] = admin.username
                        result['admin_is_admin'] = admin.is_admin
                        result['admin_has_public_key'] = admin.public_key is not None
                    
                    # Sprawdź liczbę użytkowników
                    result['user_count'] = User.query.count()
                    
                    # Sprawdź strukturę tabeli user
                    user_columns = db.session.execute("PRAGMA table_info(user);").fetchall()
                    result['user_columns'] = [col[1] for col in user_columns]
                except Exception as e:
                    result['errors'].append(f"Błąd podczas sprawdzania użytkowników: {str(e)}")
            
            # Sprawdź, czy tabele czatu istnieją
            for table in ['chat_session', 'message']:
                if table in tables:
                    try:
                        count = db.session.execute(f"SELECT COUNT(*) FROM {table};").scalar()
                        result[f'{table}_count'] = count
                    except Exception as e:
                        result['errors'].append(f"Błąd podczas sprawdzania tabeli {table}: {str(e)}")
            
            # Sprawdź czy plik blokujący istnieje
            init_lock_file = 'db_initialized.lock'
            result['lock_file_exists'] = os.path.exists(init_lock_file)
            if result['lock_file_exists']:
                try:
                    with open(init_lock_file, 'r') as f:
                        result['lock_file_content'] = f.read()
                except:
                    result['lock_file_content'] = 'Cannot read file'
            
            result['status'] = 'ok' if not result['errors'] else 'errors'
            return jsonify(result)
        except Exception as e:
            return jsonify({
                'status': 'critical_error',
                'message': str(e)
            }), 500

    @app.route('/emergency_admin/<secret_token>', methods=['GET'])
    def emergency_admin(secret_token):
        """Awaryjne tworzenie konta administratora"""
        # Używaj bardzo silnego tokenu w produkcji!
        if secret_token != os.environ.get('EMERGENCY_TOKEN', 'super_secret_emergency_token'):
            return "Unauthorized", 403
        
        try:
            from werkzeug.security import generate_password_hash
            import secrets
            
            # Wygeneruj losowe hasło
            password = "Admin123!"  # W produkcji użyj losowego hasła
            
            # Sprawdź, czy użytkownik admin już istnieje
            admin = User.query.filter_by(username='admin').first()
            
            if admin:
                # Resetuj hasło i upewnij się, że ma uprawnienia admina
                admin.password_hash = generate_password_hash(password)
                admin.is_admin = True
                db.session.commit()
                return jsonify({
                    'status': 'success',
                    'message': 'Reset hasła administratora',
                    'username': 'admin',
                    'password': password
                })
            else:
                # Utwórz nowego administratora
                user_id = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
                new_admin = User(
                    username='admin',
                    password_hash=generate_password_hash(password),
                    public_key="EMERGENCY_ADMIN_KEY",
                    is_admin=True,
                    user_id=user_id
                )
                db.session.add(new_admin)
                db.session.commit()
                return jsonify({
                    'status': 'success',
                    'message': 'Utworzono nowe konto administratora',
                    'username': 'admin',
                    'password': password,
                    'user_id': user_id
                })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/fix_database/<secret_token>', methods=['GET'])
    def fix_database(secret_token):
        """Naprawianie bazy danych"""
        if secret_token != os.environ.get('EMERGENCY_TOKEN', 'super_secret_emergency_token'):
            return "Unauthorized", 403
        
        try:
            result = {
                'status': 'fixing',
                'operations': [],
                'errors': []
            }
            
            # 1. Upewnij się, że tabele podstawowe istnieją
            try:
                db.create_all()
                result['operations'].append('Utworzono brakujące tabele podstawowe')
            except Exception as e:
                result['errors'].append(f"Błąd podczas tworzenia tabel podstawowych: {str(e)}")
            
            # 2. Sprawdź, czy tabela chat_session istnieje, jeśli nie, utwórz ją
            try:
                db.session.execute("SELECT 1 FROM chat_session LIMIT 1")
                result['operations'].append('Tabela chat_session już istnieje')
            except:
                try:
                    db.session.execute("""
                    CREATE TABLE IF NOT EXISTS chat_session (
                        id INTEGER PRIMARY KEY,
                        initiator_id INTEGER NOT NULL,
                        recipient_id INTEGER NOT NULL,
                        session_token VARCHAR(100) NOT NULL UNIQUE,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        expires_at DATETIME NOT NULL,
                        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (initiator_id) REFERENCES user (id),
                        FOREIGN KEY (recipient_id) REFERENCES user (id)
                    );
                    """)
                    db.session.commit()
                    result['operations'].append('Utworzono tabelę chat_session')
                except Exception as e:
                    result['errors'].append(f"Błąd podczas tworzenia tabeli chat_session: {str(e)}")
            
            # 3. Sprawdź, czy tabela message istnieje, jeśli nie, utwórz ją
            try:
                db.session.execute("SELECT 1 FROM message LIMIT 1")
                result['operations'].append('Tabela message już istnieje')
            except:
                try:
                    db.session.execute("""
                    CREATE TABLE IF NOT EXISTS message (
                        id INTEGER PRIMARY KEY,
                        session_id INTEGER NOT NULL,
                        sender_id INTEGER NOT NULL,
                        encrypted_data TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_delivered BOOLEAN DEFAULT 0,
                        FOREIGN KEY (session_id) REFERENCES chat_session (id),
                        FOREIGN KEY (sender_id) REFERENCES user (id)
                    );
                    """)
                    db.session.commit()
                    result['operations'].append('Utworzono tabelę message')
                except Exception as e:
                    result['errors'].append(f"Błąd podczas tworzenia tabeli message: {str(e)}")
            
            # 4. Sprawdź, czy tabela user ma wszystkie potrzebne kolumny
            try:
                columns = db.session.execute("PRAGMA table_info(user);").fetchall()
                column_names = [col[1] for col in columns]
                
                for expected_column in ['is_online']:
                    if expected_column not in column_names:
                        db.session.execute(f"ALTER TABLE user ADD COLUMN {expected_column} BOOLEAN DEFAULT 0;")
                        result['operations'].append(f'Dodano brakującą kolumnę {expected_column} do tabeli user')
                
                db.session.commit()
            except Exception as e:
                result['errors'].append(f"Błąd podczas sprawdzania/aktualizacji kolumn tabeli user: {str(e)}")
            
            # 5. Tworzenie indeksów
            try:
                db.session.execute("CREATE INDEX IF NOT EXISTS idx_session_token ON chat_session(session_token);")
                db.session.execute("CREATE INDEX IF NOT EXISTS idx_session_users ON chat_session(initiator_id, recipient_id);")
                db.session.execute("CREATE INDEX IF NOT EXISTS idx_message_session ON message(session_id);")
                db.session.execute("CREATE INDEX IF NOT EXISTS idx_message_sender ON message(sender_id);")
                db.session.commit()
                result['operations'].append('Utworzono indeksy dla tabel czatu')
            except Exception as e:
                result['errors'].append(f"Błąd podczas tworzenia indeksów: {str(e)}")
            
            result['status'] = 'success' if not result['errors'] else 'partial_success'
            return jsonify(result)
        except Exception as e:
            return jsonify({
                'status': 'critical_error',
                'message': str(e)
            }), 500

    return app
