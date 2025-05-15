from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_required
from datetime import timedelta
import os
import shutil
import datetime
import sqlite3
import time
from sqlalchemy import text
from sqlalchemy import inspect, text
import traceback
# Bezpośrednie importy
from models import db, User, ChatSession, Message
from admin import init_admin
from auth import auth_bp
from chat import chat_bp
from chat_api import chat_api

# Inicjalizacja login managera
login_manager = LoginManager()

# Funkcje pomocnicze do określania typu bazy danych
def is_sqlite():
    """Sprawdza, czy używamy bazy SQLite"""
    return db.engine.name == 'sqlite'

def is_postgresql():
    """Sprawdza, czy używamy bazy PostgreSQL"""
    return db.engine.name == 'postgresql'

# Ładowanie użytkownika
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Błąd ładowania użytkownika: {e}")
        return None

# Główna funkcja tworząca aplikację
def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)
    
    # Konfiguracja bezpieczeństwa
    app.config['SECRET_KEY'] = 'your_secret_key'
    
    # Konfiguracja sesji
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)
    app.config['REMEMBER_COOKIE_SECURE'] = False
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['SESSION_PROTECTION'] = 'basic'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_SECURE'] = False
    
    # Inicjalizacja
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.index'
    
    # Rejestracja blueprintów
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(chat_api)
    
    # Inicjalizacja panelu admina
    init_admin(app)
    
    # Endpoint do debugowania bazy danych
    @app.route('/db-debug')
    def db_debug():
        try:
            from sqlalchemy import text, inspect
            
            # Sprawdź, jaki silnik bazy danych jest używany
            engine_name = db.engine.name
            
            # Wykonaj bezpieczne zapytanie działające w obu bazach
            result = db.session.execute(text("SELECT 1 as test")).fetchone()
            
            # Pobierz listę tabel w sposób niezależny od bazy
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            return jsonify({
                "status": "success",
                "engine": engine_name,
                "test_query": dict(result) if result else None,
                "tables": tables,
                "connection_string": str(db.engine.url)
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_type": type(e).__name__,
                "connection_string": str(db.engine.url) if hasattr(db, 'engine') and hasattr(db.engine, 'url') else "unknown"
            }), 500
    
    # Inicjalizacja bazy danych
    with app.app_context():
        try:
            # Sprawdź połączenie
            db.session.execute(text("SELECT 1"))
            print("Połączenie z bazą danych nawiązane pomyślnie")
            
            # Utwórz tabele (bezpieczna metoda)
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if not existing_tables:
                print("Baza danych jest pusta, tworzę schemat...")
                db.create_all()
                
                # Tworzenie domyślnego administratora przy pierwszym uruchomieniu
                if User.query.count() == 0:
                    # Generuj parę kluczy RSA
                    try:
                        from Crypto.PublicKey import RSA
                        
                        # Generuj nową parę kluczy
                        key = RSA.generate(2048)
                        private_key = key.export_key().decode('utf-8')
                        public_key = key.publickey().export_key().decode('utf-8')
                        
                        # Utwórz nowego administratora
                        admin = User(username="admin", is_admin=True)
                        admin.set_password("TymczasoweHasloAdmina123!")  # Pamiętaj zmienić po pierwszym logowaniu
                        admin.public_key = public_key
                        admin.generate_user_id()
                        db.session.add(admin)
                        db.session.commit()
                        
                        print("\n\n==================================================")
                        print("UWAGA! UTWORZONO DOMYŚLNE KONTO ADMINISTRATORA:")
                        print("Login: admin")
                        print("Hasło: TymczasoweHasloAdmina123!")
                        print("\nPRYWATNY KLUCZ RSA (SKOPIUJ I ZACHOWAJ BEZPIECZNIE):")
                        print(private_key)
                        print("==================================================\n\n")
                        
                    except ImportError:
                        print("Nie można wygenerować pary kluczy - brak pakietu Crypto.PublicKey")
                        # Alternatywne rozwiązanie z tymczasowym kluczem
                        admin = User(username="admin", is_admin=True)
                        admin.set_password("TymczasoweHasloAdmina123!")
                        admin.public_key = "TEMPORARY_ADMIN_KEY"  # Specjalny klucz, który pozwala na logowanie bez weryfikacji
                        admin.generate_user_id()
                        db.session.add(admin)
                        db.session.commit()
                        print("Utworzono domyślne konto administratora z tymczasowym kluczem")
                    except Exception as e:
                        print(f"Błąd podczas tworzenia administratora: {e}")
                        db.session.rollback()
            else:
                print(f"Znaleziono istniejące tabele: {existing_tables}")
                
                # Sprawdź, czy wszystkie modele mają odpowiadające tabele
                models = db.Model.__subclasses__()
                model_tables = [model.__tablename__ for model in models]
                
                missing_tables = [table for table in model_tables if table not in existing_tables]
                if missing_tables:
                    print(f"Brakujące tabele: {missing_tables}")
                    db.create_all()  # Utworzy tylko brakujące tabele
                    print("Dodano brakujące tabele")
            
        except Exception as e:
            print(f"Błąd podczas inicjalizacji bazy danych: {e}")
            traceback.print_exc()
            db.session.rollback()
    
    # Dodaj zarządzanie sesją
    @app.before_request
    def before_request():
        """Zarządzanie sesją przed każdym żądaniem"""
        try:
            # Ustawienie czasu życia sesji
            app.permanent_session_lifetime = timedelta(hours=24)
            
            # Optymalizacja aktualizacji statusu online
            if current_user.is_authenticated and hasattr(current_user, 'is_online'):
                # Aktualizuj status tylko raz na 5 minut zamiast przy każdym żądaniu
                last_update_key = f'last_online_update_{current_user.id}'
                last_update = request.cookies.get(last_update_key, 0)
                try:
                    last_update = int(last_update)
                except (TypeError, ValueError):
                    last_update = 0
                    
                now = int(time.time())
                
                if now - last_update > 300:  # 5 minut = 300 sekund
                    current_user.is_online = True
                    db.session.commit()
                    # Cookies do zarządzania czasem ostatniej aktualizacji są obsługiwane w odpowiedzi
        except Exception as e:
            print(f"Błąd w before_request: {e}")
            db.session.rollback()
    
    # Dodaj obsługę błędów 404 i 500
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    # Endpointy dla panelu administracyjnego
    
    # Endpoint diagnostyczny dla sprawdzenia stanu bazy danych
    @app.route('/db-diagnostic')
    @login_required
    def db_diagnostic():
        # Bezpieczeństwo - tylko dla administratorów
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            # Sprawdź połączenie z bazą danych
            db_status = "OK" if db.session.execute(text("SELECT 1")).scalar() == 1 else "ERROR"
            
            # Sprawdź ścieżkę do bazy danych
            db_path = str(db.engine.url).split('://')[1].split('?')[0]
            
            # Sprawdź, czy plik istnieje (tylko dla SQLite)
            db_file_exists = False
            db_file_size = 0
            db_file_permissions = None
            
            if is_sqlite():
                db_file_exists = os.path.exists(db_path)
                db_file_size = os.path.getsize(db_path) if db_file_exists else 0
                try:
                    db_file_permissions = oct(os.stat(db_path).st_mode)[-3:] if db_file_exists else None
                except:
                    db_file_permissions = None
            
            # Pobierz podstawowe statystyki
            user_count = User.query.count()
            session_count = ChatSession.query.count()
            message_count = Message.query.count()
            
            # Pobierz statystyki wydajności (specyficzne dla typu bazy)
            db_stats = []
            
            if is_sqlite():
                db_stats = db.session.execute(text("PRAGMA stats")).fetchall()
            elif is_postgresql():
                try:
                    # Podstawowe statystyki PostgreSQL
                    db_stats = db.session.execute(text("""
                        SELECT * FROM pg_stat_database 
                        WHERE datname = current_database()
                    """)).fetchall()
                except Exception as e:
                    print(f"Błąd podczas pobierania statystyk PostgreSQL: {e}")
            
            return render_template('admin/db_diagnostic.html', 
                                  db_status=db_status,
                                  db_path=db_path,
                                  db_file_exists=db_file_exists, 
                                  db_file_size=db_file_size,
                                  db_file_permissions=db_file_permissions,
                                  user_count=user_count,
                                  session_count=session_count,
                                  message_count=message_count,
                                  db_stats=db_stats)
        except Exception as e:
            flash(f'Błąd podczas diagnostyki bazy danych: {str(e)}', 'danger')
            return render_template('admin/db_diagnostic.html', error=str(e))
    
    # Vacuum bazy danych (dostosowane do typu bazy)
    @app.route('/vacuum_database', methods=['POST'])
    @login_required
    def vacuum_database():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            if is_sqlite():
                # SQLite VACUUM
                db_path = str(db.engine.url).split('sqlite:///')[1].split('?')[0]
                conn = sqlite3.connect(db_path)
                conn.execute("VACUUM")
                conn.close()
                flash('Baza danych SQLite została zoptymalizowana pomyślnie', 'success')
            elif is_postgresql():
                # PostgreSQL VACUUM
                db.session.execute(text("VACUUM"))
                db.session.commit()
                flash('Baza danych PostgreSQL została zoptymalizowana pomyślnie', 'success')
            else:
                flash('Operacja VACUUM nie jest obsługiwana dla tej bazy danych', 'warning')
        except Exception as e:
            flash(f'Błąd podczas wykonywania VACUUM: {str(e)}', 'danger')
        return redirect(url_for('db_diagnostic'))
    
    # Sprawdzenie integralności bazy danych (dostosowane do typu bazy)
    @app.route('/check_integrity', methods=['POST'])
    @login_required
    def check_integrity():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            if is_sqlite():
                result = db.session.execute(text("PRAGMA integrity_check")).fetchone()[0]
                if result == 'ok':
                    flash('Baza danych SQLite jest spójna', 'success')
                else:
                    flash(f'Wykryto problemy z integralnością bazy danych: {result}', 'warning')
            elif is_postgresql():
                # PostgreSQL nie ma bezpośredniego odpowiednika, ale możemy sprawdzić połączenie
                # i podstawowe informacje o bazie danych
                result = db.session.execute(text("""
                    SELECT pg_is_in_recovery(), pg_postmaster_start_time()
                """)).fetchone()
                flash(f'Baza PostgreSQL działa, status recovery: {result[0]}, czas startu: {result[1]}', 'success')
            else:
                flash('Sprawdzanie integralności nie jest obsługiwane dla tej bazy danych', 'warning')
        except Exception as e:
            flash(f'Błąd podczas sprawdzania integralności: {str(e)}', 'danger')
        return redirect(url_for('db_diagnostic'))
    
    # Tworzenie kopii zapasowej bazy danych (dostosowane do typu bazy)
    @app.route('/backup_database', methods=['POST'])
    @login_required
    def backup_database():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            if is_sqlite():
                # Dla SQLite
                db_path = str(db.engine.url).split('sqlite:///')[1].split('?')[0]
                backup_dir = os.path.join(os.path.dirname(db_path), 'backups')
                os.makedirs(backup_dir, exist_ok=True)
                
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = os.path.join(backup_dir, f"database_backup_{timestamp}.db")
                
                # Kopia zapasowa z SQLite (aby mieć spójną kopię)
                conn = sqlite3.connect(db_path)
                backup = sqlite3.connect(backup_path)
                conn.backup(backup)
                backup.close()
                conn.close()
                
                flash(f'Kopia zapasowa została utworzona: {backup_path}', 'success')
            elif is_postgresql():
                # Dla PostgreSQL informujemy o alternatywach
                flash('Kopia zapasowa PostgreSQL powinna być wykonana przy użyciu narzędzi pg_dump lub przez panel Neon.', 'info')
                flash('Zalecamy korzystanie z automatycznych kopii zapasowych oferowanych przez Neon.', 'info')
            else:
                flash('Kopia zapasowa nie jest obsługiwana dla tej bazy danych', 'warning')
        except Exception as e:
            flash(f'Błąd podczas tworzenia kopii zapasowej: {str(e)}', 'danger')
        return redirect(url_for('db_diagnostic'))
    
    # Pobieranie kopii zapasowej (dostosowane do typu bazy)
    @app.route('/download_backup/<filename>')
    @login_required
    def download_backup(filename):
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            if is_sqlite():
                db_path = str(db.engine.url).split('sqlite:///')[1].split('?')[0]
                backup_dir = os.path.join(os.path.dirname(db_path), 'backups')
                backup_path = os.path.join(backup_dir, filename)
                
                # Sprawdź, czy plik istnieje
                if not os.path.exists(backup_path):
                    flash('Plik kopii zapasowej nie istnieje', 'danger')
                    return redirect(url_for('db_diagnostic'))
                    
                # Zwróć plik do pobrania
                return send_file(backup_path, as_attachment=True)
            else:
                flash('Pobieranie kopii zapasowej nie jest wspierane dla tej bazy danych', 'warning')
                return redirect(url_for('db_diagnostic'))
        except Exception as e:
            flash(f'Błąd podczas pobierania kopii zapasowej: {str(e)}', 'danger')
            return redirect(url_for('db_diagnostic'))
    
    # API dla uzyskania listy użytkowników
    @app.route('/api/admin/users')
    @login_required
    def admin_get_users():
        # Bezpieczeństwo - tylko dla administratorów
        if not current_user.is_admin:
            return jsonify({'status': 'error', 'message': 'Brak uprawnień'}), 403
            
        try:
            users = User.query.all()
            users_list = [
                {
                    'id': user.id,
                    'username': user.username,
                    'user_id': user.user_id,
                    'is_admin': user.is_admin,
                    'is_online': getattr(user, 'is_online', False)  # Bezpieczny dostęp do atrybutu
                } for user in users
            ]
            return jsonify({'status': 'success', 'users': users_list})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # API do nadawania uprawnień administratora
    @app.route('/api/admin/promote_to_admin', methods=['POST'])
    @login_required
    def promote_to_admin():
        # Bezpieczeństwo - tylko dla administratorów
        if not current_user.is_admin:
            return jsonify({'status': 'error', 'message': 'Brak uprawnień'}), 403
            
        try:
            data = request.get_json()
            username = data.get('username')
            
            if not username:
                return jsonify({'status': 'error', 'message': 'Brak nazwy użytkownika'}), 400
                
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
                
            user.is_admin = True
            db.session.commit()
            
            return jsonify({'status': 'success', 'message': 'Uprawnienia nadane pomyślnie'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # Endpoint do panelu administracyjnego
    @app.route('/dashboard')
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
        
        try:
            # Pobierz statystyki dla panelu
            user_count = User.query.count()
            session_count = ChatSession.query.count()
            message_count = Message.query.count()
            
            # Pobierz liczbę użytkowników online - z bezpieczną obsługą braku kolumny
            try:
                online_users = User.query.filter_by(is_online=True).count()
            except Exception as e:
                print(f"Nie można pobrać statusu online użytkowników: {e}")
                online_users = 0
        
            return render_template('admin/admin_panel.html', 
                                user_count=user_count,
                                session_count=session_count, 
                                message_count=message_count,
                                online_users=online_users)
        except Exception as e:
            flash(f'Błąd podczas generowania panelu: {str(e)}', 'danger')
            return render_template('admin/admin_panel.html', error=str(e))
            
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0')
