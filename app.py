from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_required
from datetime import timedelta
import os
import shutil
import datetime
import sqlite3

# Bezpośrednie importy
from models import db, User, ChatSession, Message
from admin import init_admin
from auth import auth_bp
from chat import chat_bp
from chat_api import chat_api

# Inicjalizacja login managera
login_manager = LoginManager()

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
    
    # Konfiguracja bazy danych - KRYTYCZNA ZMIANA ŚCIEŻKI NA RENDER!
    if 'RENDER' in os.environ:
        # Używanie TRWAŁEGO dysku na Render zamiast /tmp
        render_data_dir = '/opt/render/project/data'
        os.makedirs(render_data_dir, exist_ok=True)
        db_path = os.path.join(render_data_dir, 'users.db')
        print(f"Używam trwałej bazy danych na Render: {db_path}")
    else:
        # Upewnij się, że katalog instance istnieje
        instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
        if not os.path.exists(instance_path):
            os.makedirs(instance_path, exist_ok=True)
        db_path = os.path.join(instance_path, 'users.db')
    
    # Optymalizacja wydajności bazy danych SQLite (punkt 2)
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f'sqlite:///{db_path}?isolation_level=READ_UNCOMMITTED'
        f'&journal_mode=WAL&synchronous=NORMAL&cache_size=5000'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 10,
        'max_overflow': 20,
        'pool_timeout': 30
    }
    
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
    
    # Inicjalizacja bazy danych
    with app.app_context():
        try:
            db.create_all()
            print("Baza danych została utworzona/zweryfikowana pomyślnie")
        except Exception as e:
            print(f"Błąd podczas inicjalizacji bazy danych: {e}")
            import traceback
            traceback.print_exc()
    
    # Rejestracja blueprintów
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(chat_api)
    
    # Inicjalizacja panelu admina
    init_admin(app)
    
    # Dodaj zarządzanie sesją
    @app.before_request
    def before_request():
        try:
            app.permanent_session_lifetime = timedelta(hours=24)
            if current_user.is_authenticated and hasattr(current_user, 'is_online'):
                current_user.is_online = True
                db.session.commit()
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
    
    # Endpointy dla panelu administracyjnego (punkt 7)
    
    # Endpoint diagnostyczny dla sprawdzenia stanu bazy danych
    @app.route('/db-diagnostic')
    @login_required
    def db_diagnostic():
        # Bezpieczeństwo - tylko dla administratorów (punkt 8)
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            # Sprawdź połączenie z bazą danych
            db_status = "OK" if db.session.execute("SELECT 1").scalar() == 1 else "ERROR"
            
            # Sprawdź ścieżkę do bazy danych
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].split('sqlite:///')[1].split('?')[0]
            
            # Sprawdź, czy plik istnieje
            db_file_exists = os.path.exists(db_path)
            
            # Pobierz podstawowe statystyki
            user_count = User.query.count()
            session_count = ChatSession.query.count()
            message_count = Message.query.count()
            
            # Pobierz statystyki wydajności SQLite
            db_stats = db.session.execute("PRAGMA stats").fetchall()
            
            return render_template('admin/db_diagnostic.html', 
                                  db_status=db_status,
                                  db_path=db_path,
                                  db_file_exists=db_file_exists, 
                                  user_count=user_count,
                                  session_count=session_count,
                                  message_count=message_count,
                                  db_stats=db_stats)
        except Exception as e:
            flash(f'Błąd podczas diagnostyki bazy danych: {str(e)}', 'danger')
            return render_template('admin/db_diagnostic.html', error=str(e))
    
    # Vacuum bazy danych
    @app.route('/vacuum_database', methods=['POST'])
    @login_required
    def vacuum_database():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            # SQLAlchemy nie obsługuje VACUUM bezpośrednio, używamy połączenia SQLite
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].split('sqlite:///')[1].split('?')[0]
            conn = sqlite3.connect(db_path)
            conn.execute("VACUUM")
            conn.close()
            
            flash('Baza danych została zoptymalizowana pomyślnie', 'success')
        except Exception as e:
            flash(f'Błąd podczas wykonywania VACUUM: {str(e)}', 'danger')
        return redirect(url_for('db_diagnostic'))
    
    # Sprawdzenie integralności bazy danych
    @app.route('/check_integrity', methods=['POST'])
    @login_required
    def check_integrity():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            result = db.session.execute("PRAGMA integrity_check").fetchone()[0]
            if result == 'ok':
                flash('Baza danych jest spójna', 'success')
            else:
                flash(f'Wykryto problemy z integralnością bazy danych: {result}', 'warning')
        except Exception as e:
            flash(f'Błąd podczas sprawdzania integralności: {str(e)}', 'danger')
        return redirect(url_for('db_diagnostic'))
    
    # Tworzenie kopii zapasowej bazy danych
    @app.route('/backup_database', methods=['POST'])
    @login_required
    def backup_database():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            # Ścieżka do bazy danych
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].split('sqlite:///')[1].split('?')[0]
            # Ścieżka do kopii zapasowej
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
        except Exception as e:
            flash(f'Błąd podczas tworzenia kopii zapasowej: {str(e)}', 'danger')
        return redirect(url_for('db_diagnostic'))
    
    # Pobieranie kopii zapasowej
    @app.route('/download_backup/<filename>')
    @login_required
    def download_backup(filename):
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
            
        try:
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].split('sqlite:///')[1].split('?')[0]
            backup_dir = os.path.join(os.path.dirname(db_path), 'backups')
            backup_path = os.path.join(backup_dir, filename)
            
            # Sprawdź, czy plik istnieje
            if not os.path.exists(backup_path):
                flash('Plik kopii zapasowej nie istnieje', 'danger')
                return redirect(url_for('db_diagnostic'))
                
            # Zwróć plik do pobrania
            return send_file(backup_path, as_attachment=True)
        except Exception as e:
            flash(f'Błąd podczas pobierania kopii zapasowej: {str(e)}', 'danger')
            return redirect(url_for('db_diagnostic'))
    
    # Endpoint dla panelu webshell
    @app.route('/webshell')
    @login_required
    def webshell():
        # Bezpieczeństwo - tylko dla administratorów (punkt 8)
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
        return render_template('admin/webshell.html')
    
    # API dla uzyskania listy użytkowników - zmieniono nazwę na admin_get_users
    @app.route('/api/admin/users')
    @login_required
    def admin_get_users():
        # Bezpieczeństwo - tylko dla administratorów (punkt 8)
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
                    'is_online': user.is_online
                } for user in users
            ]
            return jsonify({'status': 'success', 'users': users_list})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # API do nadawania uprawnień administratora
    @app.route('/api/admin/promote_to_admin', methods=['POST'])
    @login_required
    def promote_to_admin():
        # Bezpieczeństwo - tylko dla administratorów (punkt 8)
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
    
    return app

# Jeśli skrypt jest uruchamiany bezpośrednio
    @app.route('/admin_dashboard')
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            flash('Brak dostępu do tej strony', 'danger')
            return redirect(url_for('auth.index'))
        
        try:
            # Pobierz statystyki dla dashboardu
            user_count = User.query.count()
            session_count = ChatSession.query.count()
            message_count = Message.query.count()
            online_users = User.query.filter_by(is_online=True).count()
        
            return render_template('admin/dashboard.html', 
                              user_count=user_count,
                              session_count=session_count, 
                              message_count=message_count,
                              online_users=online_users)
         except Exception as e:
            flash(f'Błąd podczas generowania dashboardu: {str(e)}', 'danger')
            return render_template('admin/dashboard.html', error=str(e))
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0')
