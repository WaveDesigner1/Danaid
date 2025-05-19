from flask import redirect, url_for, render_template, abort, request, jsonify, flash, Response, make_response
from flask_login import current_user, login_required
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import functools
from models import User, ChatSession, Message, db
from sqlalchemy import text, inspect
import sys
import subprocess
import time
import flask
import werkzeug
import traceback

# Dekorator sprawdzający uprawnienia administratora
def admin_required(f):
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Widok admina z zabezpieczeniami
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))

# Nowy widok administratora do zarządzania bazą danych
class DatabaseView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))
    
    @expose('/')
    def index(self):
        # Pobierz strukturę bazy danych
        try:
            # Kod tylko dla PostgreSQL
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            table_structure = {}
            record_counts = {}
            
            for table in tables:
                columns = inspector.get_columns(table)
                table_structure[table] = columns
                
                # Pobierz liczbę rekordów w tabeli
                try:
                    count = db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
                    record_counts[table] = count
                except Exception as e:
                    record_counts[table] = f"Błąd: {str(e)}"
            
            response = make_response(render_template('database.html', 
                          tables=tables, 
                          structure=table_structure,
                          record_counts=record_counts))
            
            # Dodaj nagłówki no-cache
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            
            return response
        except Exception as e:
            return render_template('database.html', error=str(e))
    
    @expose('/add_column', methods=['POST'])
    def add_column(self):
        try:
            table = request.form.get('table')
            column_name = request.form.get('column_name')
            column_type = request.form.get('column_type')
            default_value = request.form.get('default_value', '')
            
            if not all([table, column_name, column_type]):
                flash('Wszystkie pola są wymagane', 'error')
                return redirect(url_for('.index'))
            
            # Sprawdź, czy kolumna już istnieje
            inspector = inspect(db.engine)
            columns = inspector.get_columns(table)
            column_names = [col['name'] for col in columns]
            
            if column_name in column_names:
                flash(f'Kolumna {column_name} już istnieje w tabeli {table}', 'error')
                return redirect(url_for('.index'))
            
            # Dodaj kolumnę
            if default_value:
                query = f'ALTER TABLE "{table}" ADD COLUMN "{column_name}" {column_type} DEFAULT {default_value}'
            else:
                query = f'ALTER TABLE "{table}" ADD COLUMN "{column_name}" {column_type}'
            
            db.session.execute(text(query))
            db.session.commit()
            
            flash(f'Kolumna {column_name} została dodana do tabeli {table}', 'success')
            return redirect(url_for('.index'))
        except Exception as e:
            flash(f'Błąd: {str(e)}', 'error')
            return redirect(url_for('.index'))

# Klasa widoku diagnostyki
class DiagnosticsView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))
    
    @expose('/')
    def index(self):
        """Rozbudowana diagnostyka aplikacji dla administratora"""
        try:
            diagnostics = {
                'app_info': {
                    'flask_version': flask.__version__,
                    'python_version': sys.version,
                    'os_info': sys.platform,
                    'db_type': db.engine.name,
                    'werkzeug_version': werkzeug.__version__
                },
                'db_status': {},
                'session_info': {
                    'session_type': 'filesystem',
                    'permanent_session_lifetime': '24 hours',
                    'secret_key_set': True
                },
                'route_info': []
            }
            
            # Diagnostyka bazy danych
            try:
                db.session.execute(text('SELECT 1'))
                diagnostics['db_status']['connection'] = 'OK'
                
                # Pobierz informacje o tabelach
                inspector = inspect(db.engine)
                tables = inspector.get_table_names()
                diagnostics['db_status']['tables'] = tables
                
                # Pobierz liczby rekordów
                record_counts = {}
                for table in tables:
                    try:
                        count = db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
                        record_counts[table] = count
                    except Exception as table_err:
                        record_counts[table] = f"Błąd: {str(table_err)}"
                    
                diagnostics['db_status']['record_counts'] = record_counts
                
            except Exception as db_err:
                diagnostics['db_status']['connection'] = f"Błąd: {str(db_err)}"
            
            response = make_response(render_template('diagnostics.html', diagnostics=diagnostics))
            
            # Dodaj nagłówki no-cache
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            
            return response
        except Exception as e:
            return render_template('diagnostics.html', error=str(e))

# Klasa widoku webshell
class WebshellView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))
    
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        """Prosty webshell dla administratora (tylko podstawowe komendy)"""
        result = None
        command = None
        
        if request.method == 'POST':
            command = request.form.get('command')
            
            # Lista dozwolonych komend (dla bezpieczeństwa)
            allowed_commands = ['ls', 'ps', 'df', 'free', 'uptime', 'cat', 'grep', 'head', 'tail', 'find']
            
            # Sprawdź, czy komenda jest dozwolona
            if command:
                cmd_parts = command.split()
                if cmd_parts and cmd_parts[0] in allowed_commands:
                    try:
                        result = subprocess.check_output(
                            command, 
                            shell=True, 
                            stderr=subprocess.STDOUT,
                            timeout=5
                        ).decode('utf-8')
                    except Exception as e:
                        result = f"Błąd: {str(e)}"
                else:
                    result = "Niedozwolona komenda. Dozwolone są tylko: " + ", ".join(allowed_commands)
        
        # Sprawdź czy to AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            return jsonify({
                'result': result,
                'command': command
            })
        
        # Normalny request - renderujemy szablon
        html_content = render_template('webshell.html', result=result, command=command)
        
        # Tworzymy obiekt odpowiedzi z zawartości HTML
        response = make_response(html_content)
        
        # Dodaj nagłówki no-cache
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response

# Inicjalizacja panelu admina
def init_admin(app):
    admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', url='/flask_admin')
    
    # Dodaj jawnie endpoint dla każdego widoku modelu
    admin.add_view(SecureModelView(User, db.session, endpoint='user'))
    admin.add_view(SecureModelView(ChatSession, db.session, endpoint='chatsession'))
    admin.add_view(SecureModelView(Message, db.session, endpoint='message'))
    
    # Te widoki już mają poprawne endpointy
    admin.add_view(DatabaseView(name='Zarządzanie bazą danych', endpoint='db_admin'))
    admin.add_view(DiagnosticsView(name='Diagnostyka', endpoint='diagnostics'))
    admin.add_view(WebshellView(name='Webshell', endpoint='webshell'))
    
    # Panel administracyjny z obsługą błędów
    @app.route('/admin_dashboard')
    @admin_required
    def admin_panel():
        try:
            return render_template('admin_panel.html')
        except Exception as e:
            error_traceback = traceback.format_exc()
            return f"<h1>Error in admin_panel</h1><p>{str(e)}</p><pre>{error_traceback}</pre>"
    
    # API do pobierania statystyk dla panelu administratora
    @app.route('/api/admin/stats')
    @admin_required
    def get_admin_stats():
        try:
            # Pobierz liczby rekordów
            users_count = User.query.count()
            sessions_count = ChatSession.query.count()
            messages_count = Message.query.count()
            online_users_count = User.query.filter_by(is_online=True).count()
            
            return jsonify({
                'users_count': users_count,
                'sessions_count': sessions_count,
                'messages_count': messages_count,
                'online_users_count': online_users_count,
                'timestamp': int(time.time())
            })
        except Exception as e:
            print(f"Błąd API /api/admin/stats: {str(e)}")
            traceback_str = traceback.format_exc()
            print(traceback_str)
            return jsonify({'error': f'Nie można pobrać statystyk: {str(e)}'}), 500
    
    # API do pobierania listy użytkowników
    @app.route('/api/users')
    @admin_required
    def get_users():
        try:
            users = User.query.all()
            user_list = []
            
            for user in users:
                # Bezpieczne pobieranie atrybutów z obsługą błędów
                try:
                    user_data = {
                        'id': user.id,
                        'username': user.username,
                        'user_id': str(getattr(user, 'user_id', str(user.id))),
                        'is_admin': bool(getattr(user, 'is_admin', False)),
                        'is_online': bool(getattr(user, 'is_online', False))
                    }
                    user_list.append(user_data)
                except Exception as user_error:
                    # Log błędu dla pojedynczego użytkownika nie powinien przerwać całej operacji
                    print(f"Błąd podczas przetwarzania użytkownika {user.id}: {str(user_error)}")
                    
            return jsonify(user_list)
        except Exception as e:
            print(f"Błąd API /api/users: {str(e)}")
            traceback_str = traceback.format_exc()
            print(traceback_str)
            return jsonify({'error': f'Nie można pobrać listy użytkowników: {str(e)}'}), 500
    
    # API do zmiany uprawnień administratora
    @app.route('/api/users/<string:user_id>/toggle_admin', methods=['POST'])
    @admin_required
    def toggle_admin(user_id):
        try:
            # Znajdź użytkownika po user_id
            user = User.query.filter_by(user_id=user_id).first()
            
            # Jeśli nie znaleziono, spróbuj po id (dla kompatybilności)
            if not user and user_id.isdigit():
                user = User.query.get(int(user_id))
            
            # Jeśli nadal nie znaleziono, zwróć błąd
            if not user:
                return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
                
            # Nie możemy usunąć uprawnień zalogowanemu administratorowi
            if user.user_id == current_user.user_id:
                return jsonify({'status': 'error', 'message': 'Nie możesz zmienić własnych uprawnień'}), 400
                
            # Zmiana stanu uprawnień
            user.is_admin = not user.is_admin
            
            # Zapisanie zmian w bazie danych
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Uprawnienia użytkownika {user.username} zostały {"nadane" if user.is_admin else "odebrane"}',
                'is_admin': user.is_admin
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'Błąd podczas zmiany uprawnień: {str(e)}'}), 500
    
    # API do usuwania użytkownika
    @app.route('/api/users/<string:user_id>/delete', methods=['POST'])
    @admin_required
    def delete_user(user_id):
        try:
            # Znajdź użytkownika po user_id
            user = User.query.filter_by(user_id=user_id).first()
            
            # Jeśli nie znaleziono, spróbuj po id (dla kompatybilności)
            if not user and user_id.isdigit():
                user = User.query.get(int(user_id))
                
            # Jeśli nadal nie znaleziono, zwróć błąd
            if not user:
                return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
                
            # Nie możemy usunąć zalogowanego administratora
            if user.user_id == current_user.user_id:
                return jsonify({'status': 'error', 'message': 'Nie możesz usunąć własnego konta'}), 400
                
            # Usuwanie powiązanych danych
            try:
                # Usuń wszystkie sesje czatu, w których użytkownik brał udział
                sessions = ChatSession.query.filter(
                    (ChatSession.initiator_id == user.id) | 
                    (ChatSession.recipient_id == user.id)
                ).all()
                
                for session in sessions:
                    # Usuń wszystkie wiadomości w sesji
                    Message.query.filter_by(session_id=session.id).delete()
                    
                # Usuń sesje czatu
                ChatSession.query.filter(
                    (ChatSession.initiator_id == user.id) | 
                    (ChatSession.recipient_id == user.id)
                ).delete()
                
                # Zapisz nazwę użytkownika przed usunięciem
                username = user.username
                
                # Usuń użytkownika
                db.session.delete(user)
                db.session.commit()
                
                return jsonify({
                    'status': 'success',
                    'message': f'Użytkownik {username} został usunięty',
                })
            except Exception as e:
                db.session.rollback()
                return jsonify({'status': 'error', 'message': f'Błąd podczas usuwania użytkownika: {str(e)}'}), 500
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Błąd podczas usuwania użytkownika: {str(e)}'}), 500
    
    # Endpoint do sprawdzenia sesji
    @app.route('/check_session')
    def check_session():
        """Endpoint do sprawdzenia stanu sesji"""
        if current_user.is_authenticated:
            return jsonify({
                'authenticated': True,
                'user_id': current_user.user_id,
                'username': current_user.username,
                'is_admin': current_user.is_admin
            })
        else:
            return jsonify({
                'authenticated': False
            })
    
    # Endpoint do cichego wylogowania (bez przekierowania)
    @app.route('/silent-logout', methods=['POST'])
    def silent_logout():
        """Wylogowanie bez przekierowania"""
        if current_user.is_authenticated:
            try:
                # Aktualizacja statusu online
                current_user.is_online = False
                db.session.commit()
            except Exception:
                db.session.rollback()
        
        return jsonify({'status': 'success'})
    
    # Dodanie nagłówków CORS i bezpieczeństwa
    @app.after_request
    def add_headers(response):
        # Nagłówki bezpieczeństwa
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response
