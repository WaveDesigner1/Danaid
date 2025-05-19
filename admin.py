from flask import redirect, url_for, render_template, abort, request, jsonify, flash, Response, make_response
from flask_login import current_user, login_required
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import functools
from models import User, ChatSession, Message, db
from sqlalchemy import text, inspect
import sys, subprocess, time, flask, werkzeug, traceback

# Dekorator sprawdzający uprawnienia administratora
def admin_required(f):
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin: abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Bazowy widok admina z zabezpieczeniami
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))
    
    def on_model_change(self, form, model, is_created):
        if isinstance(model, User) and model.is_admin not in (True, False):
            model.is_admin = bool(model.is_admin)
        super(SecureModelView, self).on_model_change(form, model, is_created)

# Rozszerzona klasa dla modelu User
class UserModelView(SecureModelView):
    column_exclude_list = ['password_hash']
    form_excluded_columns = ['password_hash', 'sessions_initiated', 'sessions_received', 'messages']
    column_filters = ['is_admin', 'is_online']
    column_formatters = {
        'is_admin': lambda v, c, m, p: 'Tak' if m.is_admin else 'Nie',
        'is_online': lambda v, c, m, p: 'Tak' if m.is_online else 'Nie',
    }
    
    def update_model(self, form, model):
        try:
            form.populate_obj(model)
            model.is_admin = bool(model.is_admin)
            model.is_online = bool(model.is_online)
            self.session.commit()
            return True
        except Exception as ex:
            if not self.handle_view_exception(ex): 
                flash(f'Nie można zaktualizować rekordu: {str(ex)}', 'error')
            self.session.rollback()
            return False

# Nowy widok administratora do zarządzania bazą danych
class DatabaseView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))
    
    @expose('/')
    def index(self):
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            table_structure = {}
            record_counts = {}
            
            for table in tables:
                table_structure[table] = inspector.get_columns(table)
                try: record_counts[table] = db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
                except Exception as e: record_counts[table] = f"Błąd: {str(e)}"
            
            response = make_response(render_template('database.html', 
                          tables=tables, structure=table_structure, record_counts=record_counts))
            
            # Nagłówki no-cache
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            
            return response
        except Exception as e:
            return render_template('database.html', error=str(e))

# Klasa widoku diagnostyki
class DiagnosticsView(BaseView):
    def is_accessible(self): return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs): return redirect(url_for('auth.index', next=request.url))
    
    @expose('/')
    def index(self):
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
                }
            }
            
            try:
                db.session.execute(text('SELECT 1'))
                diagnostics['db_status']['connection'] = 'OK'
                tables = inspect(db.engine).get_table_names()
                diagnostics['db_status']['tables'] = tables
                
                record_counts = {}
                for table in tables:
                    try: record_counts[table] = db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
                    except Exception as e: record_counts[table] = f"Błąd: {str(e)}"
                diagnostics['db_status']['record_counts'] = record_counts
            except Exception as e:
                diagnostics['db_status']['connection'] = f"Błąd: {str(e)}"
            
            response = make_response(render_template('diagnostics.html', diagnostics=diagnostics))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            return response
        except Exception as e:
            return render_template('diagnostics.html', error=str(e))

# Klasa widoku webshell
class WebshellView(BaseView):
    def is_accessible(self): return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs): return redirect(url_for('auth.index', next=request.url))
    
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        result = None
        command = None
        
        if request.method == 'POST':
            command = request.form.get('command')
            allowed_commands = ['ls', 'ps', 'df', 'free', 'uptime', 'cat', 'grep', 'head', 'tail', 'find']
            
            if command:
                cmd_parts = command.split()
                if cmd_parts and cmd_parts[0] in allowed_commands:
                    try:
                        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5).decode('utf-8')
                    except Exception as e:
                        result = f"Błąd: {str(e)}"
                else:
                    result = "Niedozwolona komenda. Dozwolone są tylko: " + ", ".join(allowed_commands)
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'result': result, 'command': command})
        
        response = make_response(render_template('webshell.html', result=result, command=command))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

# Inicjalizacja panelu admina
def init_admin(app):
    admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', url='/flask_admin')
    
    # Dodaj widoki
    admin.add_view(UserModelView(User, db.session, endpoint='user', name='Użytkownicy'))
    admin.add_view(SecureModelView(ChatSession, db.session, endpoint='chatsession', name='Sesje Czatu'))
    admin.add_view(SecureModelView(Message, db.session, endpoint='message', name='Wiadomości'))
    admin.add_view(DatabaseView(name='Zarządzanie bazą danych', endpoint='db_admin'))
    admin.add_view(DiagnosticsView(name='Diagnostyka', endpoint='diagnostics'))
    admin.add_view(WebshellView(name='Webshell', endpoint='webshell'))
    
    # Panel administracyjny
    @app.route('/admin_dashboard')
    @admin_required
    def admin_panel():
        try: return render_template('admin_panel.html')
        except Exception as e: return f"<h1>Error in admin_panel</h1><p>{str(e)}</p><pre>{traceback.format_exc()}</pre>"
    
    # API statystyk
    @app.route('/api/admin/stats')
    @admin_required
    def get_admin_stats():
        try:
            # Pobierz dane bezpośrednio przez SQL dla większej niezawodności
            stats_query = """
            SELECT 
                (SELECT COUNT(*) FROM "user") as users_count,
                (SELECT COUNT(*) FROM "chat_session") as sessions_count,
                (SELECT COUNT(*) FROM "message") as messages_count,
                (SELECT COUNT(*) FROM "user" WHERE is_online = TRUE) as online_users_count
            """
            
            result = db.session.execute(text(stats_query)).fetchone()
            
            return jsonify({
                'status': 'success',
                'data': {
                    'users_count': result[0],
                    'sessions_count': result[1],
                    'messages_count': result[2],
                    'online_users_count': result[3],
                    'timestamp': int(time.time())
                }
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Nie można pobrać statystyk: {str(e)}'}), 500
    
    # API użytkowników - pobieranie bezpośrednio z PostgreSQL
    @app.route('/api/users')
    @admin_required
    def get_users():
        try:
            # Pobierz dane bezpośrednio z bazy przez SQL zamiast ORM
            users_query = 'SELECT id, username, user_id, is_admin, is_online FROM "user"'
            raw_users = db.session.execute(text(users_query)).fetchall()
            
            user_list = []
            
            for user in raw_users:
                user_data = {
                    'id': user[0],
                    'username': user[1],
                    'user_id': str(user[2]),
                    'is_admin': bool(user[3]),
                    'is_online': bool(user[4])
                }
                user_list.append(user_data)
            
            return jsonify({'status': 'success', 'users': user_list})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Nie można pobrać listy użytkowników: {str(e)}'}), 500
    
    # API zmiany uprawnień - prosta wersja bez zbędnych funkcji
    @app.route('/api/users/<string:user_id>/toggle_admin', methods=['POST'])
    @admin_required
    def toggle_admin(user_id):
        try:
            # Znajdź użytkownika przez SQL
            user_query = 'SELECT id, username, user_id, is_admin FROM "user" WHERE user_id = :user_id'
            user = db.session.execute(text(user_query), {'user_id': user_id}).fetchone()
            
            if not user:
                return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
            # Nie możemy zmienić własnych uprawnień
            if str(user[2]) == current_user.user_id:
                return jsonify({'status': 'error', 'message': 'Nie możesz zmienić własnych uprawnień'}), 400
            
            # Zmień uprawnienia administratora (odwróć obecny stan)
            current_admin_state = bool(user[3])
            new_admin_state = not current_admin_state
            
            # Aktualizuj bezpośrednio przez SQL
            update_query = 'UPDATE "user" SET is_admin = :new_state WHERE user_id = :user_id'
            db.session.execute(text(update_query), {'new_state': new_admin_state, 'user_id': user_id})
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Uprawnienia użytkownika {user[1]} zostały {"nadane" if new_admin_state else "odebrane"}',
                'is_admin': new_admin_state
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'Błąd podczas zmiany uprawnień: {str(e)}'}), 500
    
    # API usuwania użytkownika
    @app.route('/api/users/<string:user_id>/delete', methods=['POST'])
    @admin_required
    def delete_user(user_id):
        try:
            # Znajdź użytkownika przez SQL
            user_query = 'SELECT id, username, user_id FROM "user" WHERE user_id = :user_id'
            user = db.session.execute(text(user_query), {'user_id': user_id}).fetchone()
            
            if not user:
                return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
            # Nie możemy usunąć własnego konta
            if str(user[2]) == current_user.user_id:
                return jsonify({'status': 'error', 'message': 'Nie możesz usunąć własnego konta'}), 400
            
            # Usuń powiązane dane w jednej transakcji
            user_id_value = user[0]  # ID użytkownika w bazie (klucz główny)
            username = user[1]
            
            try:
                # Usuń wiadomości powiązane z sesjami użytkownika
                db.session.execute(text("""
                    DELETE FROM "message" 
                    WHERE session_id IN (
                        SELECT id FROM "chat_session" 
                        WHERE initiator_id = :user_id OR recipient_id = :user_id
                    )
                """), {'user_id': user_id_value})
                
                # Usuń sesje czatu użytkownika
                db.session.execute(text("""
                    DELETE FROM "chat_session" 
                    WHERE initiator_id = :user_id OR recipient_id = :user_id
                """), {'user_id': user_id_value})
                
                # Usuń użytkownika
                db.session.execute(text('DELETE FROM "user" WHERE id = :user_id'), 
                                   {'user_id': user_id_value})
                
                db.session.commit()
                
                return jsonify({
                    'status': 'success',
                    'message': f'Użytkownik {username} został usunięty'
                })
            except Exception as e:
                db.session.rollback()
                return jsonify({'status': 'error', 'message': f'Błąd podczas usuwania użytkownika: {str(e)}'}), 500
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Błąd podczas usuwania użytkownika: {str(e)}'}), 500
    
    # Sprawdzenie sesji
    @app.route('/check_session')
    def check_session():
        if current_user.is_authenticated:
            return jsonify({
                'authenticated': True,
                'user_id': current_user.user_id,
                'username': current_user.username,
                'is_admin': current_user.is_admin
            })
        else:
            return jsonify({'authenticated': False})
    
    # Ciche wylogowanie
    @app.route('/silent-logout', methods=['POST'])
    def silent_logout():
        if current_user.is_authenticated:
            try:
                # Aktualizacja statusu bezpośrednio w bazie
                db.session.execute(text("""
                    UPDATE "user" SET is_online = FALSE 
                    WHERE user_id = :user_id
                """), {'user_id': current_user.user_id})
                db.session.commit()
            except Exception:
                db.session.rollback()
        return jsonify({'status': 'success'})
    
    # Nagłówki bezpieczeństwa
    @app.after_request
    def add_headers(response):
        if request.path.startswith('/api/') or request.path.startswith('/flask_admin/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response
