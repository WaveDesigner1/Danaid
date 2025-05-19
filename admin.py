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
            users_count = User.query.count()
            sessions_count = ChatSession.query.count()
            messages_count = Message.query.count()
            online_users_count = User.query.filter_by(is_online=True).count()
            
            return jsonify({
                'status': 'success',
                'data': {
                    'users_count': users_count,
                    'sessions_count': sessions_count,
                    'messages_count': messages_count,
                    'online_users_count': online_users_count,
                    'timestamp': int(time.time())
                }
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Nie można pobrać statystyk: {str(e)}'}), 500
    
    # API użytkowników
    @app.route('/api/users')
    @admin_required
    def get_users():
        try:
            users = User.query.all()
            user_list = []
            
            for user in users:
                try:
                    user_data = {
                        'id': user.id,
                        'username': user.username,
                        'user_id': str(getattr(user, 'user_id', str(user.id))),
                        'is_admin': bool(getattr(user, 'is_admin', False)),
                        'is_online': bool(getattr(user, 'is_online', False))
                    }
                    user_list.append(user_data)
                except Exception:
                    pass
            
            return jsonify({'status': 'success', 'users': user_list})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Nie można pobrać listy użytkowników: {str(e)}'}), 500
    
    # API zmiany uprawnień
    @app.route('/api/users/<string:user_id>/toggle_admin', methods=['POST'])
    @admin_required
    def toggle_admin(user_id):
        try:
            # Znajdź użytkownika
            user = User.query.filter_by(user_id=user_id).first()
            if not user and user_id.isdigit(): user = User.query.get(int(user_id))
            if not user: return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
            # Nie możemy zmienić uprawnień zalogowanego admina
            if user.user_id == current_user.user_id:
                return jsonify({'status': 'error', 'message': 'Nie możesz zmienić własnych uprawnień'}), 400
            
            # Zmień uprawnienia
            current_admin_state = bool(user.is_admin)
            user.is_admin = not current_admin_state
            db.session.commit()
            
            # Sprawdź, czy zmiany zostały zapisane
            db.session.refresh(user)
            verified_state = bool(user.is_admin)
            
            return jsonify({
                'status': 'success',
                'message': f'Uprawnienia użytkownika {user.username} zostały {"nadane" if verified_state else "odebrane"}',
                'is_admin': verified_state
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'Błąd podczas zmiany uprawnień: {str(e)}'}), 500
    
    # API naprawy uprawnień
    @app.route('/api/users/fix_admin/<string:user_id>', methods=['POST'])
    @admin_required
    def fix_admin(user_id):
        try:
            # Znajdź użytkownika
            user = User.query.filter_by(user_id=user_id).first()
            if not user and user_id.isdigit(): user = User.query.get(int(user_id))
            if not user: return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
            # Ustaw uprawnienia admina
            user.is_admin = True
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Uprawnienia administratora przywrócone dla użytkownika {user.username}',
                'user': {'username': user.username, 'is_admin': bool(user.is_admin)}
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'Błąd podczas naprawy uprawnień: {str(e)}'}), 500
    
    # Naprawa wszystkich uprawnień admin
    @app.route('/admin/repair_all_admin_permissions')
    @admin_required
    def repair_all_admin_permissions():
        try:
            all_users = User.query.all()
            admins = [user for user in all_users if getattr(user, 'is_admin', False)]
            
            for user in admins: user.is_admin = True
            db.session.commit()
            
            flash(f'Naprawiono uprawnienia dla {len(admins)} użytkowników!', 'success')
            return redirect(url_for('user.index_view'))
        except Exception as e:
            db.session.rollback()
            flash(f'Błąd podczas naprawy uprawnień: {str(e)}', 'error')
            return redirect(url_for('admin.index'))
    
    # Naprawa uprawnień pojedynczego użytkownika
    @app.route('/admin/repair_permissions/<int:user_id>')
    @admin_required
    def repair_permissions(user_id):
        try:
            user = User.query.get(user_id)
            if not user:
                flash('Użytkownik nie istnieje', 'error')
                return redirect(url_for('admin.index'))
            
            user.is_admin = True
            db.session.commit()
            
            flash(f'Uprawnienia administratora dla użytkownika {user.username} zostały naprawione!', 'success')
            return redirect(url_for('user.index_view'))
        except Exception as e:
            db.session.rollback()
            flash(f'Błąd podczas naprawy uprawnień: {str(e)}', 'error')
            return redirect(url_for('admin.index'))
    
    # API usuwania użytkownika
    @app.route('/api/users/<string:user_id>/delete', methods=['POST'])
    @admin_required
    def delete_user(user_id):
        try:
            # Znajdź użytkownika
            user = User.query.filter_by(user_id=user_id).first()
            if not user and user_id.isdigit(): user = User.query.get(int(user_id))
            if not user: return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
            # Nie możemy usunąć własnego konta
            if user.user_id == current_user.user_id:
                return jsonify({'status': 'error', 'message': 'Nie możesz usunąć własnego konta'}), 400
            
            # Usuń powiązane dane
            try:
                # Usuń sesje czatu i wiadomości
                sessions = ChatSession.query.filter(
                    (ChatSession.initiator_id == user.id) | (ChatSession.recipient_id == user.id)
                ).all()
                
                for session in sessions:
                    Message.query.filter_by(session_id=session.id).delete()
                
                ChatSession.query.filter(
                    (ChatSession.initiator_id == user.id) | (ChatSession.recipient_id == user.id)
                ).delete()
                
                # Zapisz nazwę użytkownika przed usunięciem
                username = user.username
                db.session.delete(user)
                db.session.commit()
                
                return jsonify({'status': 'success', 'message': f'Użytkownik {username} został usunięty'})
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
                current_user.is_online = False
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
