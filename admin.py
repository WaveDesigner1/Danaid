"""
admin.py - Zoptymalizowany panel administratora
Redukcja z 200 → 120 linii kodu
"""
from flask import redirect, url_for, render_template, abort, request, jsonify, make_response
from flask_login import current_user, login_required
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import functools
from models import User, ChatSession, Message, db
from sqlalchemy import text, inspect
import sys, subprocess, time, flask, werkzeug

# === DECORATORS ===
def admin_required(f):
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin: 
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# === SECURE MODEL VIEW ===
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))

# === DIAGNOSTICS VIEW ===
class DiagnosticsView(BaseView):
    def is_accessible(self): 
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs): 
        return redirect(url_for('auth.index', next=request.url))
    
    @expose('/')
    def index(self):
        try:
            diagnostics = {
                'app_info': {
                    'flask_version': flask.__version__,
                    'python_version': sys.version,
                    'db_type': db.engine.name,
                    'werkzeug_version': werkzeug.__version__
                },
                'db_status': self._get_db_status()
            }
            
            response = make_response(render_template('diagnostics.html', diagnostics=diagnostics))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            return response
        except Exception as e:
            return render_template('diagnostics.html', error=str(e))
    
    def _get_db_status(self):
        """Pobiera status bazy danych"""
        try:
            db.session.execute(text('SELECT 1'))
            tables = inspect(db.engine).get_table_names()
            
            record_counts = {}
            for table in tables:
                try: 
                    record_counts[table] = db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
                except: 
                    record_counts[table] = "Błąd"
            
            return {
                'connection': 'OK',
                'tables': tables,
                'record_counts': record_counts
            }
        except Exception as e:
            return {'connection': f"Błąd: {str(e)}"}

# === WEBSHELL VIEW ===
class WebshellView(BaseView):
    def is_accessible(self): 
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs): 
        return redirect(url_for('auth.index', next=request.url))
    
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
                        result = subprocess.check_output(
                            command, shell=True, stderr=subprocess.STDOUT, timeout=5
                        ).decode('utf-8')
                    except Exception as e:
                        result = f"Błąd: {str(e)}"
                else:
                    result = "Niedozwolona komenda. Dozwolone: " + ", ".join(allowed_commands)
        
        response = make_response(render_template('webshell.html', result=result, command=command))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

# === ADMIN INITIALIZATION ===
def init_admin(app):
    admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', url='/flask_admin')
    
    # Dodaj widoki
    admin.add_view(DiagnosticsView(name='Diagnostyka', endpoint='diagnostics'))
    admin.add_view(WebshellView(name='Webshell', endpoint='webshell'))
    
    # === MAIN ADMIN ROUTES ===
    @app.route('/admin_dashboard')
    @admin_required
    def admin_panel():
        return render_template('admin_panel.html')
    
    @app.route('/api/admin/stats')
    @admin_required
    def get_admin_stats():
        """API statystyk - zunifikowane zapytanie"""
        try:
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
            return jsonify({'status': 'error', 'message': f'Błąd statystyk: {str(e)}'}), 500
    
    @app.route('/check_session')
    def check_session():
        """Sprawdzenie sesji użytkownika"""
        if current_user.is_authenticated:
            return jsonify({
                'authenticated': True,
                'user_id': current_user.user_id,
                'username': current_user.username,
                'is_admin': current_user.is_admin
            })
        return jsonify({'authenticated': False})
    
    @app.route('/silent-logout', methods=['POST'])
    def silent_logout():
        """Ciche wylogowanie"""
        return jsonify({'status': 'success'})
    
    # === SECURITY HEADERS ===
    @app.after_request
    def add_security_headers(response):
        if request.path.startswith(('/api/', '/flask_admin/')):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response
