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

# Bazowy widok admina
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))

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
    
    # Dodaj tylko niezbędne widoki
    admin.add_view(DiagnosticsView(name='Diagnostyka', endpoint='diagnostics'))
    admin.add_view(WebshellView(name='Webshell', endpoint='webshell'))
    
    # Panel administracyjny z uproszczonym interfejsem
    @app.route('/admin_dashboard')
    @admin_required
    def admin_panel():
        try: return render_template('admin_panel.html')
        except Exception as e: return f"<h1>Error in admin_panel</h1><p>{str(e)}</p><pre>{traceback.format_exc()}</pre>"
    
    # API statystyk - tylko odczyt
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
    
    # Ciche wylogowanie - usunięto aktualizację stanu
    @app.route('/silent-logout', methods=['POST'])
    def silent_logout():
        return jsonify({'status': 'success'})
    
    # Nagłówki bezpieczeństwa
    @app.after_request
    def add_headers(response):
        if request.path.startswith('/api/') or request.path.startswith('/flask_admin/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response
