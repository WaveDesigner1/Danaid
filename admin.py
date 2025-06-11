"""
admin.py - Zoptymalizowany panel administratora - FIXED VERSION
Naprawione problemy z przekierowaniem i 500 errors
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
    
    # === MAIN ADMIN ROUTES - FIXED ===
    @app.route('/admin_dashboard')
    @admin_required
    def admin_panel():
        """Main admin dashboard - CLEAN VERSION"""
        print(f"🔧 Admin dashboard accessed by: {current_user.username}")
        return render_template('admin_panel.html')
    
    # ✅ NOWY ENDPOINT DO SPRAWDZANIA UPRAWNIEŃ ADMINISTRATORA
    @app.route('/api/check_admin')
    @login_required
    def check_admin():
        """Sprawdza uprawnienia administratora - FIXED"""
        try:
            is_admin = getattr(current_user, 'is_admin', False)
            print(f"🔍 Admin check for {current_user.username}: {is_admin}")
            
            return jsonify({
                'is_admin': bool(is_admin),
                'username': current_user.username,
                'user_id': current_user.user_id
            })
        except Exception as e:
            print(f"❌ Admin check error: {e}")
            return jsonify({'is_admin': False, 'error': str(e)}), 200  # 200 aby nie blokować JS
    
    @app.route('/api/admin/stats')
    @admin_required
    def get_admin_stats():
        """API statystyk - zunifikowane zapytanie - FIXED"""
        try:
            print(f"📊 Stats requested by admin: {current_user.username}")
            
            stats_query = """
            SELECT 
                (SELECT COUNT(*) FROM "user") as users_count,
                (SELECT COUNT(*) FROM "chat_session") as sessions_count,
                (SELECT COUNT(*) FROM "message") as messages_count,
                (SELECT COUNT(*) FROM "user" WHERE is_online = TRUE) as online_users_count
            """
            
            result = db.session.execute(text(stats_query)).fetchone()
            
            stats_data = {
                'users_count': result[0] if result else 0,
                'sessions_count': result[1] if result else 0, 
                'messages_count': result[2] if result else 0,
                'online_users_count': result[3] if result else 0,
                'timestamp': int(time.time())
            }
            
            print(f"📈 Stats data: {stats_data}")
            
            return jsonify({
                'status': 'success',
                'data': stats_data
            })
        except Exception as e:
            print(f"❌ Stats error: {e}")
            return jsonify({'status': 'error', 'message': f'Błąd statystyk: {str(e)}'}), 500
    
    # ✅ DODATKOWE ENDPOINT DLA DEBUGOWANIA
    @app.route('/api/admin/debug')
    @admin_required  
    def admin_debug():
        """Debug endpoint dla administratorów"""
        try:
            debug_info = {
                'current_user': {
                    'username': current_user.username,
                    'user_id': current_user.user_id,
                    'is_admin': current_user.is_admin,
                    'is_authenticated': current_user.is_authenticated
                },
                'app_info': {
                    'flask_version': flask.__version__,
                    'python_version': sys.version.split()[0],
                    'db_engine': db.engine.name
                },
                'routes': [
                    '/admin_dashboard',
                    '/api/check_admin', 
                    '/api/admin/stats',
                    '/api/admin/debug',
                    '/flask_admin/',
                    '/flask_admin/diagnostics/',
                    '/flask_admin/webshell/'
                ]
            }
            
            return jsonify({
                'status': 'success',
                'debug': debug_info
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    @app.route('/check_session')
    def check_session():
        """Sprawdzenie sesji użytkownika - ENHANCED"""
        try:
            if current_user.is_authenticated:
                return jsonify({
                    'authenticated': True,
                    'user_id': current_user.user_id,
                    'username': current_user.username,
                    'is_admin': getattr(current_user, 'is_admin', False),
                    'session_valid': True
                })
            else:
                return jsonify({
                    'authenticated': False,
                    'session_valid': False
                })
        except Exception as e:
            print(f"❌ Session check error: {e}")
            return jsonify({
                'authenticated': False,
                'session_valid': False,
                'error': str(e)
            }), 500
    
    @app.route('/silent-logout', methods=['POST'])
    def silent_logout():
        """Ciche wylogowanie"""
        return jsonify({'status': 'success'})
    
    # === SECURITY HEADERS ===
    @app.after_request
    def add_security_headers(response):
        if request.path.startswith(('/api/', '/flask_admin/', '/admin_dashboard')):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response

    print("✅ Admin panel initialized with FIXED routes")
    return admin
