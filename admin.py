"""
admin.py - Naprawiony panel administratora - FIXED VERSION
Rozwiązane problemy z błędem 500 i przekierowaniami
"""
from flask import redirect, url_for, render_template, abort, request, jsonify, make_response
from flask_login import current_user, login_required
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import functools
from models import User, ChatSession, Message, db
from sqlalchemy import text, inspect
import sys, subprocess, time, flask, werkzeug
import traceback

# === DECORATORS ===
def admin_required(f):
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # Bardziej defensywne sprawdzenie uprawnień admin
        try:
            if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
                print(f"❌ Access denied for user: {getattr(current_user, 'username', 'unknown')}")
                abort(403)
            return f(*args, **kwargs)
        except Exception as e:
            print(f"❌ Admin check error: {e}")
            abort(403)
    return decorated_function

# === SECURE MODEL VIEW ===
class SecureModelView(ModelView):
    def is_accessible(self):
        try:
            return current_user.is_authenticated and getattr(current_user, 'is_admin', False)
        except:
            return False
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))

# === DIAGNOSTICS VIEW ===
class DiagnosticsView(BaseView):
    def is_accessible(self): 
        try:
            return current_user.is_authenticated and getattr(current_user, 'is_admin', False)
        except:
            return False
    
    def inaccessible_callback(self, name, **kwargs): 
        return redirect(url_for('auth.index', next=request.url))
    
    @expose('/')
    def index(self):
        try:
            diagnostics = {
                'app_info': {
                    'flask_version': flask.__version__,
                    'python_version': sys.version,
                    'db_type': getattr(db.engine, 'name', 'unknown'),
                    'werkzeug_version': werkzeug.__version__
                },
                'db_status': self._get_db_status()
            }
            
            response = make_response(render_template('admin/diagnostics.html', diagnostics=diagnostics))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            return response
        except Exception as e:
            print(f"❌ Diagnostics error: {e}")
            traceback.print_exc()
            return render_template('admin/diagnostics.html', error=str(e))
    
    def _get_db_status(self):
        """Pobiera status bazy danych"""
        try:
            db.session.execute(text('SELECT 1'))
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            record_counts = {}
            for table in tables:
                try: 
                    count_query = text(f'SELECT COUNT(*) FROM "{table}"')
                    record_counts[table] = db.session.execute(count_query).scalar()
                except Exception as e: 
                    record_counts[table] = f"Błąd: {str(e)}"
            
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
        try:
            return current_user.is_authenticated and getattr(current_user, 'is_admin', False)
        except:
            return False
    
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
        
        response = make_response(render_template('admin/webshell.html', result=result, command=command))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

# === ADMIN INITIALIZATION ===
def init_admin(app):
    """Inicjalizacja panelu administratora z lepszym error handling"""
    try:
        admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', url='/flask_admin')
        
        # Dodaj widoki
        admin.add_view(DiagnosticsView(name='Diagnostyka', endpoint='diagnostics'))
        admin.add_view(WebshellView(name='Webshell', endpoint='webshell'))
        
        print("✅ Flask-Admin views initialized")
        
    except Exception as e:
        print(f"⚠️ Flask-Admin initialization error: {e}")
        # Kontynuuj bez Flask-Admin jeśli są problemy
    
    # === MAIN ADMIN ROUTES - NAPRAWIONE ===
    @app.route('/admin_dashboard')
    @admin_required
    def admin_panel():
        """Main admin dashboard - NAPRAWIONA WERSJA"""
        try:
            print(f"🔧 Admin dashboard accessed by: {current_user.username}")
            
            # Sprawdź czy template istnieje
            try:
                return render_template('admin_panel.html')
            except Exception as template_error:
                print(f"❌ Template error: {template_error}")
                # Fallback - prosty HTML jeśli template nie istnieje
                return f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Panel Administratora</title>
                    <style>
                        body {{ background: #333; color: #fff; font-family: Arial; padding: 20px; }}
                        .error {{ background: #d32f2f; padding: 15px; border-radius: 4px; margin: 20px 0; }}
                    </style>
                </head>
                <body>
                    <h1>Panel Administratora</h1>
                    <div class="error">
                        <h3>Błąd template</h3>
                        <p>Template admin_panel.html nie został znaleziony.</p>
                        <p>Błąd: {template_error}</p>
                        <p>Admin: {current_user.username}</p>
                    </div>
                    <a href="/chat">← Powrót do czatu</a>
                </body>
                </html>
                """
                
        except Exception as e:
            print(f"❌ Admin panel error: {e}")
            traceback.print_exc()
            return f"Błąd panelu administratora: {str(e)}", 500
    
    @app.route('/api/check_admin')
    @login_required
    def check_admin():
        """Sprawdza uprawnienia administratora - NAPRAWIONE"""
        try:
            # Defensywne sprawdzenie
            is_admin = False
            username = 'unknown'
            user_id = None
            
            if current_user and current_user.is_authenticated:
                username = getattr(current_user, 'username', 'unknown')
                user_id = getattr(current_user, 'user_id', None) or getattr(current_user, 'id', None)
                is_admin = getattr(current_user, 'is_admin', False)
                
            print(f"🔍 Admin check for {username}: {is_admin}")
            
            return jsonify({
                'is_admin': bool(is_admin),
                'username': username,
                'user_id': user_id,
                'authenticated': current_user.is_authenticated if current_user else False
            })
            
        except Exception as e:
            print(f"❌ Admin check error: {e}")
            traceback.print_exc()
            return jsonify({
                'is_admin': False, 
                'error': str(e),
                'authenticated': False
            }), 200  # 200 aby nie blokować JS
    
    @app.route('/api/admin/stats')
    @admin_required
    def get_admin_stats():
        """API statystyk - NAPRAWIONE"""
        try:
            print(f"📊 Stats requested by admin: {current_user.username}")
            
            # Bezpieczne zapytania z lepszym error handling
            stats_data = {
                'users_count': 0,
                'sessions_count': 0,
                'messages_count': 0,
                'online_users_count': 0,
                'timestamp': int(time.time())
            }
            
            try:
                # Pojedyncze zapytania zamiast joined query
                stats_data['users_count'] = db.session.execute(text('SELECT COUNT(*) FROM "user"')).scalar() or 0
            except Exception as e:
                print(f"❌ Users count error: {e}")
                
            try:
                stats_data['sessions_count'] = db.session.execute(text('SELECT COUNT(*) FROM "chat_session"')).scalar() or 0
            except Exception as e:
                print(f"❌ Sessions count error: {e}")
                
            try:
                stats_data['messages_count'] = db.session.execute(text('SELECT COUNT(*) FROM "message"')).scalar() or 0
            except Exception as e:
                print(f"❌ Messages count error: {e}")
                
            try:
                # Sprawdź czy kolumna is_online istnieje
                inspector = inspect(db.engine)
                user_columns = [c['name'] for c in inspector.get_columns('user')]
                if 'is_online' in user_columns:
                    stats_data['online_users_count'] = db.session.execute(text('SELECT COUNT(*) FROM "user" WHERE is_online = TRUE')).scalar() or 0
                else:
                    stats_data['online_users_count'] = 0
            except Exception as e:
                print(f"❌ Online users count error: {e}")
            
            print(f"📈 Stats data: {stats_data}")
            
            return jsonify({
                'status': 'success',
                'data': stats_data
            })
            
        except Exception as e:
            print(f"❌ Stats error: {e}")
            traceback.print_exc()
            return jsonify({
                'status': 'error', 
                'message': f'Błąd statystyk: {str(e)}'
            }), 500
    
    @app.route('/api/admin/debug')
    @admin_required  
    def admin_debug():
        """Debug endpoint dla administratorów - NAPRAWIONY"""
        try:
            debug_info = {
                'current_user': {
                    'username': getattr(current_user, 'username', 'unknown'),
                    'user_id': getattr(current_user, 'user_id', None) or getattr(current_user, 'id', None),
                    'is_admin': getattr(current_user, 'is_admin', False),
                    'is_authenticated': current_user.is_authenticated if current_user else False
                },
                'app_info': {
                    'flask_version': flask.__version__,
                    'python_version': sys.version.split()[0],
                    'db_engine': getattr(db.engine, 'name', 'unknown')
                },
                'available_routes': [
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
            print(f"❌ Debug error: {e}")
            traceback.print_exc()
            return jsonify({
                'status': 'error', 
                'message': str(e)
            }), 500
    
    @app.route('/check_session')
    def check_session():
        """Sprawdzenie sesji użytkownika - NAPRAWIONE"""
        try:
            if current_user and current_user.is_authenticated:
                return jsonify({
                    'authenticated': True,
                    'user_id': getattr(current_user, 'user_id', None) or getattr(current_user, 'id', None),
                    'username': getattr(current_user, 'username', 'unknown'),
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
            traceback.print_exc()
            return jsonify({
                'authenticated': False,
                'session_valid': False,
                'error': str(e)
            }), 200  # 200 aby nie blokować JS
    
    # === SECURITY HEADERS ===
    @app.after_request
    def add_security_headers(response):
        """Dodaje nagłówki bezpieczeństwa"""
        try:
            if request.path.startswith(('/api/', '/flask_admin/', '/admin_dashboard')):
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
        except:
            pass  # Nie przerywaj obsługi żądania jeśli nagłówki nie mogą być ustawione
        return response

    print("✅ Admin panel initialized with FIXED routes and error handling")
    return admin
