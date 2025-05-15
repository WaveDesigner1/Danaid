from flask import redirect, url_for, render_template, abort, request, jsonify, flash
from flask_login import current_user, login_required
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import functools
from models import User, db
from sqlalchemy import text, inspect

# Funkcje pomocnicze do określania typu bazy danych
def is_sqlite():
    """Sprawdza, czy używamy bazy SQLite"""
    return db.engine.name == 'sqlite'

def is_postgresql():
    """Sprawdza, czy używamy bazy PostgreSQL"""
    return db.engine.name == 'postgresql'

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
            for table in tables:
                columns = inspector.get_columns(table)
                table_structure[table] = columns
            
            return self.render('admin/database.html', tables=tables, structure=table_structure)
        except Exception as e:
            return self.render('admin/database.html', error=str(e))
    
    @expose('/add_column', methods=['POST'])
    def add_column(self):
        try:
            table = request.form.get('table')
            column_name = request.form.get('column_
    
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
            if is_sqlite():
                columns = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
                column_names = [col[1] for col in columns]
            elif is_postgresql():
                inspector = inspect(db.engine)
                columns = inspector.get_columns(table)
                column_names = [col['name'] for col in columns]
            
            if column_name in column_names:
                flash(f'Kolumna {column_name} już istnieje w tabeli {table}', 'error')
                return redirect(url_for('.index'))
            
            # Dodaj kolumnę
            if default_value:
                query = f"ALTER TABLE {table} ADD COLUMN {column_name} {column_type} DEFAULT {default_value}"
            else:
                query = f"ALTER TABLE {table} ADD COLUMN {column_name} {column_type}"
            
            db.session.execute(text(query))
            db.session.commit()
            
            flash(f'Kolumna {column_name} została dodana do tabeli {table}', 'success')
            return redirect(url_for('.index'))
        except Exception as e:
            flash(f'Błąd: {str(e)}', 'error')
            return redirect(url_for('.index'))

# Inicjalizacja panelu admina
def init_admin(app):
    admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', url='/flask_admin')
    admin.add_view(SecureModelView(User, db.session))
    admin.add_view(DatabaseView(name='Zarządzanie bazą danych', endpoint='db_admin'))
    
    # Panel administracyjny
    @app.route('/admin_dashboard')
    @admin_required
    def admin_panel():
        return render_template('admin_panel.html')
    
    # API do pobierania listy użytkowników
    @app.route('/api/users')
    @admin_required
    def get_users():
        try:
            users = User.query.all()
            user_list = [
                {
                    'id': user.id,
                    'username': user.username,
                    'user_id': user.user_id,
                    'is_admin': user.is_admin,
                    'is_online': getattr(user, 'is_online', False)
                }
                for user in users
            ]
            return jsonify(user_list)
        except Exception as e:
            return jsonify({'error': f'Nie można pobrać listy użytkowników: {str(e)}'}), 500
    
    # API do zmiany uprawnień administratora
    @app.route('/api/users/<int:user_id>/toggle_admin', methods=['POST'])
    @admin_required
    def toggle_admin(user_id):
        # Nie możemy usunąć uprawnień zalogowanemu administratorowi
        if int(user_id) == current_user.id:
            return jsonify({'status': 'error', 'message': 'Nie możesz zmienić własnych uprawnień'}), 400
            
        user = User.query.get(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
        # Zmiana stanu uprawnień
        user.is_admin = not user.is_admin
        
        # Zapisanie zmian w bazie danych
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Uprawnienia użytkownika {user.username} zostały {"nadane" if user.is_admin else "odebrane"}',
            'is_admin': user.is_admin
        })
