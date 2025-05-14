from flask import redirect, url_for, render_template, abort, request, jsonify
from flask_login import current_user, login_required
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import functools
from models import User, db

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

# Inicjalizacja panelu admina
def init_admin(app):
    admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', url='/flask_admin')
    admin.add_view(SecureModelView(User, db.session))
    
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
                    'is_admin': user.is_admin
                }
                for user in users
            ]
            return jsonify(user_list)
        except:
            return jsonify({'error': 'Nie można pobrać listy użytkowników'}), 500
    
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