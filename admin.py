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

# Widok admina z zabezpieczeniami i poprawioną obsługą edycji
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.index', next=request.url))
    
    # Rozszerzenie funkcji na_model_change do poprawnej obsługi pola is_admin
    def on_model_change(self, form, model, is_created):
        # Dla użytkowników gwarantujemy poprawność wartości logicznej is_admin
        if isinstance(model, User):
            # Zapisz oryginalną wartość przed konwersją
            original_value = model.is_admin
            
            # Upewnij się, że is_admin jest wartością logiczną
            if model.is_admin not in (True, False):
                model.is_admin = bool(model.is_admin)
            
            print(f"SecureModelView.on_model_change: Użytkownik {model.username}, "
                  f"is_admin zmienione z {original_value} (typ: {type(original_value).__name__}) "
                  f"na {model.is_admin} (typ: {type(model.is_admin).__name__})")
            
        # Wywołaj oryginalną metodę bazową
        super(SecureModelView, self).on_model_change(form, model, is_created)

# Rozszerzona klasa dla modelu User
class UserModelView(SecureModelView):
    column_exclude_list = ['password_hash']  # Ukryj hasło
    form_excluded_columns = ['password_hash', 'sessions_initiated', 'sessions_received', 'messages']
    column_searchable_list = ['username', 'email']
    column_filters = ['is_admin', 'is_online']
    
    # Dodaj specjalne formatery dla pól logicznych
    column_formatters = {
        'is_admin': lambda v, c, m, p: 'Tak' if m.is_admin else 'Nie',
        'is_online': lambda v, c, m, p: 'Tak' if m.is_online else 'Nie',
    }
    
    # Dodaj obsługę wartości logicznych w formularzu
    form_choices = {
        'is_admin': [
            (True, 'Tak'),
            (False, 'Nie')
        ],
        'is_online': [
            (True, 'Tak'),
            (False, 'Nie')
        ]
    }
    
    # Dodaj specjalną obsługę dla edycji użytkownika
    def update_model(self, form, model):
        try:
            form.populate_obj(model)
            
            # Pobierz bezpośrednio wartości formularza
            is_admin_value = form.data.get('is_admin', model.is_admin)
            
            # Zapewnij poprawny typ
            model.is_admin = bool(is_admin_value)
            
            print(f"UserModelView.update_model: Użytkownik {model.username}, "
                  f"is_admin ustawione na {model.is_admin} (typ: {type(model.is_admin).__name__})")
            
            self.session.commit()
            return True
        except Exception as ex:
            if not self.handle_view_exception(ex):
                flash(f'Nie można zaktualizować rekordu: {str(ex)}', 'error')
                traceback.print_exc()
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
    
    # Dodaj jawnie endpoint dla każdego widoku modelu - korzystamy ze specjalnej klasy dla User
    admin.add_view(UserModelView(User, db.session, endpoint='user', name='Użytkownicy'))
    admin.add_view(SecureModelView(ChatSession, db.session, endpoint='chatsession', name='Sesje Czatu'))
    admin.add_view(SecureModelView(Message, db.session, endpoint='message', name='Wiadomości'))
    
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
            print(f"Błąd API /api/admin/stats: {str(e)}")
            traceback_str = traceback.format_exc()
            print(traceback_str)
            return jsonify({'status': 'error', 'message': f'Nie można pobrać statystyk: {str(e)}'}), 500
    
    # API do pobierania listy użytkowników
    @app.route('/api/users')
    @admin_required
    def get_users():
        try:
            # Dodaj więcej szczegółowego logowania
            print("Wywołanie API /api/users")
            
            users = User.query.all()
            user_list = []
            
            # Log liczby znalezionych użytkowników
            print(f"Znaleziono {len(users)} użytkowników")
            
            for user in users:
                # Bezpieczne pobieranie atrybutów z obsługą błędów i dokładnym logowaniem typów danych
                try:
                    # Pobierz wartości atrybutów
                    user_id_value = getattr(user, 'user_id', str(user.id))
                    is_admin_value = getattr(user, 'is_admin', False)
                    is_online_value = getattr(user, 'is_online', False)
                    
                    # Loguj oryginalne wartości i ich typy
                    print(f"Użytkownik {user.id} ({user.username}):")
                    print(f"  - user_id: {user_id_value} (typ: {type(user_id_value).__name__})")
                    print(f"  - is_admin: {is_admin_value} (typ: {type(is_admin_value).__name__})")
                    print(f"  - is_online: {is_online_value} (typ: {type(is_online_value).__name__})")
                    
                    # Upewnij się, że wartości są odpowiednio skonwertowane
                    user_data = {
                        'id': user.id,
                        'username': user.username,
                        'user_id': str(user_id_value),
                        'is_admin': bool(is_admin_value),  # Wyraźna konwersja na boolean
                        'is_online': bool(is_online_value)  # Wyraźna konwersja na boolean
                    }
                    
                    # Loguj przetworzone wartości
                    print(f"Przetworzone dane użytkownika: {user_data}")
                    
                    user_list.append(user_data)
                except Exception as user_error:
                    # Log błędu dla pojedynczego użytkownika nie powinien przerwać całej operacji
                    print(f"Błąd podczas przetwarzania użytkownika {user.id}: {str(user_error)}")
                    print(traceback.format_exc())
            
            # Loguj format odpowiedzi przed wysłaniem
            response_data = {
                'status': 'success',
                'users': user_list
            }
            print(f"Wysyłanie odpowiedzi API /api/users: {response_data}")
            
            # Zwróć dane w spójnym formacie: {"status": "success", "users": [...]}
            return jsonify(response_data)
        except Exception as e:
            error_message = f"Błąd API /api/users: {str(e)}"
            print(error_message)
            traceback_str = traceback.format_exc()
            print(traceback_str)
            return jsonify({'status': 'error', 'message': f'Nie można pobrać listy użytkowników: {str(e)}'}), 500
    
    # API do zmiany uprawnień administratora
    @app.route('/api/users/<string:user_id>/toggle_admin', methods=['POST'])
    @admin_required
    def toggle_admin(user_id):
        try:
            print(f"Wywołanie toggle_admin dla użytkownika {user_id}")
            
            # Znajdź użytkownika po user_id
            user = User.query.filter_by(user_id=user_id).first()
            
            # Jeśli nie znaleziono, spróbuj po id (dla kompatybilności)
            if not user and user_id.isdigit():
                user = User.query.get(int(user_id))
            
            # Jeśli nadal nie znaleziono, zwróć błąd
            if not user:
                print(f"Użytkownik {user_id} nie istnieje")
                return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
            # Nie możemy usunąć uprawnień zalogowanemu administratorowi
            if user.user_id == current_user.user_id:
                print(f"Próba zmiany własnych uprawnień przez {current_user.username}")
                return jsonify({'status': 'error', 'message': 'Nie możesz zmienić własnych uprawnień'}), 400
            
            # Pobierz aktualny stan z bazy danych
            current_admin_state = bool(user.is_admin)
            print(f"Aktualny stan uprawnień dla {user.username}: {current_admin_state} (typ: {type(user.is_admin).__name__})")
            
            # Zmiana stanu uprawnień - używaj wyraźnych wartości True/False
            new_admin_state = not current_admin_state
            user.is_admin = True if new_admin_state else False  # Wyraźna konwersja na boolean
            
            print(f"Nowy stan uprawnień dla {user.username}: {user.is_admin} (typ: {type(user.is_admin).__name__})")
            
            # Zapisanie zmian w bazie danych
            db.session.commit()
            
            # Sprawdź, czy zmiany zostały faktycznie zapisane
            db.session.refresh(user)
            verified_state = bool(user.is_admin)
            print(f"Zweryfikowany stan uprawnień po zapisie: {verified_state} (typ: {type(user.is_admin).__name__})")
            
            # Upewnij się, że stan po zapisie jest zgodny z oczekiwanym
            if verified_state != new_admin_state:
                print(f"BŁĄD: Stan po zapisie ({verified_state}) nie zgadza się z oczekiwanym ({new_admin_state})")
                db.session.rollback()
                return jsonify({
                    'status': 'error', 
                    'message': 'Błąd integralności danych: zmiany nie zostały poprawnie zapisane'
                }), 500
            
            return jsonify({
                'status': 'success',
                'message': f'Uprawnienia użytkownika {user.username} zostały {"nadane" if user.is_admin else "odebrane"}',
                'is_admin': verified_state
            })
        except Exception as e:
            db.session.rollback()
            error_message = f"Błąd podczas zmiany uprawnień: {str(e)}"
            print(error_message)
            traceback_str = traceback.format_exc()
            print(traceback_str)
            return jsonify({'status': 'error', 'message': error_message}), 500
    
    # API do naprawy upawnień użytkownika
    @app.route('/api/users/fix_admin/<string:user_id>', methods=['POST'])
    @admin_required
    def fix_admin(user_id):
        """
        Endpoint do naprawy uprawnień administratora (jednokrotne użycie w razie problemu)
        """
        try:
            print(f"Próba przywrócenia uprawnień administratora dla użytkownika {user_id}")
            
            # Znajdź użytkownika po user_id
            user = User.query.filter_by(user_id=user_id).first()
            
            # Jeśli nie znaleziono, spróbuj po id (dla kompatybilności)
            if not user and user_id.isdigit():
                user = User.query.get(int(user_id))
            
            # Jeśli nadal nie znaleziono, zwróć błąd
            if not user:
                return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
            # Pobierz aktualny stan
            current_state = bool(user.is_admin)
            
            # Ustaw uprawnienia administratora na True (wyraźnie)
            user.is_admin = True
            
            # Log zmiany (bardzo szczegółowy)
            print(f"Zmiana uprawnień użytkownika {user.username} (ID: {user_id}):")
            print(f"  - Przed: {current_state} (typ: {type(current_state).__name__})")
            print(f"  - Po: {bool(user.is_admin)} (typ: {type(user.is_admin).__name__})")
            
            # Zapisanie zmian w bazie danych
            db.session.commit()
            print(f"Uprawnienia administratora przywrócone dla użytkownika {user.username}")
            
            return jsonify({
                'status': 'success',
                'message': f'Uprawnienia administratora przywrócone dla użytkownika {user.username}',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'user_id': str(getattr(user, 'user_id', str(user.id))),
                    'is_admin': bool(user.is_admin)
                }
            })
        except Exception as e:
            db.session.rollback()
            error_message = f"Błąd podczas naprawy uprawnień: {str(e)}"
            print(error_message)
            traceback_str = traceback.format_exc()
            print(traceback_str)
            return jsonify({'status': 'error', 'message': error_message}), 500
    
    # Endpoint do bezpośredniego przyznania uprawnień administratora użytkownikowi (dla łatwiejszej obsługi)
    @app.route('/admin/repair_permissions/<int:user_id>')
    @admin_required
    def repair_permissions(user_id):
        try:
            # Znajdź użytkownika po id
            user = User.query.get(user_id)
            
            if not user:
                flash('Użytkownik nie istnieje', 'error')
                return redirect(url_for('admin.index'))
            
            # Ustaw uprawnienia administratora
            user.is_admin = True
            
            # Zapisz zmiany
            db.session.commit()
            
            flash(f'Uprawnienia administratora dla użytkownika {user.username} zostały naprawione!', 'success')
            return redirect(url_for('user.index_view'))
        except Exception as e:
            db.session.rollback()
            flash(f'Błąd podczas naprawy uprawnień: {str(e)}', 'error')
            return redirect(url_for('admin.index'))
    
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
        if request.path.startswith('/api/') or request.path.startswith('/flask_admin/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response
