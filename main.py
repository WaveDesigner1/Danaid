from app import create_app, db
from models import User
from werkzeug.security import generate_password_hash
import os
import secrets
import time

app = create_app()

def clear_old_databases():
    """Usuwa stare pliki baz danych"""
    try:
        import os
        app_dir = os.path.abspath(os.path.dirname(__file__))
        instance_dir = os.path.join(app_dir, 'instance')
        
        if os.path.exists(instance_dir):
            # Usuń stare pliki baz danych w katalogu instance
            for file in os.listdir(instance_dir):
                if file.endswith('.db') and file != 'new_database.db':  # Zachowaj tylko nową bazę
                    try:
                        os.remove(os.path.join(instance_dir, file))
                        print(f"Usunięto stary plik bazy danych: {file}")
                    except Exception as e:
                        print(f"Nie można usunąć pliku {file}: {e}")
        
        # Usuń pliki baz danych w katalogu głównym
        for file in os.listdir(app_dir):
            if file.endswith('.db'):
                try:
                    os.remove(os.path.join(app_dir, file))
                    print(f"Usunięto plik bazy danych z katalogu głównego: {file}")
                except Exception as e:
                    print(f"Nie można usunąć pliku {file}: {e}")
                    
    except Exception as e:
        print(f"Błąd podczas usuwania starych baz danych: {e}")

def initialize_database():
    """Inicjalizuje bazę danych i tworzy administratora"""
    print("=== INICJALIZACJA BAZY DANYCH ===")
    
    # Najpierw usuń stare bazy danych
    clear_old_databases()
    
    try:
        with app.app_context():
            # Utwórz tabele na podstawie modeli
            db.create_all()
            print("Tabele zostały utworzone")
            
            # Sprawdź, czy istnieje już użytkownik z uprawnieniami administratora
            admin = User.query.filter_by(is_admin=True).first()
            if admin:
                print(f"Administrator już istnieje: {admin.username} (ID: {admin.id})")
            else:
                # Tworzenie konta administratora
                username = 'admin'
                password = 'Admin123!'  # Domyślne hasło - zmień po zalogowaniu!
                admin_id = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
                
                # Klucz publiczny placeholder - będzie można zaktualizować po zalogowaniu
                public_key = "TEMPORARY_ADMIN_KEY"
                
                # Tworzenie użytkownika
                new_admin = User(
                    username=username,
                    password_hash=generate_password_hash(password),
                    public_key=public_key,
                    is_admin=True,
                    user_id=admin_id
                )
                
                db.session.add(new_admin)
                db.session.commit()
                
                print("=== UTWORZONO KONTO ADMINISTRATORA ===")
                print(f"Nazwa użytkownika: {username}")
                print(f"Hasło: {password}")
                print(f"ID użytkownika: {admin_id}")
                print("ZAPISZ TE DANE! NIE BĘDĄ DOSTĘPNE PÓŹNIEJ!")
            
            print("=== INICJALIZACJA BAZY DANYCH ZAKOŃCZONA ===")
                
    except Exception as e:
        print(f"!!! BŁĄD PODCZAS INICJALIZACJI BAZY DANYCH: {e}")

if __name__ == '__main__':
    # Inicjalizacja bazy danych przy starcie
    initialize_database()
    
    # Uruchomienie aplikacji
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
