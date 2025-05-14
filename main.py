from app import create_app, db
from models import User
from werkzeug.security import generate_password_hash
import os
import secrets
import time

app = create_app()



def initialize_database():
    """Inicjalizuje bazę danych i tworzy administratora"""
    print("=== INICJALIZACJA BAZY DANYCH ===")
      
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
