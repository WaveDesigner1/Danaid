from app import create_app, db
from models import User
from werkzeug.security import generate_password_hash
import os
import secrets
import sqlite3
import time

app = create_app()

def initialize_database():
    """Inicjalizuje bazę danych - tworzy tabele i podstawowe dane"""
    print("=== INICJALIZACJA BAZY DANYCH ===")
    
    # Sprawdź, czy plik blokujący istnieje
    init_lock_file = 'db_initialized.lock'
    
    if os.path.exists(init_lock_file) and not os.environ.get('FORCE_DB_INIT', '').lower() == 'true':
        print("Baza danych została już zainicjalizowana. Pomijam inicjalizację.")
        print("Aby wymusić inicjalizację, ustaw zmienną środowiskową FORCE_DB_INIT=true")
        return
    
    try:
        with app.app_context():
            # 1. Upewnij się, że tabele podstawowe istnieją
            db.create_all()
            
            # 2. Sprawdź, czy tabela chat_session istnieje, jeśli nie, utwórz ją
            try:
                # Sprawdź czy tabela istnieje
                db.session.execute(text("SELECT 1 FROM chat_session LIMIT 1"))
                print("Tabela chat_session już istnieje")
            except:
                print("Tworzenie tabeli chat_session...")
                db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS chat_session (
                    id INTEGER PRIMARY KEY,
                    initiator_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    session_token VARCHAR(100) NOT NULL UNIQUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (initiator_id) REFERENCES user (id),
                    FOREIGN KEY (recipient_id) REFERENCES user (id)
                );
                """))
                db.session.commit()
            
            # 3. Sprawdź, czy tabela message istnieje, jeśli nie, utwórz ją
            try:
                db.session.execute(text("SELECT 1 FROM message LIMIT 1"))
                print("Tabela message już istnieje")
            except:
                print("Tworzenie tabeli message...")
                db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS message (
                    id INTEGER PRIMARY KEY,
                    session_id INTEGER NOT NULL,
                    sender_id INTEGER NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_delivered BOOLEAN DEFAULT 0,
                    FOREIGN KEY (session_id) REFERENCES chat_session (id),
                    FOREIGN KEY (sender_id) REFERENCES user (id)
                );
                """))
                db.session.commit()
            
            # 4. Dodaj indeksy dla wydajności
            try:
                print("Tworzenie indeksów...")
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_session_token ON chat_session(session_token);"))
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_session_users ON chat_session(initiator_id, recipient_id);"))
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_message_session ON message(session_id);"))
                db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_message_sender ON message(sender_id);"))
                db.session.commit()
            except Exception as e:
                print(f"Błąd podczas tworzenia indeksów: {e}")
                db.session.rollback()
            
            # 5. Upewnij się, że istnieje konto administratora
            create_admin_if_not_exists()
            
            print("=== INICJALIZACJA BAZY DANYCH ZAKOŃCZONA ===")
            
            # Utwórz plik blokujący po udanej inicjalizacji
            try:
                with open(init_lock_file, 'w') as f:
                    f.write(f"Initialized at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Utworzono plik blokujący {init_lock_file}")
            except Exception as e:
                print(f"Nie można utworzyć pliku blokującego: {e}")
                
    except Exception as e:
        print(f"!!! BŁĄD PODCZAS INICJALIZACJI BAZY DANYCH: {e}")
def create_admin_if_not_exists():
    """Tworzy konto administratora, jeśli nie istnieje"""
    try:
        # Sprawdź, czy istnieje już administrator
        admin = User.query.filter_by(username='admin').first()
        
        if admin:
            # Jeśli istnieje, upewnij się że ma uprawnienia administratora
            if not admin.is_admin:
                print("Nadawanie uprawnień administratora istniejącemu użytkownikowi 'admin'...")
                admin.is_admin = True
                db.session.commit()
            else:
                print("Użytkownik 'admin' już istnieje i ma uprawnienia administratora")
            return
        
        # Domyślne dane administratora
        username = 'admin'
        password = 'Admin123!'  # Domyślne hasło - zmień po zalogowaniu!
        user_id = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # Tworzenie administratora
        print(f"Tworzenie konta administratora '{username}'...")
        new_admin = User(
            username=username,
            password_hash=generate_password_hash(password),
            public_key="ADMIN_KEY",  # Placeholder dla klucza publicznego
            is_admin=True,
            user_id=user_id
        )
        
        db.session.add(new_admin)
        db.session.commit()
        
        print("=== UTWORZONO KONTO ADMINISTRATORA ===")
        print(f"Nazwa użytkownika: {username}")
        print(f"Hasło: {password}")
        print(f"ID użytkownika: {user_id}")
        print("ZAPISZ TE DANE! NIE BĘDĄ DOSTĘPNE PÓŹNIEJ!")
    
    except Exception as e:
        db.session.rollback()
        print(f"!!! BŁĄD PODCZAS TWORZENIA KONTA ADMINISTRATORA: {e}")

if __name__ == '__main__':
    # Inicjalizacja bazy danych przy starcie
    time.sleep(2)  # Krótkie opóźnienie, aby upewnić się, że wszystkie komponenty są gotowe
    initialize_database()
    
    # Uruchomienie aplikacji
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
