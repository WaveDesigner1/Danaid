# create_admin.py
import sys
import getpass
from app import create_app, db
from models import User, generate_unique_user_id
from werkzeug.security import generate_password_hash

# Tworzenie kontekstu aplikacji
app = create_app()

def create_admin():
    """Tworzy konto administratora lub nadaje uprawnienia administratora istniejącemu użytkownikowi."""
    
    print("\n=== TWORZENIE KONTA ADMINISTRATORA ===\n")
    
    # Tryb działania
    print("Wybierz tryb działania:")
    print("1. Utwórz nowe konto administratora")
    print("2. Nadaj uprawnienia administratora istniejącemu użytkownikowi")
    
    choice = input("\nWybór [1/2]: ")
    
    with app.app_context():
        if choice == "1":
            # Tworzenie nowego konta administratora
            username = input("\nNazwa użytkownika: ")
            if User.query.filter_by(username=username).first():
                print(f"\nBŁĄD: Użytkownik '{username}' już istnieje.")
                return
            
            # Pobranie i potwierdzenie hasła
            password = getpass.getpass("Hasło: ")
            confirm_password = getpass.getpass("Potwierdź hasło: ")
            
            if password != confirm_password:
                print("\nBŁĄD: Hasła nie są identyczne.")
                return
                
            # Generowanie kluczy (uproszczone - normalnie generuje frontend)
            print("\nNormally klucze są generowane przez frontend. Na potrzeby tego skryptu tworzymy pusty klucz.")
            public_key = "ADMINISTRATOR_KEY"  # Uproszczone
            
            # Utworzenie użytkownika
            try:
                new_admin = User(
                    username=username,
                    password_hash=generate_password_hash(password),
                    public_key=public_key,
                    is_admin=True,
                    user_id=generate_unique_user_id()
                )
                
                db.session.add(new_admin)
                db.session.commit()
                print(f"\nSUKCES: Utworzono konto administratora '{username}'.")
                
            except Exception as e:
                print(f"\nBŁĄD: Nie udało się utworzyć konta administratora: {str(e)}")
                
        elif choice == "2":
            # Nadanie uprawnień istniejącemu użytkownikowi
            username = input("\nNazwa istniejącego użytkownika: ")
            user = User.query.filter_by(username=username).first()
            
            if not user:
                print(f"\nBŁĄD: Użytkownik '{username}' nie istnieje.")
                return
                
            if user.is_admin:
                print(f"\nINFORMACJA: Użytkownik '{username}' już ma uprawnienia administratora.")
                return
                
            # Nadanie uprawnień
            try:
                user.is_admin = True
                db.session.commit()
                print(f"\nSUKCES: Nadano uprawnienia administratora użytkownikowi '{username}'.")
                
            except Exception as e:
                print(f"\nBŁĄD: Nie udało się nadać uprawnień: {str(e)}")
                
        else:
            print("\nBŁĄD: Niepoprawny wybór.")

if __name__ == "__main__":
    create_admin()