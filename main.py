from app import create_app, db
import os
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
            # Utwórz tabele na podstawie modeli
            db.create_all()
            print("Tabele zostały utworzone")
            
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

if __name__ == '__main__':
    # Inicjalizacja bazy danych przy starcie
    time.sleep(2)  # Krótkie opóźnienie, aby upewnić się, że wszystkie komponenty są gotowe
    initialize_database()
    
    # Uruchomienie aplikacji
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
