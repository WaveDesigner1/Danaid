"""
validate_migration.py - Skrypt walidacji po migracji
Sprawdza czy wszystkie komponenty działają poprawnie
"""

import os
import sys
from datetime import datetime
from flask import Flask
from sqlalchemy import text, inspect
import traceback

def create_validation_app():
    """Tworzy aplikację Flask tylko do walidacji"""
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'validation-key'
    
    # Import models
    from models import db, User, ChatSession, Message, Friend, FriendRequest
    db.init_app(app)
    
    return app, db

def validate_database_structure(db):
    """Sprawdza strukturę bazy danych"""
    print("🔍 SPRAWDZANIE STRUKTURY BAZY DANYCH...")
    
    try:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        results = {
            'tables_exist': {},
            'columns_exist': {},
            'issues': []
        }
        
        # === SPRAWDŹ TABELE ===
        expected_tables = ['user', 'chat_session', 'message', 'friend', 'friend_request']
        
        for table in expected_tables:
            exists = table in tables
            results['tables_exist'][table] = exists
            if exists:
                print(f"  ✅ Tabela '{table}' istnieje")
            else:
                print(f"  ❌ Tabela '{table}' BRAKUJE")
                results['issues'].append(f"Missing table: {table}")
        
        # === SPRAWDŹ KOLUMNY ===
        table_columns = {
            'user': ['id', 'username', 'password_hash', 'public_key', 'user_id', 'is_admin', 'is_online', 'last_active'],
            'chat_session': ['id', 'session_token', 'initiator_id', 'recipient_id', 'created_at', 'last_activity', 
                           'expires_at', 'is_active', 'encrypted_keys_json', 'key_generator_id', 'key_acknowledged', 'encrypted_session_key'],
            'message': ['id', 'session_id', 'sender_id', 'content', 'iv', 'timestamp', 'read', 'is_encrypted'],
            'friend': ['id', 'user_id', 'friend_id', 'created_at'],
            'friend_request': ['id', 'from_user_id', 'to_user_id', 'status', 'created_at', 'updated_at']
        }
        
        for table, expected_columns in table_columns.items():
            if table in tables:
                actual_columns = [c['name'] for c in inspector.get_columns(table)]
                results['columns_exist'][table] = {}
                
                for column in expected_columns:
                    exists = column in actual_columns
                    results['columns_exist'][table][column] = exists
                    if exists:
                        print(f"    ✅ {table}.{column}")
                    else:
                        print(f"    ❌ {table}.{column} BRAKUJE")
                        results['issues'].append(f"Missing column: {table}.{column}")
        
        return results
        
    except Exception as e:
        print(f"❌ Błąd sprawdzania struktury: {e}")
        return {'error': str(e)}

def validate_models_import():
    """Sprawdza czy modele można zaimportować"""
    print("\n🔍 SPRAWDZANIE IMPORTÓW MODELI...")
    
    try:
        from models import User, ChatSession, Message, Friend, FriendRequest
        print("  ✅ Import models.py - OK")
        
        # Sprawdź czy modele mają wymagane atrybuty
        user_attrs = ['username', 'password_hash', 'public_key', 'user_id', 'is_online', 'get_friends']
        for attr in user_attrs:
            if hasattr(User, attr):
                print(f"    ✅ User.{attr}")
            else:
                print(f"    ❌ User.{attr} BRAKUJE")
        
        session_attrs = ['session_token', 'encrypted_keys_json', 'get_encrypted_key_for_user', 'set_encrypted_keys', 'clear_keys']
        for attr in session_attrs:
            if hasattr(ChatSession, attr):
                print(f"    ✅ ChatSession.{attr}")
            else:
                print(f"    ❌ ChatSession.{attr} BRAKUJE")
                
        return True
        
    except Exception as e:
        print(f"  ❌ Błąd importu: {e}")
        traceback.print_exc()
        return False

def validate_auth_endpoints():
    """Sprawdza czy auth endpoints można zaimportować"""
    print("\n🔍 SPRAWDZANIE AUTH ENDPOINTS...")
    
    try:
        from auth import auth_bp
        print("  ✅ Import auth.py - OK")
        
        # Sprawdź czy blueprint ma wymagane routes
        routes = [rule.rule for rule in auth_bp.url_map.iter_rules()]
        expected_routes = ['/api/register', '/api/login', '/api/logout', '/api/check_auth']
        
        for route in expected_routes:
            if any(route in r for r in routes):
                print(f"    ✅ Route {route}")
            else:
                print(f"    ❌ Route {route} BRAKUJE")
                
        return True
        
    except Exception as e:
        print(f"  ❌ Błąd importu auth: {e}")
        traceback.print_exc()
        return False

def validate_chat_endpoints():
    """Sprawdza czy chat endpoints można zaimportować"""
    print("\n🔍 SPRAWDZANIE CHAT ENDPOINTS...")
    
    try:
        from chat import chat_bp
        print("  ✅ Import chat.py - OK")
        
        # Sprawdź czy blueprint ma wymagane routes
        routes = [rule.rule for rule in chat_bp.url_map.iter_rules()]
        expected_routes = ['/api/session/init', '/api/message/send', '/api/messages', '/api/friends']
        
        for route in expected_routes:
            if any(route in r for r in routes):
                print(f"    ✅ Route {route}")
            else:
                print(f"    ❌ Route {route} BRAKUJE")
                
        return True
        
    except Exception as e:
        print(f"  ❌ Błąd importu chat: {e}")
        traceback.print_exc()
        return False

def test_database_operations(app, db):
    """Testuje podstawowe operacje na bazie danych"""
    print("\n🔍 TESTOWANIE OPERACJI BAZODANOWYCH...")
    
    with app.app_context():
        try:
            from models import User, ChatSession, Message, Friend, FriendRequest
            
            # Test 1: Podstawowe zapytanie
            result = db.session.execute(text("SELECT 1 as test")).fetchone()
            if result and result[0] == 1:
                print("  ✅ Podstawowe zapytanie SQL")
            else:
                print("  ❌ Podstawowe zapytanie SQL FAILED")
                return False
            
            # Test 2: Count users
            user_count = User.query.count()
            print(f"  ✅ Liczba użytkowników: {user_count}")
            
            # Test 3: Count sessions  
            session_count = ChatSession.query.count()
            print(f"  ✅ Liczba sesji: {session_count}")
            
            # Test 4: Count messages
            message_count = Message.query.count()
            print(f"  ✅ Liczba wiadomości: {message_count}")
            
            # Test 5: Test nowych tabel
            friend_count = Friend.query.count()
            print(f"  ✅ Liczba znajomych: {friend_count}")
            
            request_count = FriendRequest.query.count()
            print(f"  ✅ Liczba zaproszeń: {request_count}")
            
            # Test 6: Test nowych metod
            if user_count > 0:
                test_user = User.query.first()
                friends = test_user.get_friends()
                print(f"  ✅ Test get_friends(): {len(friends)} znajomych")
            
            if session_count > 0:
                test_session = ChatSession.query.first()
                has_key = test_session.has_key_for_user(1)  # Test user ID 1
                print(f"  ✅ Test has_key_for_user(): {has_key}")
            
            return True
            
        except Exception as e:
            print(f"  ❌ Błąd operacji bazodanowych: {e}")
            traceback.print_exc()
            return False

def generate_migration_report(results):
    """Generuje raport z migracji"""
    print("\n📊 RAPORT MIGRACJI")
    print("=" * 50)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Data: {timestamp}")
    
    if 'error' in results:
        print(f"❌ KRYTYCZNY BŁĄD: {results['error']}")
        return
    
    # Podsumowanie tabel
    tables = results.get('tables_exist', {})
    tables_ok = sum(1 for exists in tables.values() if exists)
    tables_total = len(tables)
    print(f"\n📋 TABELE: {tables_ok}/{tables_total}")
    
    for table, exists in tables.items():
        status = "✅" if exists else "❌"
        print(f"  {status} {table}")
    
    # Podsumowanie kolumn
    columns = results.get('columns_exist', {})
    columns_ok = 0
    columns_total = 0
    
    for table, table_columns in columns.items():
        for column, exists in table_columns.items():
            columns_total += 1
            if exists:
                columns_ok += 1
    
    print(f"\n📝 KOLUMNY: {columns_ok}/{columns_total}")
    
    # Issues
    issues = results.get('issues', [])
    if issues:
        print(f"\n⚠️  PROBLEMY ({len(issues)}):")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print(f"\n✅ BRAK PROBLEMÓW")
    
    # Ogólny status
    if tables_ok == tables_total and columns_ok == columns_total and not issues:
        print(f"\n🎉 MIGRACJA ZAKOŃCZONA POMYŚLNIE!")
        return True
    else:
        print(f"\n⚠️  MIGRACJA WYMAGA UWAGI")
        return False

def main():
    """Główna funkcja walidacji"""
    print("🚀 WALIDACJA MIGRACJI APLIKACJI CZATU")
    print("=" * 50)
    
    # Utwórz aplikację testową
    app, db = create_validation_app()
    
    # Wykonaj testy
    tests_passed = 0
    total_tests = 5
    
    # Test 1: Struktura bazy danych
    db_structure = validate_database_structure(db)
    if 'error' not in db_structure:
        tests_passed += 1
    
    # Test 2: Import modeli
    if validate_models_import():
        tests_passed += 1
    
    # Test 3: Auth endpoints
    if validate_auth_endpoints():
        tests_passed += 1
    
    # Test 4: Chat endpoints  
    if validate_chat_endpoints():
        tests_passed += 1
    
    # Test 5: Operacje bazodanowe
    if test_database_operations(app, db):
        tests_passed += 1
    
    # Wygeneruj raport
    success = generate_migration_report(db_structure)
    
    print(f"\n📊 WYNIK FINALNY:")
    print(f"Testy przeszły: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests and success:
        print("🎉 WSZYSTKO DZIAŁA POPRAWNIE!")
        return 0
    else:
        print("⚠️  WYKRYTO PROBLEMY - SPRAWDŹ LOGI POWYŻEJ")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
