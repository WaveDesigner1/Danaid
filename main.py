#!/usr/bin/env python3
"""
Danaid Chat - Main Entry Point
Zoptymalizowana wersja po redukcji kodu o 42% i scaleniu modułów
"""

import os
import sys
import logging
from datetime import datetime

# Konfiguracja logowania dla debugowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def startup_diagnostics():
    """Diagnostyka startowa - sprawdza środowisko"""
    print("=" * 50)
    print("🚀 DANAID CHAT - OPTIMIZED STARTUP")
    print("=" * 50)
    print(f"📅 Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🐍 Python version: {sys.version}")
    print(f"📁 Working directory: {os.getcwd()}")
    print(f"🌍 PORT environment: {os.environ.get('PORT', 'NOT SET (default: 8080)')}")
    print(f"🔧 Debug mode: {os.environ.get('FLASK_DEBUG', 'False')}")
    
    # Sprawdź kluczowe pliki po optymalizacji
    required_files = [
        'app.py',           # Main app factory
        'auth.py',          # Auth (niezmieniony)
        'chat.py',          # 🔄 SCALONY (chat + chat_api)  
        'admin.py',         # 🔄 ZOPTYMALIZOWANY
        'requirements.txt'
    ]
    
    print("\n📦 Checking optimized file structure:")
    for file in required_files:
        exists = "✅" if os.path.exists(file) else "❌"
        print(f"   {exists} {file}")
    
    # Sprawdź frontend po consolidacji
    frontend_files = [
        'static/js/chat.js',    # 🔄 ZUNIFIKOWANY (ChatInterface + SessionManager + SocketIO)
        'static/js/crypto.js',  # 🔄 ZOPTYMALIZOWANY (UnifiedCrypto → crypto)
        'static/js/auth.js',    # 🔄 SCALONY (user_script + register_send)
        'static/css/app.css'     # 🔄 ZUNIFIKOWANY (3x CSS → 1x CSS)
    ]
    
    print("\n🎨 Frontend consolidation status:")
    for file in frontend_files:
        exists = "✅" if os.path.exists(file) else "❌"
        print(f"   {exists} {file}")
    
    print("\n" + "=" * 50)

def main():
    """Main entry point z obsługą nowej architektury"""
    
    # Diagnostyka startowa
    startup_diagnostics()
    
    # Import app factory (powinna zwracać tuple po optymalizacji)
    try:
        print("🔄 Importing optimized app factory...")
        from app import create_app
        logger.info("✅ Successfully imported create_app from optimized structure")
    except ImportError as e:
        logger.error(f"❌ Import error - możliwe problemy z zależnościami: {e}")
        print("💡 Tip: Sprawdź czy wszystkie artefakty zostały skopiowane")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error during import: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Tworzenie aplikacji (po optymalizacji powinna zwracać app + socketio)
    try:
        print("🔄 Creating Flask app with integrated Socket.IO...")
        result = create_app()
        
        # Sprawdź czy create_app zwraca tuple czy pojedynczy obiekt
        if isinstance(result, tuple):
            app, socketio = result
            print("✅ Received app + socketio tuple (nowa architektura)")
        else:
            # Fallback dla przypadku gdy jeszcze nie wszystko zoptymalizowane
            app = result
            socketio = None
            print("⚠️  Received single app object (stara architektura)")
            
        logger.info("✅ Flask app with Socket.IO created successfully")
        
    except Exception as e:
        logger.error(f"❌ Error creating Flask app: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Start aplikacji
    if __name__ == "__main__":
        port = int(os.environ.get("PORT", 8080))
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        
        print(f"\n🚀 Starting Danaid Chat on port {port}")
        print(f"🔧 Debug mode: {debug_mode}")
        print(f"🌐 Access URL: http://localhost:{port}")
        print("=" * 50)
        
        try:
            if socketio:
                # Nowa architektura - Socket.IO zintegrowane
                print("🔌 Using integrated Socket.IO server")
                socketio.run(
                    app,
                    host="0.0.0.0",
                    port=port,
                    debug=debug_mode,
                    allow_unsafe_werkzeug=True,
                    log_output=True
                )
            else:
                # Fallback - standard Flask
                print("⚠️  Using standard Flask server (Socket.IO not integrated)")
                app.run(
                    host="0.0.0.0",
                    port=port,
                    debug=debug_mode
                )
                
        except KeyboardInterrupt:
            print("\n🛑 Graceful shutdown initiated by user")
            logger.info("Application stopped by user")
        except Exception as e:
            logger.error(f"❌ Error starting server: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    main()
