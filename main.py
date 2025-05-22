import os
import threading
import asyncio
import sys

print("=== STARTING MAIN.PY ===")
print(f"Python version: {sys.version}")
print(f"PORT env: {os.environ.get('PORT', 'NOT SET')}")
print(f"WEBSOCKET_PORT env: {os.environ.get('WEBSOCKET_PORT', 'NOT SET')}")

try:
    from app import create_app
    print("✅ Successfully imported create_app")
except Exception as e:
    print(f"❌ Error importing create_app: {e}")
    sys.exit(1)

try:
    from websocket_handler import start_websocket_server
    print("✅ Successfully imported start_websocket_server")
except Exception as e:
    print(f"❌ Error importing websocket_handler: {e}")
    sys.exit(1)

# Tworzenie aplikacji Flask
try:
    print("🔄 Creating Flask app...")
    app = create_app()
    print("✅ Flask app created successfully")
except Exception as e:
    print(f"❌ Error creating Flask app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Funkcja uruchamiająca serwer WebSocket w osobnym wątku
def run_websocket_server():
    print("🔄 WebSocket thread starting...")
    asyncio.run(start_websocket_server(
        host="0.0.0.0", 
        port=int(os.environ.get("WEBSOCKET_PORT", 8081))
    ))

# Uruchom WebSocket w osobnym wątku przy starcie aplikacji
print("🔄 Starting WebSocket thread...")
websocket_thread = threading.Thread(target=run_websocket_server)
websocket_thread.daemon = True
websocket_thread.start()
print("✅ WebSocket thread started")

if __name__ == "__main__":
    # Pobierz port dla głównej aplikacji z zmiennej środowiskowej
    port = int(os.environ.get("PORT", 8080))
    print(f"🚀 Starting Flask on port {port}")
    
    try:
        # W trybie deweloperskim użyj wbudowanego serwera Flask
        app.run(host="0.0.0.0", port=port, debug=False)
    except Exception as e:
        print(f"❌ Error starting Flask: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
