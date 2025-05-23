import os
import sys

print("=== STARTING MAIN.PY WITH SOCKET.IO ===")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")
print(f"Files in directory: {os.listdir('.')}")
print(f"PORT env: {os.environ.get('PORT', 'NOT SET')}")

try:
    from app import create_app
    print("✅ Successfully imported create_app")
except Exception as e:
    print(f"❌ Error importing create_app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Tworzenie aplikacji Flask z Socket.IO
try:
    print("🔄 Creating Flask app with Socket.IO...")
    app, socketio = create_app()  # Teraz zwraca tuple (app, socketio)
    print("✅ Flask app with Socket.IO created successfully")
except Exception as e:
    print(f"❌ Error creating Flask app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

if __name__ == "__main__":
    # Pobierz port dla aplikacji
    port = int(os.environ.get("PORT", 8080))
    print(f"🚀 Starting Flask with Socket.IO on port {port}")
    
    try:
        # Użyj socketio.run zamiast app.run
        # Socket.IO automatycznie obsługuje WebSocket connections na tym samym porcie
        socketio.run(
            app,
            host="0.0.0.0",
            port=port,
            debug=False,
            allow_unsafe_werkzeug=True  # Wymagane dla nowszych wersji
        )
    except Exception as e:
        print(f"❌ Error starting Flask with Socket.IO: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
