# wsgi.py
import os
import threading
import asyncio
from app import create_app
from websocket_handler import start_websocket_server

# Tworzenie aplikacji Flask
app = create_app()

# Funkcja uruchamiająca serwer WebSocket w osobnym wątku
def run_websocket_server():
    asyncio.run(start_websocket_server(
        host="0.0.0.0", 
        port=int(os.environ.get("WEBSOCKET_PORT", 8081))
    ))

# Uruchom WebSocket w osobnym wątku przy starcie aplikacji
websocket_thread = threading.Thread(target=run_websocket_server)
websocket_thread.daemon = True
websocket_thread.start()
