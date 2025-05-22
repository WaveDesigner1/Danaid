#!/usr/bin/env python
"""
websocket_server.py - Dedykowany serwer WebSocket dla aplikacji Danaid
"""

import asyncio
import websockets
import json
import logging
import os
import signal
import sys
from datetime import datetime

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("websocket_server")

# Przechowywanie aktywnych połączeń
active_connections = {}
# Flaga informująca, czy serwer jest uruchomiony
server_running = False

# Handler dla nowych połączeń WebSocket
async def connection_handler(websocket, path):
    """
    Obsługuje nowe połączenie WebSocket.
    
    Args:
        websocket: Obiekt WebSocket
        path: Ścieżka żądania, np. /ws/chat/12345
    """
    user_id = None
    try:
        # Wyciągnij user_id z ścieżki (np. /ws/chat/12345)
        parts = path.split('/')
        if len(parts) > 2 and parts[-2] == 'chat':
            user_id = parts[-1]
        
        if not user_id:
            logger.warning(f"Nieprawidłowa ścieżka: {path}")
            await websocket.close(1008, "Nieprawidłowa ścieżka")
            return
        
        logger.info(f"Nowe połączenie WebSocket od użytkownika {user_id}")
        
        # Dodaj do aktywnych połączeń
        if user_id not in active_connections:
            active_connections[user_id] = set()
        active_connections[user_id].add(websocket)
        
        # Powiadom klienta o pomyślnym połączeniu
        await websocket.send(json.dumps({
            'type': 'connection_established',
            'user_id': user_id,
            'timestamp': datetime.now().isoformat(),
            'message': 'Połączenie WebSocket nawiązane pomyślnie'
        }))
        
        # Powiadom o statusie online
        broadcast_online_status(user_id, True)
        
        # Pętla odbierania wiadomości
        async for message in websocket:
            try:
                data = json.loads(message)
                logger.info(f"Otrzymano wiadomość od {user_id}: {str(data)[:100]}...")
                
                # Obsługa różnych typów wiadomości
                message_type = data.get('type')
                
                if message_type == 'ping':
                    # Obsługa ping-pong dla utrzymania połączenia
                    await websocket.send(json.dumps({
                        'type': 'pong',
                        'timestamp': datetime.now().isoformat()
                    }))
                elif message_type == 'message':
                    # Przesyłanie wiadomości do odbiory
                    recipient_id = data.get('recipient_id')
                    if recipient_id:
                        await send_to_user(recipient_id, {
                            'type': 'new_message',
                            'from_user_id': user_id,
                            'content': data.get('content'),
                            'session_token': data.get('session_token'),
                            'timestamp': datetime.now().isoformat()
                        })
                
            except json.JSONDecodeError:
                logger.warning(f"Otrzymano nieprawidłowy JSON: {message[:100]}...")
            except Exception as e:
                logger.error(f"Błąd przetwarzania wiadomości: {e}")
    
    except websockets.exceptions.ConnectionClosed as e:
        logger.info(f"Połączenie zamknięte przez klienta: {e}")
    except Exception as e:
        logger.error(f"Błąd w obsłudze WebSocket: {e}")
    finally:
        # Sprzątanie przy rozłączeniu
        if user_id and user_id in active_connections:
            active_connections[user_id].discard(websocket)
            if not active_connections[user_id]:
                del active_connections[user_id]
                # Powiadom o statusie offline
                broadcast_online_status(user_id, False)
        
        logger.info(f"Użytkownik {user_id} rozłączony")

# Funkcja do wysyłania wiadomości do konkretnego użytkownika
async def send_to_user(user_id, message):
    """
    Wysyła wiadomość do użytkownika.
    
    Args:
        user_id (str): ID użytkownika
        message (dict): Wiadomość do wysłania
    
    Returns:
        bool: True jeśli wiadomość została wysłana, False w przeciwnym razie
    """
    if not user_id or user_id not in active_connections:
        logger.info(f"Nie można wysłać wiadomości: użytkownik {user_id} nie jest połączony")
        return False
    
    # Konwertuj obiekt na JSON, jeśli to nie jest string
    if not isinstance(message, str):
        message = json.dumps(message)
    
    # Licznik udanych wysłań
    sent_count = 0
    
    # Kopia zestawu, aby uniknąć błędów modyfikacji podczas iteracji
    connections = active_connections[user_id].copy()
    
    # Wyślij do wszystkich połączeń użytkownika
    for websocket in connections:
        try:
            await websocket.send(message)
            sent_count += 1
        except Exception as e:
            logger.error(f"Błąd wysyłania do {user_id}: {e}")
            # Usuń nieprawidłowe połączenie
            active_connections[user_id].discard(websocket)
    
    # Jeśli wszystkie połączenia się nie powiodły, usuń użytkownika z aktywnych
    if sent_count == 0 and user_id in active_connections:
        active_connections.pop(user_id, None)
        return False
    
    return sent_count > 0

# Funkcja do rozgłaszania zmiany statusu online
def broadcast_online_status(user_id, is_online):
    """
    Informuje wszystkich użytkowników o zmianie statusu online.
    
    Args:
        user_id (str): ID użytkownika
        is_online (bool): Status online
    """
    asyncio.create_task(broadcast_status_update(user_id, is_online))

async def broadcast_status_update(user_id, is_online):
    """
    Wysyła powiadomienia o statusie online do wszystkich użytkowników.
    
    Args:
        user_id (str): ID użytkownika
        is_online (bool): Status online
    """
    status_message = {
        'type': 'user_status_change',
        'user_id': user_id,
        'is_online': is_online,
        'timestamp': datetime.now().isoformat()
    }
    
    # Wyślij do wszystkich użytkowników poza tym, który zmienił status
    for recipient_id, connections in active_connections.items():
        if recipient_id != user_id:
            for websocket in connections:
                try:
                    await websocket.send(json.dumps(status_message))
                except Exception as e:
                    logger.error(f"Błąd wysyłania statusu do {recipient_id}: {e}")

# Funkcja do wysyłania listy użytkowników online
async def send_online_users():
    """Wysyła listę użytkowników online do wszystkich połączonych klientów."""
    while True:
        try:
            # Lista wszystkich użytkowników online
            online_users = list(active_connections.keys())
            
            # Wyślij do każdego połączonego klienta
            for user_id, connections in active_connections.items():
                message = {
                    'type': 'online_users',
                    'users': online_users,
                    'timestamp': datetime.now().isoformat()
                }
                
                for websocket in connections:
                    try:
                        await websocket.send(json.dumps(message))
                    except Exception as e:
                        logger.error(f"Błąd wysyłania listy online do {user_id}: {e}")
            
            # Aktualizuj co 30 sekund
            await asyncio.sleep(30)
        
        except Exception as e:
            logger.error(f"Błąd w pętli wysyłania użytkowników online: {e}")
            await asyncio.sleep(10)  # Krótsza przerwa przy błędzie

# Obsługa sygnałów systemowych
def handle_signal(sig, frame):
    """Obsługuje sygnały zamknięcia dla czystego zamknięcia."""
    logger.info(f"Otrzymano sygnał {sig}, zamykanie...")
    sys.exit(0)

# Główna funkcja uruchamiająca serwer
async def run_server(host="0.0.0.0", port=8081):
    """
    Uruchamia serwer WebSocket na podanym hoście i porcie.
    
    Args:
        host (str): Host do nasłuchiwania
        port (int): Port do nasłuchiwania
    """
    global server_running
    
    if server_running:
        logger.info("Serwer WebSocket już działa")
        return
    
    logger.info(f"Uruchamianie serwera WebSocket na {host}:{port}")
    
    # Uruchom wysyłanie listy użytkowników online
    asyncio.create_task(send_online_users())
    
    # Uruchom serwer WebSocket
    server_running = True
    async with websockets.serve(connection_handler, host, port):
        logger.info(f"Serwer WebSocket uruchomiony na {host}:{port}")
        await asyncio.Future()  # Uruchom bezterminowo

# Funkcja do uruchamiania serwera WebSocket w osobnym wątku
def start_websocket_server_thread():
    """
    Uruchamia serwer WebSocket w osobnym wątku.
    Ta funkcja może być wywoływana z innych skryptów, np. wsgi.py.
    """
    import threading
    
    def run_async_server():
        # Pobierz port z zmiennej środowiskowej lub użyj domyślnego
        port = int(os.environ.get("WEBSOCKET_PORT", 8081))
        host = os.environ.get("HOST", "0.0.0.0")
        
        print(f"Uruchamianie serwera WebSocket w wątku na {host}:{port}...")
        sys.stdout.flush()
        
        # Uruchom pętlę zdarzeń asyncio w tym wątku
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(run_server(host, port))
        except Exception as e:
            print(f"Błąd podczas uruchamiania serwera WebSocket: {e}")
            sys.stdout.flush()
    
    # Uruchom w osobnym wątku
    websocket_thread = threading.Thread(target=run_async_server)
    websocket_thread.daemon = True
    websocket_thread.start()
    
    return websocket_thread

# Gdy skrypt jest uruchamiany samodzielnie
if __name__ == "__main__":
    # Rejestruj obsługę sygnałów
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Pobierz port z zmiennej środowiskowej lub użyj domyślnego
    port = int(os.environ.get("WEBSOCKET_PORT", 8081))
    host = os.environ.get("HOST", "0.0.0.0")
    
    print(f"Uruchamianie serwera WebSocket na {host}:{port}...")
    sys.stdout.flush()  # Upewnij się, że log jest natychmiast widoczny
    
    try:
        # Uruchom główną pętlę
        asyncio.run(run_server(host, port))
    except Exception as e:
        print(f"Błąd podczas uruchamiania serwera WebSocket: {e}")
        sys.stdout.flush()
        sys.exit(1)

def start_flask_app():
    """Uruchamia aplikację Flask w osobnym wątku"""
    import threading
    from app import create_app
    
    print("🚀 Starting Flask app...")
    app = create_app()
    
    def run_flask():
        app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
    
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    print("✅ Flask thread started on port 8080")

# Gdy skrypt jest uruchamiany samodzielnie
if __name__ == "__main__":
    # Rejestruj obsługę sygnałów
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Pobierz port z zmiennej środowiskowej lub użyj domyślnego
    port = int(os.environ.get("WEBSOCKET_PORT", 8081))  # WebSocket na 8081
    host = os.environ.get("HOST", "0.0.0.0")
    
    print(f"Uruchamianie serwera WebSocket na {host}:{port}...")
    sys.stdout.flush()
    
    # DODAJ TĘ LINIĘ:
    start_flask_app()  # Uruchom Flask przed WebSocket
    
    try:
        # Uruchom główną pętlę WebSocket
        asyncio.run(run_server(host, port))
    except Exception as e:
        print(f"Błąd podczas uruchamiania serwera WebSocket: {e}")
        sys.stdout.flush()
        sys.exit(1)
