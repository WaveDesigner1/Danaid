# W pliku app.py - dodaj te importy na górze
from flask_socketio import SocketIO, emit, join_room, leave_room
import logging

# Po utworzeniu app dodaj:
def create_app():
    app = Flask(__name__)
    
    # ... twoje obecne konfiguracje ...
    
    # DODAJ to po konfiguracji Flask:
    socketio = SocketIO(
        app, 
        cors_allowed_origins="*",
        logger=True,
        engineio_logger=True,
        async_mode='threading'  # Ważne dla Railway
    )
    
    # Słownik przechowujący aktywne połączenia
    active_connections = {}
    
    # Event handlers dla SocketIO
    @socketio.on('connect')
    def handle_connect(auth):
        """Obsługa nowych połączeń WebSocket"""
        try:
            # Pobierz user_id z auth lub request args
            user_id = None
            if auth and 'user_id' in auth:
                user_id = auth['user_id']
            else:
                # Alternatywnie z query string
                from flask import request
                user_id = request.args.get('user_id')
            
            if not user_id:
                print("Brak user_id w połączeniu WebSocket")
                return False
            
            # Zapisz połączenie
            session_id = request.sid
            active_connections[user_id] = session_id
            
            # Dodaj do pokoju użytkownika
            join_room(f"user_{user_id}")
            
            print(f"✅ Użytkownik {user_id} połączony (session: {session_id})")
            
            # Wyślij potwierdzenie
            emit('connection_established', {
                'type': 'connection_established',
                'user_id': user_id,
                'timestamp': datetime.now().isoformat(),
                'message': 'Połączenie WebSocket nawiązane pomyślnie'
            })
            
            # Powiadom innych o s
