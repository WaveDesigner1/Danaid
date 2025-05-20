"""
websocket_routes.py - Moduł obsługi WebSocket dla aplikacji Flask
"""

import logging
import json
from flask import Blueprint, request, Response, jsonify
from flask_login import current_user, login_required

# Konfiguracja logowania
logger = logging.getLogger(__name__)

# Utwórz blueprint dla ścieżek WebSocket
websocket_bp = Blueprint('websocket', __name__)

@websocket_bp.route('/ws/chat/<user_id>', methods=['GET', 'POST', 'OPTIONS'])
def websocket_endpoint(user_id):
    """
    Endpoint obsługujący żądania WebSocket.
    
    W środowisku Railway.app, serwer WebSocket działa jako oddzielny proces,
    więc ten endpoint służy jako proxy dla klienta przeglądarki.
    """
    # Logowanie informacji o żądaniu
    logger.info(f"Otrzymano żądanie WebSocket dla użytkownika {user_id}")
    logger.info(f"Metoda: {request.method}")
    logger.info(f"Nagłówki: {dict(request.headers)}")
    
    # Dla żądań OPTIONS (CORS preflight) zwracamy odpowiednie nagłówki
    if request.method == 'OPTIONS':
        resp = Response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        resp.headers['Access-Control-Max-Age'] = '86400'  # 24 godziny
        return resp
    
    # Dla żądań GET zwracamy informacje o endpoincie WebSocket
    return jsonify({
        'status': 'success',
        'message': 'Endpoint WebSocket jest dostępny. Użyj protokołu WebSocket do połączenia.',
        'websocket_info': {
            'user_id': user_id,
            'host': request.host,
            'protocol': 'wss' if request.is_secure else 'ws',
            'suggested_url': f"{'wss' if request.is_secure else 'ws'}://{request.host}/ws/chat/{user_id}"
        }
    })

@websocket_bp.route('/api/websocket/status', methods=['GET'])
def websocket_status():
    """
    Endpoint do sprawdzania statusu serwera WebSocket.
    """
    try:
        # Pobierz status serwera WebSocket
        # W rzeczywistej implementacji, należałoby sprawdzić, czy serwer działa
        from websocket_handler import ws_handler
        
        # Sprawdź, czy handler ma atrybut _running
        is_running = getattr(ws_handler, '_running', False)
        
        # Przygotuj informacje o statusie
        status_info = {
            'status': 'success',
            'websocket_running': is_running,
            'connections': len(getattr(ws_handler, 'active_connections', {})),
            'websocket_url': f"{'wss' if request.is_secure else 'ws'}://{request.host}/ws/chat"
        }
        
        # Dodaj liczbę aktywnych połączeń dla zalogowanego użytkownika
        if current_user.is_authenticated:
            user_connections = []
            active_connections = getattr(ws_handler, 'active_connections', {})
            if current_user.user_id in active_connections:
                user_connections = len(active_connections[current_user.user_id])
            
            status_info['user_connections'] = user_connections
        
        return jsonify(status_info)
        
    except ImportError:
        # Nie można zaimportować ws_handler
        return jsonify({
            'status': 'error',
            'message': 'Serwer WebSocket nie jest dostępny',
            'error': 'ImportError: nie można zaimportować websocket_handler'
        }), 503
    except Exception as e:
        # Inny błąd
        logger.error(f"Błąd sprawdzania statusu WebSocket: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Wystąpił błąd podczas sprawdzania statusu serwera WebSocket',
            'error': str(e)
        }), 500

@websocket_bp.route('/api/websocket/test/<user_id>', methods=['GET'])
@login_required
def websocket_test(user_id):
    """
    Endpoint testowy do sprawdzenia, czy można wysłać wiadomość przez WebSocket.
    """
    try:
        # Sprawdź, czy user_id zgadza się z ID zalogowanego użytkownika
        if current_user.user_id != user_id:
            return jsonify({
                'status': 'error',
                'message': 'Nie można wysłać wiadomości testowej do innego użytkownika'
            }), 403
        
        # Spróbuj wysłać wiadomość testową przez WebSocket
        from websocket_handler import ws_handler
        
        # Przygotuj wiadomość testową
        test_message = {
            'type': 'test_message',
            'message': 'To jest wiadomość testowa od serwera',
            'timestamp': from_datetime(datetime.datetime.utcnow())
        }
        
        # Wyślij wiadomość
        success = ws_handler.send_to_user(user_id, test_message)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Wiadomość testowa wysłana pomyślnie',
                'test_message': test_message
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Nie można wysłać wiadomości testowej - użytkownik nie jest online',
                'is_online': ws_handler.is_user_online(user_id)
            }), 404
            
    except ImportError:
        return jsonify({
            'status': 'error',
            'message': 'Serwer WebSocket nie jest dostępny',
            'error': 'ImportError: nie można zaimportować websocket_handler'
        }), 503
    except Exception as e:
        logger.error(f"Błąd wysyłania wiadomości testowej: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Wystąpił błąd podczas wysyłania wiadomości testowej',
            'error': str(e)
        }), 500

def from_datetime(dt):
    """Konwertuje datetime na string ISO"""
    if hasattr(dt, 'isoformat'):
        return dt.isoformat() + 'Z'
    return str(dt)

def init_websocket_routes(app):
    """
    Inicjalizuje ścieżki WebSocket w aplikacji Flask.
    """
    # Rejestruje blueprint z endpointami WebSocket
    app.register_blueprint(websocket_bp)
    
    logger.info("Zainicjalizowano ścieżki WebSocket")
    
    return app
