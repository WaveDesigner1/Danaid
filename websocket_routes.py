"""
websocket_routes.py - Moduł obsługi WebSocket dla aplikacji Flask
"""

import logging
import json
import os
import datetime
from flask import Blueprint, request, Response, jsonify, current_app
from flask_login import current_user, login_required

# Konfiguracja logowania
logger = logging.getLogger(__name__)

# Utwórz blueprint dla ścieżek WebSocket
websocket_bp = Blueprint('websocket', __name__)

@websocket_bp.route('/ws/chat/<user_id>', methods=['GET', 'POST', 'OPTIONS'])
def websocket_endpoint(user_id):
    """
    Endpoint wskazujący na dedykowany serwer WebSocket.
    Nie implementuje faktycznej obsługi WebSocket, a jedynie zwraca informacje 
    o dedykowanym serwerze WebSocket.
    """
    # Logowanie informacji o żądaniu
    logger.info(f"Otrzymano żądanie WebSocket dla użytkownika {user_id}")
    logger.info(f"Metoda: {request.method}")
    
    # Dla żądań OPTIONS (CORS preflight) zwracamy odpowiednie nagłówki
    if request.method == 'OPTIONS':
        resp = Response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
        resp.headers['Access-Control-Max-Age'] = '86400'  # 24 godziny
        return resp
    
    # Pobierz adres URL serwera WebSocket z zmiennej środowiskowej
    websocket_url = os.environ.get('WEBSOCKET_URL', '')
    
    # Dla żądań GET zwracamy informacje o dedykowanym serwerze WebSocket
    if websocket_url:
        # Określ protokół (wss dla HTTPS, ws dla HTTP)
        protocol = 'wss' if request.is_secure else 'ws'
        
        return jsonify({
            'status': 'info',
            'message': 'WebSocket jest obsługiwany przez dedykowany serwer',
            'websocket_info': {
                'user_id': user_id,
                'websocket_url': f"{protocol}://{websocket_url}/ws/chat/{user_id}"
            }
        })
    else:
        # Brak skonfigurowanego adresu WebSocket
        return jsonify({
            'status': 'error',
            'message': 'Nie skonfigurowano adresu serwera WebSocket (WEBSOCKET_URL)'
        }), 500

@websocket_bp.route('/api/websocket/config')
def websocket_config():
    """Dostarcza konfigurację WebSocket dla klienta"""
    # Pobierz URL z zmiennej środowiskowej
    websocket_url = os.environ.get('WEBSOCKET_URL', '')
    if not websocket_url:
        # Użyj domyślnego hosta jeśli nie ma zmiennej środowiskowej
        logger.warning('Zmienna WEBSOCKET_URL nie jest ustawiona!')
        websocket_url = request.host
    
    # Loguj dla debugowania
    logger.info(f"Konfiguracja WebSocket: {websocket_url}")
    
    return jsonify({
        'wsUrl': websocket_url
    })

@websocket_bp.route('/api/websocket/status', methods=['GET'])
def websocket_status():
    """
    Endpoint informujący o statusie serwera WebSocket.
    
    Nie próbuje importować ws_handler (który jest dostępny tylko na serwerze WebSocket),
    a zamiast tego sprawdza dostępność serwera WebSocket na podstawie zmiennej środowiskowej.
    """
    websocket_url = os.environ.get('WEBSOCKET_URL', '')
    
    if not websocket_url:
        return jsonify({
            'status': 'warning',
            'message': 'Nie skonfigurowano adresu serwera WebSocket (WEBSOCKET_URL)',
            'websocket_running': False
        }), 200
    
    return jsonify({
        'status': 'success',
        'message': 'WebSocket jest obsługiwany przez dedykowany serwer',
        'websocket_running': True,
        'websocket_url': f"{'wss' if request.is_secure else 'ws'}://{websocket_url}/ws/chat"
    })

@websocket_bp.route('/api/websocket/test/<user_id>', methods=['GET'])
@login_required
def websocket_test(user_id):
    """
    Endpoint testowy - przekierowuje do dedykowanego serwera WebSocket.
    """
    websocket_url = os.environ.get('WEBSOCKET_URL', '')
    
    if not websocket_url:
        return jsonify({
            'status': 'error',
            'message': 'Nie skonfigurowano adresu serwera WebSocket (WEBSOCKET_URL)'
        }), 500
    
    return jsonify({
        'status': 'info',
        'message': 'Test WebSocket jest dostępny na dedykowanym serwerze',
        'websocket_url': f"{'https' if request.is_secure else 'http'}://{websocket_url}/api/websocket/test/{user_id}"
    })

def from_datetime(dt):
    """Konwertuje datetime na string ISO"""
    if hasattr(dt, 'isoformat'):
        return dt.isoformat() + 'Z'
    return str(dt)

def init_websocket_routes(app):
    """
    Inicjalizuje ścieżki WebSocket w aplikacji Flask.
    
    ⚠️ UWAGA: Ta funkcja NIE uruchamia serwera WebSocket!
    Rejestruje tylko endpointy, które wskazują na dedykowany serwer WebSocket.
    """
    # Rejestruje blueprint z endpointami WebSocket
    app.register_blueprint(websocket_bp)
    
    # Dodaj trasę główną, jeśli nie ma jej jeszcze
    if not any(rule.rule == '/' for rule in app.url_map.iter_rules()):
        @app.route('/')
        def index_redirect():
            """Przekierowanie ze strony głównej do właściwej strony początkowej"""
            if current_user.is_authenticated:
                # Jeśli użytkownik jest zalogowany, przekieruj do czatu
                return current_app.view_functions['chat.index']()
            else:
                # Jeśli użytkownik nie jest zalogowany, przekieruj do logowania
                return current_app.view_functions['auth.index']()
    
    logger.info("Zainicjalizowano ścieżki WebSocket (tylko przekierowanie)")
    
    return app
