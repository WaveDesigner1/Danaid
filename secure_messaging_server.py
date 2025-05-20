"""
Secure Messaging Server Module

Ten moduł obsługuje bezpieczną komunikację między użytkownikami z szyfrowaniem end-to-end.
Implementuje protokół wymiany kluczy i zarządzania sesją, zapewniając prywatność wiadomości.
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import logging
import threading
import asyncio
import uuid
import json
import base64

# Konfiguracja logowania
logger = logging.getLogger(__name__)

# Tworzenie blueprint
secure_messaging = Blueprint('secure_messaging', __name__)

@secure_messaging.route('/api/friend_requests', methods=['POST'])
@login_required
def send_friend_request():
    """Wysyła zaproszenie do znajomych do innego użytkownika"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Brak danych w żądaniu'
            }), 400
        
        # Obsługuj zarówno username jak i recipient_id (dla kompatybilności)
        if 'username' in data:
            username = data['username']
            # Import modeli
            from models import User, db, FriendRequest
            # Szukaj użytkownika po nazwie
            recipient = User.query.filter_by(username=username).first()
        elif 'recipient_id' in data:
            recipient_id = data['recipient_id']
            # Import modeli
            from models import User, db, FriendRequest
            # Szukaj użytkownika po ID
            recipient = User.query.filter_by(user_id=recipient_id).first()
        else:
            return jsonify({
                'status': 'error',
                'message': 'Brak wymaganego parametru username lub recipient_id'
            }), 400
        
        if not recipient:
            return jsonify({
                'status': 'error',
                'message': 'Użytkownik nie został znaleziony'
            }), 404
        
        # Sprawdź czy nadawca i odbiorca to ta sama osoba
        if recipient.id == current_user.id:
            return jsonify({
                'status': 'error',
                'message': 'Nie możesz wysłać zaproszenia do samego siebie'
            }), 400
        
        # Sprawdź czy zaproszenie już istnieje
        existing_request = FriendRequest.query.filter_by(
            from_user_id=current_user.id,
            to_user_id=recipient.id,
            status='pending'
        ).first()
        
        if existing_request:
            return jsonify({
                'status': 'error',
                'message': 'Zaproszenie do znajomych już istnieje'
            }), 400
        
        # Sprawdź czy już są znajomymi
        from models import Friend
        is_friend = Friend.query.filter(
            ((Friend.user_id == current_user.id) & (Friend.friend_id == recipient.id)) |
            ((Friend.user_id == recipient.id) & (Friend.friend_id == current_user.id))
        ).first()
        
        if is_friend:
            return jsonify({
                'status': 'error',
                'message': 'Użytkownicy są już znajomymi'
            }), 400
        
        # Utwórz nowe zaproszenie
        new_request = FriendRequest(
            from_user_id=current_user.id,
            to_user_id=recipient.id,
            status='pending',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.session.add(new_request)
        db.session.commit()
        
        # Powiadom drugiego użytkownika (jeśli jest online)
        try:
            from websocket_handler import ws_handler
            if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(recipient.user_id):
                ws_handler.send_to_user(recipient.user_id, {
                    'type': 'friend_request',
                    'from_user': {
                        'id': current_user.id,
                        'user_id': current_user.user_id,
                        'username': current_user.username
                    },
                    'request_id': new_request.id,
                    'timestamp': datetime.utcnow().isoformat()
                })
        except (ImportError, AttributeError, Exception) as e:
            # Błędy związane z WebSocket nie powinny zatrzymywać procesu
            logger.error(f"Błąd podczas wysyłania powiadomienia: {e}")
        
        return jsonify({
            'status': 'success',
            'message': 'Zaproszenie do znajomych wysłane',
            'request_id': new_request.id
        }), 201
    
    except Exception as e:
        db.session.rollback()  # Cofnij transakcję w przypadku błędu
        logger.error(f"Błąd podczas wysyłania zaproszenia: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Błąd serwera: {str(e)}'
        }), 500

@secure_messaging.route('/api/friend_requests/pending', methods=['GET'])
@login_required
def get_pending_requests():
    """Pobiera listę oczekujących zaproszeń dla zalogowanego użytkownika"""
    from models import FriendRequest, User
    
    # Pobierz oczekujące zaproszenia
    pending_requests = FriendRequest.query.filter_by(
        to_user_id=current_user.id,
        status='pending'
    ).all()
    
    requests_list = []
    for req in pending_requests:
        sender = User.query.get(req.from_user_id)
        requests_list.append({
            'id': req.id,
            'sender_id': sender.user_id,
            'username': sender.username,
            'created_at': req.created_at.isoformat()
        })
    
    return jsonify({
        'status': 'success',
        'requests': requests_list
    })

@secure_messaging.route('/api/friend_requests/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """Akceptuje zaproszenie do znajomych"""
    from models import db, FriendRequest, Friend, User
    
    # Znajdź zaproszenie
    friend_request = FriendRequest.query.filter_by(
        id=request_id,
        to_user_id=current_user.id
    ).first()
    
    # Sprawdź czy zaproszenie istnieje
    if not friend_request:
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie nie zostało znalezione'
        }), 404
    
    # Sprawdź czy zaproszenie nie zostało już przetworzone
    if friend_request.status != 'pending':
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie zostało już przetworzone'
        }), 400
    
    try:
        # Aktualizuj status zaproszenia
        friend_request.status = 'accepted'
        friend_request.updated_at = datetime.utcnow()
        
        # Utwórz relacje znajomości (w obie strony)
        friend1 = Friend(
            user_id=current_user.id,
            friend_id=friend_request.from_user_id,
            created_at=datetime.utcnow()
        )
        
        friend2 = Friend(
            user_id=friend_request.from_user_id,
            friend_id=current_user.id,
            created_at=datetime.utcnow()
        )
        
        db.session.add(friend1)
        db.session.add(friend2)
        db.session.commit()
        
        # Powiadom drugiego użytkownika
        try:
            from websocket_handler import ws_handler
            sender = User.query.get(friend_request.from_user_id)
            
            if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(sender.user_id):
                ws_handler.send_to_user(sender.user_id, {
                    'type': 'friend_added',
                    'friend': {
                        'id': current_user.id,
                        'user_id': current_user.user_id,
                        'username': current_user.username,
                        'is_online': current_user.is_online
                    },
                    'timestamp': datetime.utcnow().isoformat()
                })
        except (ImportError, AttributeError, Exception) as e:
            # Błędy związane z WebSocket nie powinny zatrzymywać procesu
            logger.error(f"Błąd podczas wysyłania powiadomienia: {e}")
        
        return jsonify({
            'status': 'success',
            'message': 'Zaproszenie zaakceptowane'
        })
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd podczas akceptacji zaproszenia: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Błąd podczas akceptacji zaproszenia'
        }), 500

@secure_messaging.route('/api/friend_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """Odrzuca zaproszenie do znajomych"""
    from models import db, FriendRequest
    
    # Znajdź zaproszenie
    friend_request = FriendRequest.query.filter_by(
        id=request_id,
        to_user_id=current_user.id
    ).first()
    
    # Sprawdź czy zaproszenie istnieje
    if not friend_request:
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie nie zostało znalezione'
        }), 404
    
    # Sprawdź czy zaproszenie nie zostało już przetworzone
    if friend_request.status != 'pending':
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie zostało już przetworzone'
        }), 400
    
    # Aktualizuj status zaproszenia
    friend_request.status = 'rejected'
    friend_request.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Zaproszenie odrzucone'
    })

@secure_messaging.route('/api/online_users', methods=['GET'])
@login_required
def get_online_users():
    """Pobiera listę użytkowników online"""
    from models import User
    
    # Pobierz użytkowników online
    online_users = User.query.filter(
        User.is_online == True,
        User.id != current_user.id
    ).all()
    
    user_list = []
    for user in online_users:
        user_list.append({
            'id': user.id,
            'user_id': user.user_id,
            'username': user.username
        })
    
    return jsonify({
        'status': 'success',
        'online_users': user_list
    })

@secure_messaging.route('/api/friends', methods=['GET'])
@login_required
def get_friends():
    """Pobiera listę znajomych użytkownika"""
    from models import db, User, Friend
    
    # Pobierz znajomych
    friend_records = Friend.query.filter_by(user_id=current_user.id).all()
    
    friend_ids = [friend.friend_id for friend in friend_records]
    friends = User.query.filter(User.id.in_(friend_ids)).all()
    
    friend_list = []
    for friend in friends:
        friend_list.append({
            'id': friend.id,
            'user_id': friend.user_id,
            'username': friend.username,
            'is_online': friend.is_online
        })
    
    return jsonify({
        'status': 'success',
        'friends': friend_list
    })

@secure_messaging.route('/api/session/init', methods=['POST'])
@login_required
def initialize_session():
    """Inicjalizuje nową sesję czatu z szyfrowaniem E2EE"""
    data = request.get_json()
    
    if not data or 'recipient_id' not in data:
        return jsonify({
            'status': 'error',
            'message': 'Brak wymaganego parametru recipient_id'
        }), 400
    
    recipient_id = data['recipient_id']
    
    from models import db, User, Friend, ChatSession
    
    # Sprawdź czy odbiorca istnieje
    recipient = User.query.filter_by(user_id=recipient_id).first()
    if not recipient:
        return jsonify({
            'status': 'error',
            'message': 'Użytkownik nie został znaleziony'
        }), 404
    
    # Sprawdź czy są znajomymi
    is_friend = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == recipient.id)) |
        ((Friend.user_id == recipient.id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if not is_friend:
        return jsonify({
            'status': 'error',
            'message': 'Możesz inicjować czat tylko ze znajomymi'
        }), 403
    
    # Sprawdź czy sesja już istnieje
    existing_session = ChatSession.query.filter(
        ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient.id)) |
        ((ChatSession.initiator_id == recipient.id) & (ChatSession.recipient_id == current_user.id))
    ).filter(
        ChatSession.is_active == True,
        ChatSession.expires_at > datetime.utcnow()
    ).first()
    
    if existing_session:
        # Zwróć istniejącą sesję
        other_user = recipient if existing_session.initiator_id == current_user.id else User.query.get(existing_session.initiator_id)
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja już istnieje',
            'session': {
                'token': existing_session.session_token,
                'initiator_id': existing_session.initiator_id,
                'recipient_id': existing_session.recipient_id,
                'created_at': existing_session.created_at.isoformat(),
                'expires_at': existing_session.expires_at.isoformat(),
                'has_key': existing_session.encrypted_session_key is not None,
                'key_acknowledged': existing_session.key_acknowledged,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': other_user.is_online
                }
            }
        })
    
    # Utwórz nową sesję
    session_token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=30)  # Sesja ważna przez 30 dni
    
    new_session = ChatSession(
        session_token=session_token,
        initiator_id=current_user.id,
        recipient_id=recipient.id,
        created_at=datetime.utcnow(),
        last_activity=datetime.utcnow(),
        expires_at=expires_at,
        is_active=True
    )
    
    db.session.add(new_session)
    db.session.commit()
    
    # Powiadom odbiorcę o nowej sesji
    try:
        from websocket_handler import ws_handler
        if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(recipient.user_id):
            ws_handler.send_to_user(recipient.user_id, {
                'type': 'session_update',
                'session_token': session_token,
                'initiator': {
                    'id': current_user.id,
                    'user_id': current_user.user_id,
                    'username': current_user.username
                },
                'timestamp': datetime.utcnow().isoformat()
            })
    except (ImportError, AttributeError, Exception) as e:
        # Błędy związane z WebSocket nie powinny zatrzymywać procesu
        logger.error(f"Błąd podczas wysyłania powiadomienia: {e}")
    
    return jsonify({
        'status': 'success',
        'message': 'Nowa sesja utworzona',
        'session': {
            'token': session_token,
            'initiator_id': current_user.id,
            'recipient_id': recipient.id,
            'created_at': new_session.created_at.isoformat(),
            'expires_at': expires_at.isoformat(),
            'has_key': False,
            'key_acknowledged': False,
            'other_user': {
                'id': recipient.id,
                'user_id': recipient.user_id,
                'username': recipient.username,
                'is_online': recipient.is_online
            }
        }
    })

@secure_messaging.route('/api/sessions/active', methods=['GET'])
@login_required
def get_active_sessions():
    """Pobiera aktywne sesje czatu dla zalogowanego użytkownika"""
    from models import ChatSession, User
    
    # Pobierz aktywne sesje
    active_sessions = ChatSession.query.filter(
        ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
        ChatSession.is_active == True,
        ChatSession.expires_at > datetime.utcnow()
    ).all()
    
    session_list = []
    for session in active_sessions:
        # Określ drugiego uczestnika
        other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        other_user = User.query.get(other_user_id)
        
        session_list.append({
            'token': session.session_token,
            'initiator_id': session.initiator_id,
            'recipient_id': session.recipient_id,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'has_key': session.encrypted_session_key is not None,
            'key_acknowledged': session.key_acknowledged,
            'other_user': {
                'id': other_user.id,
                'user_id': other_user.user_id,
                'username': other_user.username,
                'is_online': other_user.is_online
            }
        })
    
    return jsonify({
        'status': 'success',
        'sessions': session_list
    })

@secure_messaging.route('/api/session/<string:session_token>/key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """Wymienia klucz sesji E2EE (handshake protokołu)"""
    data = request.get_json()
    
    if not data or 'encrypted_key' not in data:
        return jsonify({
            'status': 'error',
            'message': 'Brak wymaganego parametru encrypted_key'
        }), 400
    
    encrypted_session_key = data.get('encrypted_key')
    
    from models import db, ChatSession, User
    
    # Pobierz sesję
    session = ChatSession.query.filter_by(session_token=session_token).first()
    
    if not session:
        return jsonify({
            'status': 'error',
            'message': 'Sesja nie istnieje'
        }), 404
    
    # Sprawdź czy użytkownik jest uczestnikiem sesji
    if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Brak dostępu do sesji'
        }), 403
    
    # Zapisz zaszyfrowany klucz sesji
    session.encrypted_session_key = encrypted_session_key
    session.last_activity = datetime.utcnow()
    db.session.commit()
    
    # Powiadom odbiorcę o nowym kluczu sesji
    try:
        from websocket_handler import ws_handler
        recipient_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        recipient = User.query.get(recipient_id)
        
        if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(recipient.user_id):
            ws_handler.send_to_user(recipient.user_id, {
                'type': 'session_key_update',
                'session_token': session_token,
                'encrypted_key': encrypted_session_key,
                'sender_id': current_user.user_id,
                'timestamp': datetime.utcnow().isoformat()
            })
    except (ImportError, AttributeError, Exception) as e:
        # Błędy związane z WebSocket nie powinny zatrzymywać procesu
        logger.error(f"Błąd podczas wysyłania powiadomienia: {e}")
    
    return jsonify({
        'status': 'success',
        'message': 'Klucz sesji zaktualizowany'
    })

@secure_messaging.route('/api/session/<string:session_token>/key', methods=['GET'])
@login_required
def get_session_key(session_token):
    """Pobiera zaszyfrowany klucz sesji"""
    
    from models import ChatSession
    
    # Pobierz sesję
    session = ChatSession.query.filter_by(session_token=session_token).first()
    
    if not session:
        return jsonify({
            'status': 'error',
            'message': 'Sesja nie istnieje'
        }), 404
    
    # Sprawdź czy użytkownik jest uczestnikiem sesji
    if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Brak dostępu do sesji'
        }), 403
    
    # Sprawdź czy klucz sesji istnieje
    if not session.encrypted_session_key:
        return jsonify({
            'status': 'error',
            'message': 'Klucz sesji nie został jeszcze przesłany'
        }), 404
    
    return jsonify({
        'status': 'success',
        'encrypted_key': session.encrypted_session_key
    })

@secure_messaging.route('/api/session/<string:session_token>/acknowledge_key', methods=['POST'])
@login_required
def acknowledge_session_key(session_token):
    """Potwierdza odebranie i odszyfrowanie klucza sesji przez odbiorcę"""
    
    from models import db, ChatSession
    
    # Pobierz sesję
    session = ChatSession.query.filter_by(session_token=session_token).first()
    
    if not session:
        return jsonify({
            'status': 'error',
            'message': 'Sesja nie istnieje'
        }), 404
    
    # Sprawdź czy użytkownik jest odbiorcą sesji
    if session.recipient_id != current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Tylko odbiorca może potwierdzić klucz sesji'
        }), 403
    
    # Oznacz klucz jako potwierdzony
    session.key_acknowledged = True
    session.last_activity = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Klucz sesji potwierdzony'
    })

# WebSocket endpoint - this will be handled separately by the websocket_handler.py
def start_websocket_server():
    """Start WebSocket server in a separate thread"""
    import threading
    import asyncio
    from websocket_handler import start_websocket_server, ws_handler
    
    # Sprawdź, czy WebSocket jest już uruchomiony
    if hasattr(ws_handler, '_running') and ws_handler._running:
        logger.info("WebSocket server is already running")
        return
    
    # Oznacz jako uruchomiony
    ws_handler._running = True
    
    # Create a new event loop for the thread
    def run_websocket_server():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            logger.info("Starting WebSocket server...")
            loop.run_until_complete(start_websocket_server())
            loop.close()
        except Exception as e:
            logger.error(f"Error in WebSocket server thread: {e}")
            ws_handler._running = False
    
    # Start the server in a separate thread
    thread = threading.Thread(target=run_websocket_server)
    thread.daemon = True
    thread.start()
    
    logger.info("WebSocket server thread started")

def initialize_app(app):
    """Initialize the secure messaging module"""
    # Register the blueprint
    app.register_blueprint(secure_messaging)
    
    # Start WebSocket server
    app.before_first_request(start_websocket_server)
    
    logger.info("Secure messaging module initialized")

def initialize_app(app):
    """Initialize the secure messaging module"""
    # Register the blueprint
    app.register_blueprint(secure_messaging)
    
    # Start WebSocket server
    start_websocket_server()
    
    logger.info("Secure messaging module initialized")
@secure_messaging.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """Wysyła wiadomość do innego użytkownika"""
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ['session_token', 'content', 'iv']):
            return jsonify({
                'status': 'error',
                'message': 'Brak wymaganych parametrów'
            }), 400
        
        session_token = data['session_token']
        content = data['content']
        iv = data['iv']
        header = data.get('header')  # Optional for Double Ratchet
        
        from models import db, ChatSession, Message, User
        
        # Pobierz sesję
        session = ChatSession.query.filter_by(
            session_token=session_token,
            is_active=True
        ).first()
        
        if not session:
            return jsonify({
                'status': 'error',
                'message': 'Sesja nie istnieje lub wygasła'
            }), 404
        
        # Sprawdź czy użytkownik jest uczestnikiem sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({
                'status': 'error',
                'message': 'Brak dostępu do sesji'
            }), 403
        
        # Sprawdź, czy wymiana kluczy została zakończona
        if not session.encrypted_session_key or not session.key_acknowledged:
            return jsonify({
                'status': 'error',
                'message': 'Wymiana kluczy nie została zakończona'
            }), 400
        
        # Określ odbiorcę
        recipient_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        recipient = User.query.get(recipient_id)
        
        if not recipient:
            return jsonify({
                'status': 'error',
                'message': 'Odbiorca nie istnieje'
            }), 404
        
        # Utwórz nową wiadomość
        new_message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            header=header,
            timestamp=datetime.utcnow(),
            read=False
        )
        
        db.session.add(new_message)
        
        # Aktualizuj czas ostatniej aktywności sesji
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        # Powiadom odbiorcę przez WebSocket
        try:
            from websocket_handler import ws_handler
            
            message_data = {
                'id': new_message.id,
                'session_token': session_token,
                'sender_id': current_user.id,
                'content': content,
                'iv': iv,
                'header': header,
                'timestamp': new_message.timestamp.isoformat(),
                'read': False
            }
            
            # Sprawdź, czy WebSocket jest zainicjalizowany
            if hasattr(ws_handler, 'is_user_online') and hasattr(ws_handler, 'send_to_user'):
                if ws_handler.is_user_online(recipient.user_id):
                    logger.info(f"Sending message notification to user {recipient.user_id}")
                    ws_handler.send_to_user(recipient.user_id, {
                        'type': 'new_message',
                        'session_token': session_token,
                        'message': message_data
                    })
                else:
                    logger.info(f"User {recipient.user_id} is offline, message will be delivered when they connect")
            else:
                logger.warning("WebSocket handler not properly initialized")
                
        except Exception as e:
            # Błędy związane z WebSocket nie powinny zatrzymywać procesu
            logger.error(f"Error sending WebSocket notification: {e}")
        
        return jsonify({
            'status': 'success',
            'message': 'Wiadomość wysłana',
            'message_id': new_message.id,
            'timestamp': new_message.timestamp.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending message: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Server error: {str(e)}'
        }), 500
