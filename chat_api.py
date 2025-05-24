from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from models import User, ChatSession, Message, db, Friend, FriendRequest
import datetime
import hashlib
import json
import logging
import secrets
import string

# Konfiguracja logowania
logger = logging.getLogger(__name__)

chat_api = Blueprint('chat_api', __name__)

@chat_api.route('/api/user/<user_id>/public_key', methods=['GET'])
@login_required
def get_user_public_key(user_id):
    """Pobiera klucz publiczny użytkownika"""
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
        
    return jsonify({
        'status': 'success',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key
    })

@chat_api.route('/api/user/<user_id>/info', methods=['GET'])
@login_required
def get_user_info(user_id):
    """Pobiera podstawowe informacje o użytkowniku"""
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
        
    return jsonify({
        'status': 'success',
        'user': {
            'id': user.id,
            'user_id': user.user_id,
            'username': user.username,
            'is_online': user.is_online if hasattr(user, 'is_online') else False
        }
    })

@chat_api.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Pobiera listę wszystkich użytkowników (poza sobą)"""
    users = User.query.filter(User.id != current_user.id).all()
    
    user_list = [{
        'id': user.id,
        'user_id': user.user_id,
        'username': user.username,
        'is_online': user.is_online if hasattr(user, 'is_online') else False
    } for user in users]
    
    return jsonify({
        'status': 'success',
        'users': user_list
    })

@chat_api.route('/api/online_users', methods=['GET'])
@login_required
def get_online_users():
    """Pobiera listę użytkowników online"""
    try:
        # Sprawdź czy kolumna is_online istnieje w modelu
        if hasattr(User, 'is_online'):
            online_users = User.query.filter(User.is_online == True, User.id != current_user.id).all()
            
            user_list = [{
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username,
            } for user in online_users]
            
            return jsonify({
                'status': 'success',
                'online_users': user_list
            })
        else:
            # Jeśli kolumna nie istnieje, zwróć pustą listę
            return jsonify({
                'status': 'success',
                'online_users': [],
                'message': 'Funkcja statusu online nie jest dostępna'
            })
    except Exception as e:
        logger.error(f"Błąd pobierania użytkowników online: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """POPRAWIONA: Inicjuje sesję czatu z automatyczną wymianą kluczy"""
    try:
        data = request.get_json()
        
        recipient_id = data.get('recipient_id')
        if not recipient_id:
            return jsonify({'status': 'error', 'message': 'Nie podano ID adresata'}), 400
            
        # Znajdź użytkownika, do którego chcemy pisać
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'status': 'error', 'message': 'Adresat nie istnieje'}), 404
        
        # POPRAWIONE: Sprawdź czy nie istnieje już aktywna sesja
        existing_session = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient.id)) |
            ((ChatSession.initiator_id == recipient.id) & (ChatSession.recipient_id == current_user.id))
        ).filter(
            ChatSession.is_active == True, 
            ChatSession.expires_at > datetime.datetime.utcnow()
        ).first()
        
        if existing_session:
            logger.info(f"Znaleziono istniejącą sesję {existing_session.session_token}")
            
            # NOWE: Sprawdź stan wymiany kluczy
            has_encrypted_key = existing_session.encrypted_session_key is not None
            key_acknowledged = existing_session.key_acknowledged or False
            needs_key_exchange = not has_encrypted_key or not key_acknowledged
            
            # Odśwież sesję
            existing_session.last_activity = datetime.datetime.utcnow()
            existing_session.expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
            db.session.commit()
            
            # Określ drugiego uczestnika sesji
            other_user = recipient if existing_session.initiator_id == current_user.id else User.query.get(existing_session.initiator_id)
            
            response_data = {
                'status': 'success',
                'message': 'Sesja istnieje',
                'session': {
                    'id': existing_session.id,
                    'token': existing_session.session_token,
                    'expires_at': existing_session.expires_at.isoformat(),
                    'initiator_id': existing_session.initiator_id,
                    'recipient_id': existing_session.recipient_id,
                    'has_key': has_encrypted_key,
                    'key_acknowledged': key_acknowledged,
                    'needs_key_exchange': needs_key_exchange,
                    'is_initiator': existing_session.initiator_id == current_user.id,
                    'other_user': {
                        'id': other_user.id,
                        'user_id': other_user.user_id,
                        'username': other_user.username,
                        'is_online': other_user.is_online if hasattr(other_user, 'is_online') else False
                    }
                }
            }
            
            # NOWE: Jeśli potrzebna wymiana kluczy, powiadom o tym frontend
            if needs_key_exchange:
                response_data['session']['auto_start_key_exchange'] = True
                logger.info(f"Sesja {existing_session.session_token} wymaga wymiany kluczy")
            
            return jsonify(response_data)
        
        # NOWE: Tworzenie nowej sesji z flagą do automatycznej wymiany kluczy
        session_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        
        new_session = ChatSession(
            session_token=session_token,
            initiator_id=current_user.id,
            recipient_id=recipient.id,
            created_at=datetime.datetime.utcnow(),
            last_activity=datetime.datetime.utcnow(),
            expires_at=expires_at,
            is_active=True,
            encrypted_session_key=None,  # Będzie ustawiony przez wymianę kluczy
            key_acknowledged=False
        )
        
        db.session.add(new_session)
        db.session.commit()
        
        logger.info(f"Utworzono nową sesję {session_token} między {current_user.user_id} a {recipient.user_id}")
        
        # NOWE: Powiadom drugiego użytkownika o nowej sesji przez WebSocket
        try:
            from websocket_handler import ws_handler
            if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(recipient.user_id):
                ws_handler.send_to_user(recipient.user_id, {
                    'type': 'new_session_created',
                    'session_token': session_token,
                    'initiator': {
                        'id': current_user.id,
                        'user_id': current_user.user_id,
                        'username': current_user.username
                    },
                    'timestamp': datetime.datetime.utcnow().isoformat()
                })
                logger.info(f"Powiadomiono {recipient.user_id} o nowej sesji")
        except Exception as ws_error:
            logger.error(f"Błąd WebSocket podczas powiadomienia o sesji: {ws_error}")
        
        return jsonify({
            'status': 'success',
            'message': 'Nowa sesja utworzona',
            'session': {
                'id': new_session.id,
                'token': new_session.session_token,
                'expires_at': new_session.expires_at.isoformat(),
                'initiator_id': new_session.initiator_id,
                'recipient_id': new_session.recipient_id,
                'has_key': False,
                'key_acknowledged': False,
                'needs_key_exchange': True,
                'auto_start_key_exchange': True,  # NOWE: Flaga dla frontendu
                'is_initiator': True,
                'other_user': {
                    'id': recipient.id,
                    'user_id': recipient.user_id,
                    'username': recipient.username,
                    'is_online': recipient.is_online if hasattr(recipient, 'is_online') else False
                }
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd inicjacji sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/validate', methods=['GET'])
@login_required
def validate_session(session_token):
    """POPRAWIONA: Sprawdza ważność sesji czatu i automatycznie inicjuje wymianę kluczy"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
            
        # Sprawdź ważność sesji
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
            
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        # NOWE: Szczegółowe sprawdzenie stanu kluczy
        has_encrypted_key = session.encrypted_session_key is not None
        key_acknowledged = session.key_acknowledged or False
        needs_key_exchange = not has_encrypted_key or not key_acknowledged
        is_initiator = session.initiator_id == current_user.id
        
        # Znajdź drugiego uczestnika
        other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        other_user = User.query.get(other_user_id)
        
        response_data = {
            'status': 'success',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'initiator_id': session.initiator_id,
                'recipient_id': session.recipient_id,
                'is_valid': True,
                'has_key': has_encrypted_key,
                'key_acknowledged': key_acknowledged,
                'needs_key_exchange': needs_key_exchange,
                'is_initiator': is_initiator,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': other_user.is_online if hasattr(other_user, 'is_online') else False
                }
            }
        }
        
        # NOWE: Jeśli potrzebujesz wymiany kluczy i jesteś inicjatorem
        if needs_key_exchange and is_initiator:
            response_data['session']['should_generate_key'] = True
            logger.info(f"Sesja {session_token}: inicjator powinien wygenerować klucz")
        elif needs_key_exchange and not is_initiator:
            response_data['session']['should_wait_for_key'] = True
            logger.info(f"Sesja {session_token}: odbiorca czeka na klucz")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Błąd walidacji sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/exchange_key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """POPRAWIONA: Przesyła zaszyfrowany klucz sesji z powiadomieniami real-time"""
    try:
        data = request.get_json()
        encrypted_key = data.get('encrypted_key')
        
        if not encrypted_key:
            return jsonify({'status': 'error', 'message': 'Brak klucza sesji'}), 400
            
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź, czy użytkownik jest uczestnikiem sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
        
        # NOWE: Tylko inicjator może wysłać klucz (lub jeśli nie ma jeszcze klucza)
        if session.encrypted_session_key and session.initiator_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Klucz już został ustawiony'}), 409
            
        # Zapisz zaszyfrowany klucz sesji
        session.encrypted_session_key = encrypted_key
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Klucz sesji zapisany dla {session_token}")
        
        # POPRAWIONE: Powiadom drugiego użytkownika z dodatkowymi informacjami
        try:
            recipient_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            recipient = User.query.get(recipient_id)
            
            from websocket_handler import ws_handler
            if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(recipient.user_id):
                notification_data = {
                    'type': 'session_key_received',
                    'session_token': session_token,
                    'encrypted_key': encrypted_key,
                    'sender_id': current_user.user_id,
                    'sender_username': current_user.username,
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'action_required': 'acknowledge_key'
                }
                
                ws_handler.send_to_user(recipient.user_id, notification_data)
                logger.info(f"Powiadomiono {recipient.user_id} o nowym kluczu sesji")
        except Exception as ws_error:
            logger.error(f"Błąd WebSocket podczas wymiany klucza: {ws_error}")
        
        return jsonify({
            'status': 'success',
            'message': 'Klucz sesji przesłany',
            'next_step': 'wait_for_acknowledgment'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd wymiany klucza sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/key', methods=['GET'])
@login_required
def get_session_key(session_token):
    """POPRAWIONA: Pobiera zaszyfrowany klucz sesji z dodatkowymi informacjami"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
            
        # Sprawdź czy klucz sesji istnieje
        if not session.encrypted_session_key:
            return jsonify({
                'status': 'error', 
                'message': 'Klucz sesji nie został jeszcze przesłany',
                'should_wait': True
            }), 404
            
        # NOWE: Dodatkowe informacje o stanie sesji
        is_initiator = session.initiator_id == current_user.id
        other_user_id = session.recipient_id if is_initiator else session.initiator_id
        other_user = User.query.get(other_user_id)
        
        return jsonify({
            'status': 'success',
            'encrypted_key': session.encrypted_session_key,
            'session_info': {
                'is_initiator': is_initiator,
                'key_acknowledged': session.key_acknowledged,
                'other_user': {
                    'user_id': other_user.user_id,
                    'username': other_user.username
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Błąd pobierania klucza sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/acknowledge_key', methods=['POST'])
@login_required
def acknowledge_session_key(session_token):
    """POPRAWIONA: Potwierdza odebranie klucza sesji z powiadomieniami real-time"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem sesji (nie tylko odbiorcą)
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
        
        # POPRAWIONE: Sprawdź czy klucz istnieje
        if not session.encrypted_session_key:
            return jsonify({'status': 'error', 'message': 'Brak klucza do potwierdzenia'}), 400
            
        # Oznacz klucz jako potwierdzony
        session.key_acknowledged = True
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Klucz sesji {session_token} potwierdzony przez {current_user.user_id}")
        
        # POPRAWIONE: Powiadom wszystkich uczestników o zakończeniu wymiany kluczy
        try:
            from websocket_handler import ws_handler
            
            # Powiadom drugiego uczestnika
            other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            other_user = User.query.get(other_user_id)
            
            if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(other_user.user_id):
                ws_handler.send_to_user(other_user.user_id, {
                    'type': 'key_exchange_completed',
                    'session_token': session_token,
                    'acknowledged_by': current_user.user_id,
                    'acknowledged_by_username': current_user.username,
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'status': 'ready_for_messaging'
                })
                logger.info(f"Powiadomiono {other_user.user_id} o zakończeniu wymiany kluczy")
                
        except Exception as ws_error:
            logger.error(f"Błąd WebSocket podczas potwierdzania klucza: {ws_error}")
        
        return jsonify({
            'status': 'success',
            'message': 'Klucz sesji potwierdzony',
            'session_status': 'ready_for_messaging'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd potwierdzania klucza sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """POPRAWIONA: Wysyła wiadomość z lepszymi powiadomieniami real-time"""
    try:
        data = request.get_json()
        
        # Sprawdź wymagane pola
        required_fields = ['session_token', 'content', 'iv']
        if not data or not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error', 
                'message': 'Brakujące wymagane dane'
            }), 400
            
        session_token = data.get('session_token')
        content = data.get('content')  # Zaszyfrowana treść
        iv = data.get('iv')  # Wektor inicjalizacyjny
        mentions = data.get('mentions', [])  # Lista wzmianek (@username)
        
        # Pobierz sesję
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({
                'status': 'error', 
                'message': 'Nieprawidłowa sesja'
            }), 404
            
        # Sprawdź, czy sesja jest aktywna
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({
                'status': 'error', 
                'message': 'Sesja wygasła'
            }), 401
            
        # POPRAWIONE: Sprawdź czy wymiana kluczy została zakończona
        if not session.encrypted_session_key or not session.key_acknowledged:
            return jsonify({
                'status': 'error', 
                'message': 'Wymiana kluczy nie została zakończona. Poczekaj na zakończenie procesu.',
                'needs_key_exchange': True
            }), 400
            
        # Sprawdź, czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({
                'status': 'error', 
                'message': 'Brak dostępu do tej sesji'
            }), 403
        
        # Zapisz wiadomość
        new_message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            timestamp=datetime.datetime.utcnow()
        )
        
        db.session.add(new_message)
        
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
        
        # Commit przed wysłaniem powiadomień
        db.session.commit()
        
        logger.info(f"Wiadomość zapisana: ID {new_message.id} w sesji {session_token}")
        
        # POPRAWIONE: Natychmiast powiadom odbiorcę
        try:
            recipient_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            recipient = User.query.get(recipient_id)
            
            from websocket_handler import ws_handler
            if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(recipient.user_id):
                message_data = {
                    'type': 'new_message',
                    'session_token': session_token,
                    'message': {
                        'id': new_message.id,
                        'sender_id': current_user.id,
                        'sender_username': current_user.username,
                        'content': content,
                        'iv': iv,
                        'timestamp': new_message.timestamp.isoformat(),
                        'is_mine': False
                    },
                    'session_info': {
                        'other_user': {
                            'user_id': current_user.user_id,
                            'username': current_user.username
                        }
                    }
                }
                
                success = ws_handler.send_to_user(recipient.user_id, message_data)
                if success:
                    logger.info(f"Powiadomiono {recipient.user_id} o nowej wiadomości")
                else:
                    logger.warning(f"Nie udało się powiadomić {recipient.user_id}")
        except Exception as ws_error:
            logger.error(f"Błąd WebSocket podczas wysyłania wiadomości: {ws_error}")
        
        # Obsługa wzmianek (bez zmian)
        if mentions and len(mentions) > 0:
            for username in mentions:
                mentioned_user = User.query.filter_by(username=username).first()
                
                if mentioned_user:
                    try:
                        from websocket_handler import ws_handler
                        if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(mentioned_user.user_id):
                            ws_handler.send_to_user(mentioned_user.user_id, {
                                'type': 'mention_notification',
                                'from_user': {
                                    'id': current_user.id,
                                    'user_id': current_user.user_id,
                                    'username': current_user.username
                                },
                                'session_token': session_token,
                                'message_id': new_message.id,
                                'timestamp': datetime.datetime.utcnow().isoformat()
                            })
                    except Exception as e:
                        logger.error(f"Błąd wysyłania powiadomienia o wzmiance: {e}")
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': new_message.id,
                'timestamp': new_message.timestamp.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd wysyłania wiadomości: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/messages/<session_token>', methods=['GET'])
@login_required
def get_messages(session_token):
    """POPRAWIONA: Pobiera wiadomości z sesji z automatycznym oznaczaniem jako przeczytane"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
            
        # Sprawdź ważność sesji
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
        
        # Pobierz wiadomości
        messages = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).all()
        
        # POPRAWIONE: Oznacz nieswoje wiadomości jako przeczytane i powiadom nadawcę
        other_user_id = session.initiator_id if session.recipient_id == current_user.id else session.recipient_id
        unread_messages = Message.query.filter_by(
            session_id=session.id,
            sender_id=other_user_id,
            read=False
        ).all()
        
        if unread_messages:
            for msg in unread_messages:
                msg.read = True
            
            db.session.commit()
            logger.info(f"Oznaczono {len(unread_messages)} wiadomości jako przeczytane w sesji {session_token}")
            
            # NOWE: Powiadom nadawcę o przeczytaniu wiadomości
            try:
                from websocket_handler import ws_handler
                other_user = User.query.get(other_user_id)
                
                if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(other_user.user_id):
                    ws_handler.send_to_user(other_user.user_id, {
                        'type': 'messages_read',
                        'session_token': session_token,
                        'read_by': current_user.user_id,
                        'read_by_username': current_user.username,
                        'message_count': len(unread_messages),
                        'timestamp': datetime.datetime.utcnow().isoformat()
                    })
                    logger.info(f"Powiadomiono {other_user.user_id} o przeczytaniu wiadomości")
            except Exception as ws_error:
                logger.error(f"Błąd powiadomienia o przeczytaniu: {ws_error}")
        
        message_list = [{
            'id': msg.id,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'iv': msg.iv,
            'timestamp': msg.timestamp.isoformat(),
            'is_mine': msg.sender_id == current_user.id,
            'read': msg.read
        } for msg in messages]
        
        return jsonify({
            'status': 'success',
            'messages': message_list,
            'session_info': {
                'token': session_token,
                'total_messages': len(message_list),
                'unread_marked': len(unread_messages)
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd pobierania wiadomości: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/sessions/active', methods=['GET'])
@login_required
def get_active_sessions():
    """POPRAWIONA: Pobiera aktywne sesje z dodatkowymi informacjami o stanie kluczy"""
    try:
        # Pobierz aktywne sesje
        active_sessions = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.datetime.utcnow()
        ).order_by(ChatSession.last_activity.desc()).all()
        
        session_list = []
        for session in active_sessions:
            # Określ drugiego uczestnika
            other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            other_user = User.query.get(other_user_id)
            
            # Policz nieprzeczytane wiadomości
            unread_count = Message.query.filter_by(
                session_id=session.id,
                sender_id=other_user_id,
                read=False
            ).count()
            
            # NOWE: Sprawdź stan wymiany kluczy
            has_encrypted_key = session.encrypted_session_key is not None
            key_acknowledged = session.key_acknowledged or False
            is_ready = has_encrypted_key and key_acknowledged
            needs_key_exchange = not is_ready
            is_initiator = session.initiator_id == current_user.id
            
            # Pobierz ostatnią wiadomość
            last_message = Message.query.filter_by(session_id=session.id)\
                .order_by(Message.timestamp.desc()).first()
            
            session_data = {
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'has_key': has_encrypted_key,
                'key_acknowledged': key_acknowledged,
                'is_ready': is_ready,
                'needs_key_exchange': needs_key_exchange,
                'is_initiator': is_initiator,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': other_user.is_online if hasattr(other_user, 'is_online') else False
                },
                'unread_count': unread_count,
                'last_message': None
            }
            
            # NOWE: Dodaj informacje o ostatniej wiadomości (jeśli istnieje)
            if last_message:
                session_data['last_message'] = {
                    'id': last_message.id,
                    'sender_id': last_message.sender_id,
                    'timestamp': last_message.timestamp.isoformat(),
                    'is_mine': last_message.sender_id == current_user.id,
                    'read': last_message.read
                }
            
            session_list.append(session_data)
        
        return jsonify({
            'status': 'success',
            'sessions': session_list,
            'total_sessions': len(session_list),
            'ready_sessions': len([s for s in session_list if s['is_ready']]),
            'pending_key_exchange': len([s for s in session_list if s['needs_key_exchange']])
        })
        
    except Exception as e:
        logger.error(f"Błąd pobierania aktywnych sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/close', methods=['POST'])
@login_required
def close_session(session_token):
    """POPRAWIONA: Zamyka sesję czatu z powiadomieniem drugiego użytkownika"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
        
        # Znajdź drugiego użytkownika przed zamknięciem
        other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        other_user = User.query.get(other_user_id)
        
        # Zamknij sesję
        session.is_active = False
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Sesja {session_token} zamknięta przez {current_user.user_id}")
        
        # NOWE: Powiadom drugiego użytkownika o zamknięciu sesji
        try:
            from websocket_handler import ws_handler
            if hasattr(ws_handler, 'is_user_online') and ws_handler.is_user_online(other_user.user_id):
                ws_handler.send_to_user(other_user.user_id, {
                    'type': 'session_closed',
                    'session_token': session_token,
                    'closed_by': current_user.user_id,
                    'closed_by_username': current_user.username,
                    'timestamp': datetime.datetime.utcnow().isoformat()
                })
                logger.info(f"Powiadomiono {other_user.user_id} o zamknięciu sesji")
        except Exception as ws_error:
            logger.error(f"Błąd powiadomienia o zamknięciu sesji: {ws_error}")
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja zamknięta'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd zamykania sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

# === ZNAJOMI - BEZ ZMIAN ===

@chat_api.route('/api/friends', methods=['GET'])
@login_required
def get_friends():
    """Pobiera listę znajomych użytkownika"""
    try:
        # Użyj metody z modelu User
        if hasattr(current_user, 'get_friends'):
            friends = current_user.get_friends()
        else:
            # Zapasowa implementacja jeśli metoda nie istnieje
            from models import Friend
            friend_records = Friend.query.filter_by(user_id=current_user.id).all()
            friend_ids = [friend.friend_id for friend in friend_records]
            friends = User.query.filter(User.id.in_(friend_ids)).all() if friend_ids else []
        
        friends_list = [{
            'id': friend.id,
            'user_id': friend.user_id,
            'username': friend.username,
            'is_online': friend.is_online if hasattr(friend, 'is_online') else False
        } for friend in friends]
        
        return jsonify({
            'status': 'success',
            'friends': friends_list
        })
    except Exception as e:
        logger.error(f"Błąd pobierania znajomych: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/api/friend_requests', methods=['POST'])
@login_required
def send_friend_request():
    """Wysyła zaproszenie do znajomych"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Brak danych w żądaniu'
            }), 400
        
        # Obsługa zarówno username jak i recipient_id
        if 'username' in data:
            username = data['username']
            recipient = User.query.filter_by(username=username).first()
        elif 'recipient_id' in data:
            recipient_id = data['recipient_id']
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
        if current_user.is_friend_with(recipient.id):
            return jsonify({
                'status': 'error',
                'message': 'Użytkownicy są już znajomymi'
            }), 400
        
        # Utwórz nowe zaproszenie
        new_request = FriendRequest(
            from_user_id=current_user.id,
            to_user_id=recipient.id,
            status='pending',
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
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
                    'timestamp': datetime.datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Błąd podczas wysyłania powiadomienia: {e}")
        
        return jsonify({
            'status': 'success',
            'message': 'Zaproszenie do znajomych wysłane',
            'request_id': new_request.id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd podczas wysyłania zaproszenia: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Błąd serwera: {str(e)}'
        }), 500

@chat_api.route('/api/friend_requests/pending', methods=['GET'])
@login_required
def get_pending_requests():
    """Pobiera listę oczekujących zaproszeń dla zalogowanego użytkownika"""
    try:
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
    except Exception as e:
        logger.error(f"Błąd pobierania oczekujących zaproszeń: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Błąd serwera: {str(e)}'
        }), 500

@chat_api.route('/api/friend_requests/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """Akceptuje zaproszenie do znajomych"""
    try:
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
        friend_request.status = 'accepted'
        friend_request.updated_at = datetime.datetime.utcnow()
        
        # Utwórz relacje znajomości (w obie strony)
        friend1 = Friend(
            user_id=current_user.id,
            friend_id=friend_request.from_user_id,
            created_at=datetime.datetime.utcnow()
        )
        
        friend2 = Friend(
            user_id=friend_request.from_user_id,
            friend_id=current_user.id,
            created_at=datetime.datetime.utcnow()
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
                        'is_online': current_user.is_online if hasattr(current_user, 'is_online') else False
                    },
                    'timestamp': datetime.datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Błąd podczas wysyłania powiadomienia: {e}")
        
        return jsonify({
            'status': 'success',
            'message': 'Zaproszenie zaakceptowane'
        })
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd akceptacji zaproszenia: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Błąd podczas akceptacji zaproszenia'
        }), 500

@chat_api.route('/api/friend_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """Odrzuca zaproszenie do znajomych"""
    try:
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
        friend_request.updated_at = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Zaproszenie odrzucone'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd odrzucania zaproszenia: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Błąd podczas odrzucania zaproszenia: {str(e)}'
        }), 500

# === POLLING FALLBACK - BEZ ZMIAN ===

@chat_api.route('/api/polling/messages', methods=['GET'])
@login_required
def polling_messages():
    """Endpoint fallback do odbierania wiadomości poprzez polling."""
    try:
        # Pobierz ostatnie znane ID wiadomości
        last_id = request.args.get('last_id', 0)
        try:
            last_id = int(last_id)
        except ValueError:
            last_id = 0
        
        # Znajdź aktywne sesje użytkownika
        active_sessions = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.datetime.utcnow()
        ).all()
        
        # IDs sesji
        session_ids = [session.id for session in active_sessions]
        
        # Pobierz nowe wiadomości
        new_messages = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.id > last_id,
            Message.sender_id != current_user.id,
            Message.read == False
        ).order_by(Message.id).all()
        
        # Dane wiadomości do zwrócenia
        messages = []
        max_id = last_id
        
        for msg in new_messages:
            # Znajdź sesję dla tej wiadomości
            session = next((s for s in active_sessions if s.id == msg.session_id), None)
            if session:
                # Zbuduj informację o wiadomości
                max_id = max(max_id, msg.id)
                messages.append({
                    'type': 'new_message',
                    'session_token': session.session_token,
                    'message': {
                        'id': msg.id,
                        'sender_id': msg.sender_id,
                        'content': msg.content,
                        'iv': msg.iv,
                        'timestamp': msg.timestamp.isoformat(),
                        'is_mine': False
                    }
                })
        
        return jsonify({
            'status': 'success',
            'messages': messages,
            'last_id': max_id
        })
    
    except Exception as e:
        logger.error(f"Błąd pollingu wiadomości: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
