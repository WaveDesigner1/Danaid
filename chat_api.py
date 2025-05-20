from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from models import User, ChatSession, Message, db
import datetime
import hashlib
import json

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

@chat_api.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Pobiera listę wszystkich użytkowników (poza sobą)"""
    users = User.query.filter(User.id != current_user.id).all()
    
    user_list = [{
        'id': user.id,
        'user_id': user.user_id,
        'username': user.username,
        
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """Inicjuje nową sesję czatu z innym użytkownikiem"""
    try:
        data = request.get_json()
        
        recipient_id = data.get('recipient_id')
        if not recipient_id:
            return jsonify({'status': 'error', 'message': 'Nie podano ID adresata'}), 400
            
        # Znajdź użytkownika, do którego chcemy pisać
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'status': 'error', 'message': 'Adresat nie istnieje'}), 404
            
        # Sprawdź, czy nie ma już aktywnej sesji między tymi użytkownikami
        existing_session = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient.id)) |
            ((ChatSession.initiator_id == recipient.id) & (ChatSession.recipient_id == current_user.id))
        ).filter(ChatSession.is_active == True, ChatSession.expires_at > datetime.datetime.utcnow()).first()
        
        if existing_session:
            # Zwróć informację czy istnieje już wymieniony klucz
            has_key = existing_session.encrypted_session_key is not None
            key_acknowledged = existing_session.key_acknowledged
            
            # Jeśli istnieje aktywna sesja, odśwież ją
            existing_session.refresh_session()
            
            return jsonify({
                'status': 'success',
                'message': 'Sesja odświeżona',
                'session': {
                    'id': existing_session.id,
                    'token': existing_session.session_token,
                    'expires_at': existing_session.expires_at.isoformat(),
                    'initiator_id': existing_session.initiator_id,
                    'recipient_id': existing_session.recipient_id,
                    'has_key': has_key,
                    'key_acknowledged': key_acknowledged
                }
            })
        
        # Utwórz nową sesję
        new_session = ChatSession.create_session(current_user.id, recipient.id)
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja utworzona',
            'session': {
                'id': new_session.id,
                'token': new_session.session_token,
                'expires_at': new_session.expires_at.isoformat(),
                'initiator_id': new_session.initiator_id,
                'recipient_id': new_session.recipient_id,
                'has_key': False,
                'key_acknowledged': False
            }
        }), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/validate', methods=['GET'])
@login_required
def validate_session(session_token):
    """Sprawdza ważność sesji czatu"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
            
        # Sprawdź ważność sesji
        if not session.is_valid:
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
            
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        has_key = session.encrypted_session_key is not None
        
        return jsonify({
            'status': 'success',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'initiator_id': session.initiator_id,
                'recipient_id': session.recipient_id,
                'is_valid': session.is_valid,
                'has_key': has_key,
                'key_acknowledged': session.key_acknowledged
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/close', methods=['POST'])
@login_required
def close_session(session_token):
    """Zamyka sesję czatu"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
            
        # Zamknij sesję
        session.invalidate()
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja zamknięta'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/exchange_key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """Przesyła zaszyfrowany klucz sesji dla odbiorcy"""
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
            
        # Zapisz zaszyfrowany klucz sesji
        session.encrypted_session_key = encrypted_key
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Klucz sesji przesłany'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/key', methods=['GET'])
@login_required
def get_session_key(session_token):
    """Pobiera zaszyfrowany klucz sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
            
        # Sprawdź czy klucz sesji istnieje
        if not session.encrypted_session_key:
            return jsonify({'status': 'error', 'message': 'Klucz sesji nie został jeszcze przesłany'}), 404
            
        return jsonify({
            'status': 'success',
            'encrypted_key': session.encrypted_session_key
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/session/<session_token>/acknowledge_key', methods=['POST'])
@login_required
def acknowledge_session_key(session_token):
    """Potwierdza odebranie i odszyfrowanie klucza sesji przez odbiorcę"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest odbiorcą sesji
        if session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Tylko odbiorca może potwierdzić klucz sesji'}), 403
            
        # Oznacz klucz jako potwierdzony
        session.key_acknowledged = True
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Klucz sesji potwierdzony'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500
@chat_api.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """Wysyła zaszyfrowaną wiadomość z obsługą wzmianek"""
    try:
        data = request.get_json()
        
        session_token = data.get('session_token')
        content = data.get('content')  # Zaszyfrowana treść
        iv = data.get('iv')  # Wektor inicjalizacyjny
        mentions = data.get('mentions', [])  # Lista wzmianek (@username)
        
        if not all([session_token, content, iv]):
            return jsonify({'status': 'error', 'message': 'Brakujące dane'}), 400
            
        # Pobierz sesję
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Nieprawidłowa sesja'}), 404
            
        # Sprawdź, czy sesja jest aktywna
        if not session.is_valid:
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
            
        # Sprawdź, czy klucz sesji został potwierdzony
        if not session.key_acknowledged:
            return jsonify({'status': 'error', 'message': 'Wymiana kluczy nie została zakończona'}), 400
            
        # Sprawdź, czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
        
        # Zapisz wiadomość
        new_message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv
        )
        
        db.session.add(new_message)
        
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
        
        # Obsługa wzmianek - powiadomienia dla wspomnianych użytkowników
        if mentions and len(mentions) > 0:
            for username in mentions:
                # Znajdź użytkownika po nazwie
                mentioned_user = User.query.filter_by(username=username).first()
                
                if mentioned_user:
                    # Jeśli użytkownik istnieje i mamy dostęp do handlera WebSocket
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
                    except (ImportError, AttributeError, Exception) as e:
                        # Błędy związane z WebSocket nie powinny zatrzymywać całego procesu
                        print(f"Ostrzeżenie: Nie można wysłać powiadomienia o wzmiance: {e}")
        
        # Zakończ transakcję
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': new_message.id,
                'timestamp': new_message.timestamp.isoformat()
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/messages/<session_token>', methods=['GET'])
@login_required
def get_messages(session_token):
    """Pobiera wiadomości z sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Sprawdź czy użytkownik jest uczestnikiem tej sesji
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
            
        # Sprawdź ważność sesji
        if not session.is_valid:
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
        
        # Pobierz wiadomości
        messages = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).all()
        
        # Oznacz wszystkie nieswoje wiadomości jako przeczytane
        unread_messages = Message.query.filter_by(
            session_id=session.id,
            sender_id=session.initiator_id if session.recipient_id == current_user.id else session.recipient_id,
            read=False
        ).all()
        
        for msg in unread_messages:
            msg.read = True
        
        db.session.commit()
        
        message_list = [{
            'id': msg.id,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'iv': msg.iv,
            'timestamp': msg.timestamp.isoformat(),
            'is_mine': msg.sender_id == current_user.id
        } for msg in messages]
        
        return jsonify({
            'status': 'success',
            'messages': message_list
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

@chat_api.route('/api/sessions/active', methods=['GET'])
@login_required
def get_active_sessions():
    """Pobiera wszystkie aktywne sesje czatu dla użytkownika"""
    try:
        sessions = ChatSession.get_active_sessions(current_user.id)
        
        session_list = []
        for session in sessions:
            # Ustal drugiego użytkownika
            other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            other_user = User.query.get(other_user_id)
            
            # Policz nieprzeczytane wiadomości
            unread_count = Message.query.filter_by(
                session_id=session.id,
                sender_id=other_user_id,
                read=False
            ).count()
            
            session_list.append({
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'has_key': session.encrypted_session_key is not None,
                'key_acknowledged': session.key_acknowledged,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username
                },
                'unread_count': unread_count
            })
        
        return jsonify({
            'status': 'success',
            'sessions': session_list
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500
