"""
chat.py - Zunifikowany moduł czatu (scalenie starego i nowego systemu)
Obsługuje zarówno stary system (encrypted_session_key) jak i nowy (dual encryption)
"""
import json
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_
from models import db, ChatSession, Message, User, Friend, FriendRequest
import logging

logger = logging.getLogger(__name__)
chat_bp = Blueprint('chat', __name__)

# === VIEWS ===
@chat_bp.route('/chat')
@login_required
def chat():
    """Główna strona czatu"""
    return render_template('chat.html')

# === HELPER FUNCTIONS ===
def _generate_session_token():
    """Generuje bezpieczny token sesji"""
    return secrets.token_urlsafe(32)

def _find_or_create_session(recipient_id):
    """Znajduje lub tworzy sesję czatu"""
    # Sprawdź istniejącą aktywną sesję
    existing = ChatSession.query.filter(
        or_(
            (ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient_id),
            (ChatSession.initiator_id == recipient_id) & (ChatSession.recipient_id == current_user.id)
        ),
        ChatSession.is_active == True,
        ChatSession.expires_at > datetime.utcnow()
    ).first()
    
    if existing:
        # Odśwież istniejącą sesję
        existing.last_activity = datetime.utcnow()
        existing.expires_at = datetime.utcnow() + timedelta(days=7)  # Nowy standard: 7 dni
        db.session.commit()
        return existing
    
    # Utwórz nową sesję
    new_session = ChatSession(
        session_token=_generate_session_token(),
        initiator_id=current_user.id,
        recipient_id=recipient_id,
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.session.add(new_session)
    db.session.commit()
    return new_session

# === SESSION API (NOWY + STARY) ===

@chat_bp.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """Inicjuje sesję czatu - ZMODERNIZOWANE"""
    try:
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        
        if not recipient_id:
            return jsonify({'error': 'Recipient ID required'}), 400
        
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        session = _find_or_create_session(recipient.id)
        
        return jsonify({
            'status': 'success',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'initiator_id': session.initiator_id,
                'recipient_id': session.recipient_id,
                'expires_at': session.expires_at.isoformat(),
                'has_key': bool(session.encrypted_keys_json or session.encrypted_session_key),  # Backward compatibility
                'key_acknowledged': session.key_acknowledged,
                'other_user': {
                    'id': recipient.id,
                    'user_id': recipient.user_id,
                    'username': recipient.username,
                    'is_online': getattr(recipient, 'is_online', False)
                }
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/exchange_key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """Wymiana klucza sesji - NOWY SYSTEM z backward compatibility"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        # NOWY SYSTEM: Klucze dla każdego użytkownika osobno
        if 'keys' in data:
            encrypted_keys = data.get('keys', {})
            
            if not encrypted_keys or not isinstance(encrypted_keys, dict):
                return jsonify({'error': 'Invalid keys format'}), 400
            
            # Walidacja kluczy dla uczestników sesji
            expected_users = {str(session.initiator_id), str(session.recipient_id)}
            provided_users = set(encrypted_keys.keys())
            
            if not expected_users.issubset(provided_users):
                return jsonify({'error': f'Keys required for users: {expected_users}'}), 400
            
            # Zapobiegaj nadpisaniu chyba że wymuszone
            if session.encrypted_keys_json and not data.get('force_overwrite', False):
                return jsonify({'error': 'Keys already exist'}), 409
            
            session.set_encrypted_keys(encrypted_keys, current_user.id)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'key_generator': current_user.user_id,
                'users_with_keys': list(encrypted_keys.keys()),
                'system': 'dual_encryption'
            })
        
        # STARY SYSTEM: Jeden klucz dla wszystkich (backward compatibility)
        elif 'encrypted_key' in data:
            encrypted_key = data.get('encrypted_key')
            
            if not encrypted_key:
                return jsonify({'error': 'Missing encrypted key'}), 400
            
            session.encrypted_session_key = encrypted_key
            session.last_activity = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': 'Key exchanged (legacy system)',
                'system': 'legacy'
            })
        
        else:
            return jsonify({'error': 'No valid key data provided'}), 400
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/key')
@login_required
def get_session_key(session_token):
    """Pobiera klucz sesji - NOWY SYSTEM z fallback"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        # NOWY SYSTEM: Spróbuj pobrać klucz dla konkretnego użytkownika
        encrypted_key = session.get_encrypted_key_for_user(current_user.id)
        
        if encrypted_key:
            return jsonify({
                'status': 'success',
                'encrypted_key': encrypted_key,
                'key_generator': session.key_generator.user_id if session.key_generator else None,
                'system': 'dual_encryption' if session.encrypted_keys_json else 'legacy'
            })
        
        return jsonify({'error': 'No key available'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/validate')
@login_required
def validate_session(session_token):
    """Waliduje sesję"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
            
        if not session.is_active or session.expires_at < datetime.utcnow():
            return jsonify({'error': 'Session expired'}), 401
            
        # Odśwież sesję
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        other_user = User.query.get(other_user_id)
        
        return jsonify({
            'status': 'success',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'is_valid': True,
                'has_key': session.has_key_for_user(current_user.id),
                'key_acknowledged': session.key_acknowledged,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': getattr(other_user, 'is_online', False)
                }
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/sessions/active')
@login_required
def get_active_sessions():
    """Lista aktywnych sesji"""
    try:
        sessions = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            ),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        session_list = []
        for session in sessions:
            other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            other_user = User.query.get(other_user_id)
            
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
                'has_key': session.has_key_for_user(current_user.id),
                'key_acknowledged': session.key_acknowledged,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': getattr(other_user, 'is_online', False)
                },
                'unread_count': unread_count
            })
        
        return jsonify({'status': 'success', 'sessions': session_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/close', methods=['POST'])
@login_required
def close_session(session_token):
    """Zamyka sesję"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
            
        session.is_active = False
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Session closed'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/acknowledge_key', methods=['POST'])
@login_required
def acknowledge_session_key(session_token):
    """Potwierdza odbiór klucza sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
            
        session.key_acknowledged = True
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Key acknowledged'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# === MESSAGES API ===

@chat_bp.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """Wysyła wiadomość - ZMODERNIZOWANE"""
    try:
        print("📨 Send message endpoint called")
        data = request.get_json()
        print("Request data:", data)
        
        session_token = data.get('session_token')
        content = data.get('content')
        iv = data.get('iv')
        
        if not all([session_token, content, iv]):
            return jsonify({'error': 'Missing required fields'}), 400
            
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if not session.is_active or session.expires_at < datetime.utcnow():
            return jsonify({'error': 'Session expired'}), 401
            
        # Sprawdź czy sesja ma klucz (nowy lub stary system)
        if not (session.encrypted_keys_json or session.encrypted_session_key):
            return jsonify({'error': 'No encryption key available'}), 400
            
        print("✅ Validation passed, saving message")
        
        # Utwórz wiadomość
        message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            is_encrypted=True
        )
        db.session.add(message)
        
        # Odśwież aktywność sesji
        session.last_activity = datetime.utcnow()
        
        # Automatycznie potwierdź klucz jeśli jeszcze nie potwierdzony
        if not session.key_acknowledged:
            session.key_acknowledged = True
            print("✅ Key automatically acknowledged")
            
        db.session.commit()
        print(f"✅ Message saved with ID: {message.id}")
        
        # Określ odbiorcę dla Socket.IO
        recipient_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        
        # Emit via Socket.IO (jeśli dostępne)
        try:
            from app import socketio
            socketio.emit('message', {
                'type': 'new_message',
                'session_token': session_token,
                'message': {
                    'id': message.id,
                    'sender_id': current_user.id,
                    'content': content,
                    'iv': iv,
                    'timestamp': message.timestamp.isoformat(),
                    'is_encrypted': True
                }
            }, room=f"user_{recipient_id}")
        except:
            pass  # Socket.IO not available
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': message.id,
                'timestamp': message.timestamp.isoformat()
            }
        })
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/messages/<session_token>')
@login_required
def get_messages(session_token):
    """Pobiera wiadomości z sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
            
        messages = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).all()
        
        # Oznacz jako przeczytane wiadomości od drugiej strony
        other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        unread_messages = Message.query.filter_by(
            session_id=session.id,
            sender_id=other_user_id,
            read=False
        ).all()
        
        for msg in unread_messages:
            msg.read = True
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'messages': [{
                'id': msg.id,
                'sender_id': msg.sender_id,
                'content': msg.content,
                'iv': msg.iv,
                'timestamp': msg.timestamp.isoformat(),
                'is_encrypted': msg.is_encrypted,
                'is_mine': msg.sender_id == current_user.id
            } for msg in messages]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/messages/<session_token>/clear', methods=['DELETE'])
@login_required
def clear_session_messages(session_token):
    """Usuwa wszystkie wiadomości z sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        deleted_count = Message.query.filter_by(session_id=session.id).delete()
        db.session.commit()
        
        return jsonify({
            'status': 'success', 
            'message': f'Deleted {deleted_count} messages',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/message/<int:message_id>', methods=['DELETE'])
@login_required
def delete_single_message(message_id):
    """Usuwa pojedynczą wiadomość"""
    try:
        message = Message.query.get(message_id)
        
        if not message:
            return jsonify({'error': 'Message not found'}), 404
            
        session = ChatSession.query.get(message.session_id)
        if not session or (session.initiator_id != current_user.id and session.recipient_id != current_user.id):
            return jsonify({'error': 'Access denied'}), 403
            
        if message.sender_id != current_user.id:
            return jsonify({'error': 'Can only delete own messages'}), 403
        
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Message deleted'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# === USERS API ===

@chat_bp.route('/api/user/<user_id>/public_key')
@login_required
def get_user_public_key(user_id):
    """Pobiera klucz publiczny użytkownika"""
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'status': 'success',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key
    })

@chat_bp.route('/api/users')
@login_required  
def get_users():
    """Lista wszystkich użytkowników (poza sobą)"""
    try:
        users = User.query.filter(User.id != current_user.id).all()
        
        user_list = [{
            'id': user.id,
            'user_id': user.user_id,
            'username': user.username,
            'is_online': getattr(user, 'is_online', False)
        } for user in users]
        
        return jsonify({'status': 'success', 'users': user_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/user/<user_id>/info')
@login_required
def get_user_info(user_id):
    """Informacje o użytkowniku"""
    try:
        user = User.query.filter_by(user_id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'status': 'success',
            'user': {
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username,
                'is_online': getattr(user, 'is_online', False)
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/online_users')
@login_required
def get_online_users():
    """Lista użytkowników online"""
    try:
        if hasattr(User, 'is_online'):
            online_users = User.query.filter(
                User.is_online == True, 
                User.id != current_user.id
            ).all()
            return jsonify({
                'status': 'success',
                'online_users': [{'id': u.id, 'user_id': u.user_id, 'username': u.username} for u in online_users]
            })
        return jsonify({'status': 'success', 'online_users': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === FRIENDS API ===

@chat_bp.route('/api/friends')
@login_required
def get_friends():
    """Lista znajomych użytkownika"""
    try:
        friends = current_user.get_friends()
        friends_list = [{
            'id': friend.id,
            'user_id': friend.user_id,
            'username': friend.username,
            'is_online': getattr(friend, 'is_online', False)
        } for friend in friends]
        return jsonify({'status': 'success', 'friends': friends_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/pending')
@login_required
def get_pending_requests():
    """Lista oczekujących zaproszeń"""
    try:
        requests = FriendRequest.query.filter_by(
            to_user_id=current_user.id,
            status='pending'
        ).all()
        
        requests_list = []
        for req in requests:
            sender = User.query.get(req.from_user_id)
            requests_list.append({
                'id': req.id,
                'sender_id': sender.user_id,
                'username': sender.username,
                'created_at': req.created_at.isoformat()
            })
        
        return jsonify({'status': 'success', 'requests': requests_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """Akceptuje zaproszenie"""
    try:
        friend_request = FriendRequest.query.filter_by(
            id=request_id,
            to_user_id=current_user.id,
            status='pending'
        ).first()
        
        if not friend_request:
            return jsonify({'error': 'Friend request not found'}), 404
            
        friend_request.status = 'accepted'
        friend_request.updated_at = datetime.utcnow()
        
        # Dodaj znajomość (obie strony)
        friend1 = Friend(user_id=current_user.id, friend_id=friend_request.from_user_id)
        friend2 = Friend(user_id=friend_request.from_user_id, friend_id=current_user.id)
        
        db.session.add(friend1)
        db.session.add(friend2)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Friend request accepted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """Odrzuca zaproszenie"""
    try:
        friend_request = FriendRequest.query.filter_by(
            id=request_id,
            to_user_id=current_user.id,
            status='pending'
        ).first()
        
        if not friend_request:
            return jsonify({'error': 'Friend request not found'}), 404
            
        friend_request.status = 'rejected'
        friend_request.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Friend request rejected'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# === UTILITY ENDPOINTS ===

@chat_bp.route('/api/polling/messages')
@login_required
def polling_messages():
    """Endpoint fallback do odbierania wiadomości poprzez polling"""
    try:
        last_id = request.args.get('last_id', 0)
        try:
            last_id = int(last_id)
        except ValueError:
            last_id = 0
        
        # Znajdź aktywne sesje
        active_sessions = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            ),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        session_ids = [session.id for session in active_sessions]
        
        # Pobierz nowe wiadomości
        new_messages = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.id > last_id,
            Message.sender_id != current_user.id,
            Message.read == False
        ).order_by(Message.id).all()
        
        messages = []
        max_id = last_id
        
        for msg in new_messages:
            session = next((s for s in active_sessions if s.id == msg.session_id), None)
            if session:
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
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/sessions/<session_token>/stats')
@login_required
def get_session_stats(session_token):
    """Pobiera statystyki sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Statystyki wiadomości
        total_messages = Message.query.filter_by(session_id=session.id).count()
        my_messages = Message.query.filter_by(session_id=session.id, sender_id=current_user.id).count()
        other_messages = total_messages - my_messages
        
        # Pierwsza i ostatnia wiadomość
        first_message = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).first()
        last_message = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp.desc()).first()
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_messages': total_messages,
                'my_messages': my_messages,
                'other_messages': other_messages,
                'first_message': first_message.timestamp.isoformat() if first_message else None,
                'last_message': last_message.timestamp.isoformat() if last_message else None,
                'session_created': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === DODAJ NA KONIEC chat.py ===

from flask_socketio import emit, join_room, leave_room
import logging

logger = logging.getLogger(__name__)

# Socket.IO events handler
def init_socketio_handler(socketio):
    """Inicjalizuje Socket.IO event handlers dla czatu"""
    
    @socketio.on('connect')
    def on_connect():
        if current_user.is_authenticated:
            # Dołącz użytkownika do jego pokoju
            join_room(f"user_{current_user.id}")
            logger.info(f"User {current_user.username} connected via Socket.IO")
            
            # Powiadom o statusie online
            emit('user_status', {
                'user_id': current_user.user_id,
                'status': 'online'
            }, broadcast=True)
    
    @socketio.on('disconnect')
    def on_disconnect():
        if current_user.is_authenticated:
            # Opuść pokój użytkownika
            leave_room(f"user_{current_user.id}")
            logger.info(f"User {current_user.username} disconnected from Socket.IO")
            
            # Powiadom o statusie offline (z opóźnieniem)
            emit('user_status', {
                'user_id': current_user.user_id,
                'status': 'offline'
            }, broadcast=True)
    
    @socketio.on('join_session')
    def on_join_session(data):
        """Dołącza użytkownika do pokoju sesji czatu"""
        if not current_user.is_authenticated:
            return
            
        session_token = data.get('session_token')
        if not session_token:
            return
            
        # Sprawdź czy użytkownik ma dostęp do sesji
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return
            
        # Dołącz do pokoju sesji
        join_room(f"session_{session_token}")
        logger.info(f"User {current_user.username} joined session {session_token}")
        
        emit('session_joined', {
            'session_token': session_token,
            'status': 'success'
        })
    
    @socketio.on('leave_session')
    def on_leave_session(data):
        """Opuszcza pokój sesji czatu"""
        if not current_user.is_authenticated:
            return
            
        session_token = data.get('session_token')
        if session_token:
            leave_room(f"session_{session_token}")
            logger.info(f"User {current_user.username} left session {session_token}")
    
    @socketio.on('typing_start')
    def on_typing_start(data):
        """Powiadamia o rozpoczęciu pisania"""
        if not current_user.is_authenticated:
            return
            
        session_token = data.get('session_token')
        if session_token:
            emit('typing_status', {
                'user_id': current_user.user_id,
                'username': current_user.username,
                'typing': True
            }, room=f"session_{session_token}", include_self=False)
    
    @socketio.on('typing_stop')
    def on_typing_stop(data):
        """Powiadamia o zakończeniu pisania"""
        if not current_user.is_authenticated:
            return
            
        session_token = data.get('session_token')
        if session_token:
            emit('typing_status', {
                'user_id': current_user.user_id,
                'username': current_user.username,
                'typing': False
            }, room=f"session_{session_token}", include_self=False)
    
    print("✅ Socket.IO handlers zainicjalizowane w chat.py")
    return socketio

# Helper function do wysyłania powiadomień przez Socket.IO
def emit_message_notification(session_token, message_data, recipient_id):
    """Wysyła powiadomienie o nowej wiadomości przez Socket.IO"""
    try:
        from flask import current_app
        if hasattr(current_app, 'socketio'):
            current_app.socketio.emit('message', {
                'type': 'new_message',
                'session_token': session_token,
                'message': message_data
            }, room=f"user_{recipient_id}")
            return True
    except Exception as e:
        logger.error(f"Failed to emit Socket.IO message: {e}")
    return False
