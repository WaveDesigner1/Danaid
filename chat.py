"""
chat.py - Zunifikowany moduł czatu (scalenie chat.py + chat_api.py)
CZĘŚĆ 1: Podstawowe API - Users, Friends, Sessions
Redukcja z 850 → 400 linii kodu
"""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from models import User, ChatSession, Message, db, Friend, FriendRequest
import datetime
import secrets
import string
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
    """Generuje token sesji"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

def _find_or_create_session(recipient_id):
    """Znajduje lub tworzy sesję czatu"""
    # Sprawdź istniejącą sesję
    existing = ChatSession.query.filter(
        ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient_id)) |
        ((ChatSession.initiator_id == recipient_id) & (ChatSession.recipient_id == current_user.id))
    ).filter(
        ChatSession.is_active == True, 
        ChatSession.expires_at > datetime.datetime.utcnow()
    ).first()
    
    if existing:
        # Odśwież sesję
        existing.last_activity = datetime.datetime.utcnow()
        existing.expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        db.session.commit()
        return existing
    
    # Utwórz nową sesję
    new_session = ChatSession(
        session_token=_generate_session_token(),
        initiator_id=current_user.id,
        recipient_id=recipient_id,
        created_at=datetime.datetime.utcnow(),
        last_activity=datetime.datetime.utcnow(),
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(days=30),
        is_active=True
    )
    db.session.add(new_session)
    db.session.commit()
    return new_session

# === USER API ===
@chat_bp.route('/api/user/<user_id>/public_key')
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """Wysyła wiadomość"""
    try:
        print("📨 Send message endpoint called")  # Debug
        data = request.get_json()
        print("Request data:", data)  # Debug
        
        required_fields = ['session_token', 'content', 'iv']
        
        if not data or not all(field in data for field in required_fields):
            print("❌ Brakujące dane:", data)
            return jsonify({'status': 'error', 'message': 'Brakujące dane'}), 400
            
        session_token = data.get('session_token')
        content = data.get('content')
        iv = data.get('iv')
        
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            print("❌ Nieprawidłowa sesja:", session_token)
            return jsonify({'status': 'error', 'message': 'Nieprawidłowa sesja'}), 404
            
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            print("❌ Sesja wygasła")
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
            
        # 🔧 ZMIENIONE: Nie wymagamy key_acknowledged (może być False na początku)
        if not session.encrypted_session_key:
            print("❌ Brak klucza sesji")
            return jsonify({'status': 'error', 'message': 'Brak klucza sesji'}), 400
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            print("❌ Brak dostępu do sesji")
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
        
        print("✅ Walidacja przeszła, zapisuję wiadomość")
        
        # Zapisz wiadomość
        new_message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            timestamp=datetime.datetime.utcnow(),
            read=False
        )
        db.session.add(new_message)
        
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
        
        # Automatycznie potwierdź klucz jeśli jeszcze nie został potwierdzony
        if not session.key_acknowledged:
            session.key_acknowledged = True
            print("✅ Klucz automatycznie potwierdzony")
            
        db.session.commit()
        print("✅ Wiadomość zapisana:", new_message.id)
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': new_message.id,
                'timestamp': new_message.timestamp.isoformat()
            }
        })
    except Exception as e:
        print(f"❌ Błąd wysyłania wiadomości: {e}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
            return jsonify({'status': 'error', 'message': 'Zaproszenie nie znalezione'}), 404
            
        # Aktualizuj status
        friend_request.status = 'accepted'
        friend_request.updated_at = datetime.datetime.utcnow()
        
        # Dodaj znajomość (obie strony)
        friend1 = Friend(user_id=current_user.id, friend_id=friend_request.from_user_id)
        friend2 = Friend(user_id=friend_request.from_user_id, friend_id=current_user.id)
        
        db.session.add(friend1)
        db.session.add(friend2)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Zaproszenie zaakceptowane'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
            return jsonify({'status': 'error', 'message': 'Zaproszenie nie znalezione'}), 404
            
        friend_request.status = 'rejected'
        friend_request.updated_at = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Zaproszenie odrzucone'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === SESSIONS API ===
@chat_bp.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """Inicjuje sesję czatu"""
    try:
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        
        if not recipient_id:
            return jsonify({'status': 'error', 'message': 'Brak ID adresata'}), 400
            
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'status': 'error', 'message': 'Adresat nie istnieje'}), 404
            
        session = _find_or_create_session(recipient.id)
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja zainicjalizowana',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'initiator_id': session.initiator_id,
                'recipient_id': session.recipient_id,
                'has_key': session.encrypted_session_key is not None,
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/sessions/active')
@login_required
def get_active_sessions():
    """Lista aktywnych sesji"""
    try:
        sessions = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.datetime.utcnow()
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
                'has_key': session.encrypted_session_key is not None,
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/validate')
@login_required
def validate_session(session_token):
    """Waliduje sesję"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
            
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
            
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
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
                'has_key': session.encrypted_session_key is not None,
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === KEY EXCHANGE API ===
@chat_bp.route('/api/session/<session_token>/exchange_key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """Wymiana klucza sesji"""
    try:
        data = request.get_json()
        encrypted_key = data.get('encrypted_key')
        
        if not encrypted_key:
            return jsonify({'status': 'error', 'message': 'Brak klucza'}), 400
            
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
            
        session.encrypted_session_key = encrypted_key
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Klucz wymieniony'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/key')
@login_required
def get_session_key(session_token):
    """Pobiera klucz sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
            
        if not session.encrypted_session_key:
            return jsonify({'status': 'error', 'message': 'Brak klucza'}), 404
            
        return jsonify({'status': 'success', 'encrypted_key': session.encrypted_session_key})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/close', methods=['POST'])
@login_required
def close_session(session_token):
    """Zamyka sesję"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
            
        session.is_active = False
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Sesja zamknięta'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/acknowledge_key', methods=['POST'])
@login_required
def acknowledge_session_key(session_token):
    """Potwierdza klucz sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Tylko odbiorca może potwierdzić'}), 403
            
        session.key_acknowledged = True
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Klucz potwierdzony'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === MESSAGES API ===

@chat_bp.route('/api/messages/<session_token>')
@login_required
def get_messages(session_token):
    """Pobiera wiadomości z sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
            
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
        
        # Pobierz wiadomości
        messages = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).all()
        
        # Oznacz jako przeczytane
        other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        unread_messages = Message.query.filter_by(
            session_id=session.id,
            sender_id=other_user_id,
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
        
        return jsonify({'status': 'success', 'messages': message_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === POLLING FALLBACK ===
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
            ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.datetime.utcnow()
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === UTILITY ENDPOINTS ===
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/user/<user_id>/info')
@login_required
def get_user_info(user_id):
    """Informacje o użytkowniku"""
    try:
        user = User.query.filter_by(user_id=user_id).first()
        
        if not user:
            return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === DODAJ TE ENDPOINTY NA KOŃCU chat.py ===

@chat_bp.route('/api/messages/<session_token>/clear', methods=['DELETE'])
@login_required
def clear_session_messages(session_token):
    """Usuwa wszystkie wiadomości z sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
        # Delete all messages in this session
        deleted_count = Message.query.filter_by(session_id=session.id).delete()
        db.session.commit()
        
        return jsonify({
            'status': 'success', 
            'message': f'Deleted {deleted_count} messages',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/message/<int:message_id>', methods=['DELETE'])
@login_required
def delete_single_message(message_id):
    """Usuwa pojedynczą wiadomość"""
    try:
        message = Message.query.get(message_id)
        
        if not message:
            return jsonify({'status': 'error', 'message': 'Message not found'}), 404
            
        # Check if user has access to this message
        session = ChatSession.query.get(message.session_id)
        if not session or (session.initiator_id != current_user.id and session.recipient_id != current_user.id):
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
            
        # Only sender can delete their own messages
        if message.sender_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Can only delete own messages'}), 403
        
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Message deleted'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/sessions/<session_token>/stats')
@login_required
def get_session_stats(session_token):
    """Pobiera statystyki sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
        # Count messages
        total_messages = Message.query.filter_by(session_id=session.id).count()
        my_messages = Message.query.filter_by(session_id=session.id, sender_id=current_user.id).count()
        other_messages = total_messages - my_messages
        
        # Get first and last message timestamps
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

