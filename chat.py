"""
chat.py - Zunifikowany moduł czatu z Socket.IO + FIXED ENDPOINTS
Obsługuje dual encryption + backward compatibility + missing endpoints
"""
import json
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from flask_socketio import emit, join_room, leave_room
from sqlalchemy import or_
from models import db, ChatSession, Message, User, Friend, FriendRequest
import logging

logger = logging.getLogger(__name__)
chat_bp = Blueprint('chat', __name__)

# === HELPER FUNCTIONS ===
def _generate_session_token():
    return secrets.token_urlsafe(32)

def _find_or_create_session(recipient_id):
    """Znajduje lub tworzy sesję czatu"""
    existing = ChatSession.query.filter(
        or_(
            (ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient_id),
            (ChatSession.initiator_id == recipient_id) & (ChatSession.recipient_id == current_user.id)
        ),
        ChatSession.is_active == True,
        ChatSession.expires_at > datetime.utcnow()
    ).first()
    
    if existing:
        existing.last_activity = datetime.utcnow()
        existing.expires_at = datetime.utcnow() + timedelta(days=7)
        db.session.commit()
        return existing
    
    new_session = ChatSession(
        session_token=_generate_session_token(),
        initiator_id=current_user.id,
        recipient_id=recipient_id,
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.session.add(new_session)
    db.session.commit()
    return new_session

def _get_other_user(session):
    """Pobiera drugiego uczestnika sesji"""
    other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
    return User.query.get(other_user_id)

# === VIEWS ===
@chat_bp.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

# === SESSION API ===
@chat_bp.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
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
                'has_key': bool(session.encrypted_keys_json or session.encrypted_session_key),
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
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        # NOWY SYSTEM: Dual encryption
        if 'keys' in data:
            encrypted_keys = data.get('keys', {})
            if not encrypted_keys or not isinstance(encrypted_keys, dict):
                return jsonify({'error': 'Invalid keys format'}), 400
            
            expected_users = {str(session.initiator_id), str(session.recipient_id)}
            if not expected_users.issubset(set(encrypted_keys.keys())):
                return jsonify({'error': f'Keys required for users: {expected_users}'}), 400
            
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
        
        # STARY SYSTEM: Legacy compatibility
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
        
        return jsonify({'error': 'No valid key data provided'}), 400
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/key')
@login_required
def get_session_key(session_token):
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
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

@chat_bp.route('/api/sessions/active')
@login_required
def get_active_sessions():
    try:
        sessions = ChatSession.query.filter(
            or_(ChatSession.initiator_id == current_user.id, ChatSession.recipient_id == current_user.id),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        session_list = []
        for session in sessions:
            other_user = _get_other_user(session)
            unread_count = Message.query.filter_by(
                session_id=session.id,
                sender_id=other_user.id,
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

# === MESSAGES API ===
@chat_bp.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.get_json()
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
            
        if not (session.encrypted_keys_json or session.encrypted_session_key):
            return jsonify({'error': 'No encryption key available'}), 400
        
        # Utwórz wiadomość
        message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            is_encrypted=True
        )
        db.session.add(message)
        
        # Odśwież sesję i potwierdź klucz
        session.last_activity = datetime.utcnow()
        if not session.key_acknowledged:
            session.key_acknowledged = True
            
        db.session.commit()
        
        # Socket.IO notification
        recipient_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        emit_message_notification(session_token, {
            'id': message.id,
            'sender_id': current_user.id,
            'content': content,
            'iv': iv,
            'timestamp': message.timestamp.isoformat(),
            'is_encrypted': True
        }, recipient_id)
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': message.id,
                'timestamp': message.timestamp.isoformat()
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/messages/<session_token>')
@login_required
def get_messages(session_token):
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
            
        messages = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).all()
        
        # Oznacz jako przeczytane
        other_user = _get_other_user(session)
        Message.query.filter_by(session_id=session.id, sender_id=other_user.id, read=False).update({'read': True})
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

# === USERS & FRIENDS API ===
@chat_bp.route('/api/user/<user_id>/public_key')
@login_required
def get_user_public_key(user_id):
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
    try:
        users = User.query.filter(User.id != current_user.id).all()
        return jsonify({
            'status': 'success',
            'users': [{
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username,
                'is_online': getattr(user, 'is_online', False)
            } for user in users]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friends')
@login_required
def get_friends():
    try:
        friends = current_user.get_friends()
        return jsonify({
            'status': 'success',
            'friends': [{
                'id': friend.id,
                'user_id': friend.user_id,
                'username': friend.username,
                'is_online': getattr(friend, 'is_online', False)
            } for friend in friends]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ✅ ADDED: Missing add friend endpoint
@chat_bp.route('/api/friends/add', methods=['POST'])
@login_required
def add_friend():
    """Dodaje znajomego przez wysłanie zaproszenia"""
    try:
        data = request.get_json()
        user_identifier = data.get('user_identifier')
        
        if not user_identifier:
            return jsonify({'error': 'User identifier is required'}), 400
        
        # Znajdź użytkownika po nazwie lub ID
        target_user = User.query.filter(
            or_(
                User.username == user_identifier,
                User.user_id == user_identifier
            )
        ).first()
        
        if not target_user:
            return jsonify({'error': 'User not found'}), 404
        
        if target_user.id == current_user.id:
            return jsonify({'error': 'Cannot add yourself as friend'}), 400
        
        # Sprawdź czy już są znajomymi
        existing_friendship = Friend.query.filter(
            or_(
                (Friend.user_id == current_user.id) & (Friend.friend_id == target_user.id),
                (Friend.user_id == target_user.id) & (Friend.friend_id == current_user.id)
            )
        ).first()
        
        if existing_friendship:
            return jsonify({'error': 'Already friends'}), 409
        
        # Sprawdź czy zaproszenie już istnieje
        existing_request = FriendRequest.query.filter(
            or_(
                (FriendRequest.from_user_id == current_user.id) & (FriendRequest.to_user_id == target_user.id),
                (FriendRequest.from_user_id == target_user.id) & (FriendRequest.to_user_id == current_user.id)
            ),
            FriendRequest.status == 'pending'
        ).first()
        
        if existing_request:
            return jsonify({'error': 'Friend request already exists'}), 409
        
        # Utwórz nowe zaproszenie
        friend_request = FriendRequest(
            from_user_id=current_user.id,
            to_user_id=target_user.id,
            status='pending'
        )
        
        db.session.add(friend_request)
        db.session.commit()
        
        # Wyślij powiadomienie Socket.IO jeśli możliwe
        try:
            emit_friend_request_notification(target_user.id, {
                'type': 'friend_request',
                'from_user_id': current_user.user_id,
                'from_username': current_user.username,
                'message': f'{current_user.username} sent you a friend request'
            })
        except Exception as e:
            logger.error(f"Failed to send friend request notification: {e}")
        
        return jsonify({
            'status': 'success',
            'message': 'Friend request sent successfully',
            'request_id': friend_request.id
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Add friend error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/pending')
@login_required
def get_pending_requests():
    try:
        requests = FriendRequest.query.filter_by(
            to_user_id=current_user.id, 
            status='pending'
        ).all()
        
        return jsonify({
            'status': 'success',
            'requests': [{
                'id': req.id,
                'sender_id': User.query.get(req.from_user_id).user_id,
                'username': User.query.get(req.from_user_id).username,
                'created_at': req.created_at.isoformat()
            } for req in requests]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
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
        db.session.add(Friend(user_id=current_user.id, friend_id=friend_request.from_user_id))
        db.session.add(Friend(user_id=friend_request.from_user_id, friend_id=current_user.id))
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Friend request accepted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
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

# ✅ ADDED: Remove friend endpoint
@chat_bp.route('/api/friends/<int:friend_id>', methods=['DELETE'])
@login_required
def remove_friend(friend_id):
    try:
        # Znajdź znajomego
        friend_user = User.query.get(friend_id)
        if not friend_user:
            return jsonify({'error': 'Friend not found'}), 404
        
        # Usuń znajomość (obie strony)
        Friend.query.filter(
            or_(
                (Friend.user_id == current_user.id) & (Friend.friend_id == friend_user.id),
                (Friend.user_id == friend_user.id) & (Friend.friend_id == current_user.id)
            )
        ).delete()
        
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Friend removed successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# === UTILITY ENDPOINTS ===
@chat_bp.route('/api/polling/messages')
@login_required
def polling_messages():
    try:
        last_id = int(request.args.get('last_id', 0))
        
        active_sessions = ChatSession.query.filter(
            or_(ChatSession.initiator_id == current_user.id, ChatSession.recipient_id == current_user.id),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        session_ids = [session.id for session in active_sessions]
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
        
        return jsonify({'status': 'success', 'messages': messages, 'last_id': max_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === ✅ FIXED SOCKET.IO INTEGRATION ===
def init_socketio_handler(socketio):
    """Inicjalizuje Socket.IO event handlers - FIXED VERSION"""
    
    @socketio.on('connect')
    def on_connect():
        if current_user.is_authenticated:
            join_room(f"user_{current_user.id}")
            emit('user_status', {
                'user_id': current_user.user_id, 
                'status': 'online'
            }, broadcast=True)
            logger.info(f"User {current_user.username} connected to Socket.IO")
    
    @socketio.on('disconnect')
    def on_disconnect():
        if current_user.is_authenticated:
            leave_room(f"user_{current_user.id}")
            emit('user_status', {
                'user_id': current_user.user_id, 
                'status': 'offline'
            }, broadcast=True)
            logger.info(f"User {current_user.username} disconnected from Socket.IO")
    
    @socketio.on('register_user')
    def on_register_user(data):
        if current_user.is_authenticated:
            user_id = data.get('user_id')
            join_room(f"user_{current_user.id}")
            logger.info(f"User {current_user.username} registered for Socket.IO events")
    
    @socketio.on('join_session')
    def on_join_session(data):
        if not current_user.is_authenticated:
            return
            
        session_token = data.get('session_token')
        if not session_token:
            return
            
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session or (session.initiator_id != current_user.id and session.recipient_id != current_user.id):
            return
            
        join_room(f"session_{session_token}")
        emit('session_joined', {'session_token': session_token, 'status': 'success'})
    
    @socketio.on('leave_session')
    def on_leave_session(data):
        if current_user.is_authenticated and data.get('session_token'):
            leave_room(f"session_{data['session_token']}")
    
    @socketio.on('typing_start')
    def on_typing_start(data):
        if current_user.is_authenticated and data.get('session_token'):
            emit('typing_status', {
                'user_id': current_user.user_id,
                'username': current_user.username,
                'typing': True
            }, room=f"session_{data['session_token']}", include_self=False)
    
    @socketio.on('typing_stop')
    def on_typing_stop(data):
        if current_user.is_authenticated and data.get('session_token'):
            emit('typing_status', {
                'user_id': current_user.user_id,
                'username': current_user.username,
                'typing': False
            }, room=f"session_{data['session_token']}", include_self=False)
    
    logger.info("✅ Socket.IO handlers initialized successfully")
    return socketio

def emit_message_notification(session_token, message_data, recipient_id):
    """Wysyła powiadomienie Socket.IO o nowej wiadomości"""
    try:
        from flask import current_app
        if hasattr(current_app, 'socketio'):
            current_app.socketio.emit('message', {
                'type': 'new_message',
                'session_token': session_token,
                'message': message_data
            }, room=f"user_{recipient_id}")
            logger.info(f"Message notification sent to user {recipient_id}")
            return True
    except Exception as e:
        logger.error(f"Socket.IO emit failed: {e}")
    return False

def emit_friend_request_notification(recipient_id, notification_data):
    """Wysyła powiadomienie Socket.IO o nowym zaproszeniu"""
    try:
        from flask import current_app
        if hasattr(current_app, 'socketio'):
            current_app.socketio.emit('message', notification_data, room=f"user_{recipient_id}")
            logger.info(f"Friend request notification sent to user {recipient_id}")
            return True
    except Exception as e:
        logger.error(f"Socket.IO friend request notification failed: {e}")
    return False

@chat_bp.route('/api/session/<session_token>/clear', methods=['DELETE'])
@login_required
def clear_session_messages(session_token):
    # ... (kod z poprzedniego artifact)

@chat_bp.route('/api/session/<session_token>/delete', methods=['DELETE'])  
@login_required
def delete_session(session_token):
