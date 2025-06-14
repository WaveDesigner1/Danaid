"""
chat.py - Refactored Chat System with Auto-Switch Messaging
Clean, optimized chat API with Socket.IO integration and automatic context switching
"""

import json
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from flask_socketio import emit, join_room, leave_room
from sqlalchemy import or_
from models import db, ChatSession, Message, User, Friend, FriendRequest
import logging

logger = logging.getLogger(__name__)

# ================================================
# BLUEPRINT SETUP
# ================================================

chat_bp = Blueprint('chat', __name__)

# ================================================
# HELPER FUNCTIONS
# ================================================

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def find_or_create_session(recipient_id):
    """Find existing session or create new one"""
    # Look for existing active session
    existing = ChatSession.query.filter(
        or_(
            (ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient_id),
            (ChatSession.initiator_id == recipient_id) & (ChatSession.recipient_id == current_user.id)
        ),
        ChatSession.is_active == True,
        ChatSession.expires_at > datetime.utcnow()
    ).first()
    
    if existing:
        # Update existing session
        existing.last_activity = datetime.utcnow()
        existing.expires_at = datetime.utcnow() + timedelta(days=7)
        db.session.commit()
        return existing
    
    # Create new session
    new_session = ChatSession(
        session_token=generate_session_token(),
        initiator_id=current_user.id,
        recipient_id=recipient_id,
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.session.add(new_session)
    db.session.commit()
    return new_session

def get_other_user(session):
    """Get the other participant in chat session"""
    other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
    return User.query.get(other_user_id)

def validate_session_access(session_token):
    """Validate user access to session"""
    session = ChatSession.query.filter_by(session_token=session_token).first()
    if not session:
        return None, jsonify({'error': 'Session not found'}), 404
    
    if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
        return None, jsonify({'error': 'Access denied'}), 403
    
    return session, None, None

def emit_socketio(event, data, room=None):
    """Helper for Socket.IO emission with error handling"""
    try:
        if hasattr(current_app, 'socketio'):
            current_app.socketio.emit(event, data, room=room)
            return True
        else:
            logger.warning("Socket.IO not available for emission")
            return False
    except Exception as e:
        logger.error(f"Socket.IO emit failed: {e}")
        return False

def emit_auto_switch_message(session_token, message_data, recipient_id):
    """Emit message with auto-switch functionality"""
    notification_data = {
        'type': 'new_message',
        'session_token': session_token,
        'message': message_data,
        'auto_switch': True,  # KEY: This enables auto-switch
        'sender_username': current_user.username
    }
    
    # Send to recipient's room
    emit_socketio('message', notification_data, room=f"user_{recipient_id}")
    
    # Also send general notification for unread count updates
    emit_socketio('notification', {
        'type': 'new_message',
        'sender_username': current_user.username,
        'session_token': session_token
    }, room=f"user_{recipient_id}")

# ================================================
# MAIN VIEWS
# ================================================

@chat_bp.route('/chat')
@login_required
def chat():
    """Main chat interface"""
    return render_template('chat.html')

# ================================================
# SESSION MANAGEMENT API
# ================================================

@chat_bp.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """Initialize or find chat session"""
    try:
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        
        if not recipient_id:
            return jsonify({'error': 'Recipient ID required'}), 400
        
        # Find recipient user
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Find or create session
        session = find_or_create_session(recipient.id)
        
        return jsonify({
            'status': 'success',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'initiator_id': session.initiator_id,
                'recipient_id': session.recipient_id,
                'expires_at': session.expires_at.isoformat(),
                'has_key': bool(session.encrypted_keys_json or session.encrypted_session_key),
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
        logger.error(f"Session init error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/exchange_key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """Exchange encryption keys for session"""
    try:
        session, error_response, status_code = validate_session_access(session_token)
        if error_response:
            return error_response, status_code
        
        data = request.get_json()
        
        # NEW SYSTEM: Dual encryption support
        if 'keys' in data:
            encrypted_keys = data.get('keys', {})
            expected_users = {str(session.initiator_id), str(session.recipient_id)}
            
            if not encrypted_keys or not expected_users.issubset(set(encrypted_keys.keys())):
                return jsonify({'error': 'Invalid keys format'}), 400
            
            if session.encrypted_keys_json and not data.get('force_overwrite', False):
                return jsonify({'error': 'Keys already exist'}), 409
            
            session.set_encrypted_keys(encrypted_keys, current_user.id)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'system': 'dual_encryption',
                'users_with_keys': list(encrypted_keys.keys())
            })
        
        # OLD SYSTEM: Legacy compatibility
        elif 'encrypted_key' in data:
            session.encrypted_session_key = data.get('encrypted_key')
            session.last_activity = datetime.utcnow()
            db.session.commit()
            
            return jsonify({'status': 'success', 'system': 'legacy'})
        
        return jsonify({'error': 'No valid key data provided'}), 400
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Key exchange error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/key')
@login_required
def get_session_key(session_token):
    """Get encryption key for session"""
    try:
        session, error_response, status_code = validate_session_access(session_token)
        if error_response:
            return error_response, status_code
        
        encrypted_key = session.get_encrypted_key_for_user(current_user.id)
        if not encrypted_key:
            return jsonify({'error': 'No key available'}), 404
            
        return jsonify({
            'status': 'success',
            'encrypted_key': encrypted_key,
            'system': 'dual_encryption' if session.encrypted_keys_json else 'legacy'
        })
        
    except Exception as e:
        logger.error(f"Get key error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/sessions/active')
@login_required
def get_active_sessions():
    """Get all active chat sessions for current user"""
    try:
        sessions = ChatSession.query.filter(
            or_(ChatSession.initiator_id == current_user.id, ChatSession.recipient_id == current_user.id),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        sessions_data = []
        for session in sessions:
            other_user = get_other_user(session)
            unread_count = Message.query.filter_by(
                session_id=session.id,
                sender_id=other_user.id,
                read=False
            ).count()
            
            sessions_data.append({
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'has_key': session.has_key_for_user(current_user.id),
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': getattr(other_user, 'is_online', False)
                },
                'unread_count': unread_count
            })
        
        return jsonify({
            'status': 'success',
            'sessions': sessions_data
        })
        
    except Exception as e:
        logger.error(f"Get active sessions error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/switch/<session_token>', methods=['POST'])
@login_required
def switch_to_session(session_token):
    """Switch to specific chat session and mark messages as read"""
    try:
        session, error_response, status_code = validate_session_access(session_token)
        if error_response:
            return error_response, status_code
        
        other_user = get_other_user(session)
        
        # Mark messages as read
        Message.query.filter_by(
            session_id=session.id,
            sender_id=other_user.id,
            read=False
        ).update({'read': True})
        
        # Update session activity
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': getattr(other_user, 'is_online', False)
                }
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Session switch error: {e}")
        return jsonify({'error': str(e)}), 500

# ================================================
# MESSAGE API WITH AUTO-SWITCH
# ================================================

@chat_bp.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """Send encrypted message with auto-switch notification"""
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        content = data.get('content')
        iv = data.get('iv')
        
        if not all([session_token, content, iv]):
            return jsonify({'error': 'Missing required fields'}), 400
            
        session, error_response, status_code = validate_session_access(session_token)
        if error_response:
            return error_response, status_code
        
        # Validate session is active and not expired
        if not session.is_active or session.expires_at < datetime.utcnow():
            return jsonify({'error': 'Session expired'}), 401
            
        # Check encryption key availability
        if not (session.encrypted_keys_json or session.encrypted_session_key):
            return jsonify({'error': 'No encryption key available'}), 400
        
        # Create message
        message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            is_encrypted=True
        )
        db.session.add(message)
        
        # Update session activity
        session.last_activity = datetime.utcnow()
        if not session.key_acknowledged:
            session.key_acknowledged = True
            
        db.session.commit()
        
        # Prepare message data for Socket.IO
        message_data = {
            'id': message.id,
            'sender_id': current_user.id,
            'content': content,
            'iv': iv,
            'timestamp': message.timestamp.isoformat(),
            'is_encrypted': True,
            'is_mine': False  # For recipient
        }
        
        # Get recipient for Socket.IO notification
        recipient_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        
        # KEY FEATURE: Emit with auto-switch capability
        emit_auto_switch_message(session_token, message_data, recipient_id)
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': message.id,
                'timestamp': message.timestamp.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Send message error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/messages/<session_token>')
@login_required
def get_messages(session_token):
    """Get all messages for session"""
    try:
        session, error_response, status_code = validate_session_access(session_token)
        if error_response:
            return error_response, status_code
            
        messages = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).all()
        
        # Mark unread messages as read
        other_user = get_other_user(session)
        Message.query.filter_by(
            session_id=session.id,
            sender_id=other_user.id,
            read=False
        ).update({'read': True})
        db.session.commit()
        
        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'content': msg.content,
                'iv': msg.iv,
                'timestamp': msg.timestamp.isoformat(),
                'is_encrypted': msg.is_encrypted,
                'is_mine': msg.sender_id == current_user.id
            })
        
        return jsonify({
            'status': 'success',
            'messages': messages_data
        })
        
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        return jsonify({'error': str(e)}), 500

# ================================================
# SESSION MANAGEMENT OPERATIONS
# ================================================

@chat_bp.route('/api/session/<session_token>/clear', methods=['DELETE'])
@login_required
def clear_session_messages(session_token):
    """Clear all messages in session"""
    try:
        session, error_response, status_code = validate_session_access(session_token)
        if error_response:
            return error_response, status_code
        
        messages_count = Message.query.filter_by(session_id=session.id).count()
        Message.query.filter_by(session_id=session.id).delete()
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        # Notify other user
        other_user = get_other_user(session)
        emit_socketio('session_cleared', {
            'session_token': session_token,
            'cleared_by': current_user.username
        }, room=f"user_{other_user.id}")
        
        return jsonify({
            'status': 'success',
            'messages_deleted': messages_count
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Clear session error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/delete', methods=['DELETE'])
@login_required
def delete_session(session_token):
    """Permanently delete session and all messages"""
    try:
        session, error_response, status_code = validate_session_access(session_token)
        if error_response:
            return error_response, status_code
        
        messages_count = Message.query.filter_by(session_id=session.id).count()
        other_user = get_other_user(session)
        
        # Delete all messages and session
        Message.query.filter_by(session_id=session.id).delete()
        db.session.delete(session)
        db.session.commit()
        
        # Notify other user
        emit_socketio('session_deleted', {
            'session_token': session_token,
            'deleted_by': current_user.username
        }, room=f"user_{other_user.id}")
        
        return jsonify({
            'status': 'success',
            'messages_deleted': messages_count,
            'deletion_type': 'permanent'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete session error: {e}")
        return jsonify({'error': str(e)}), 500

# ================================================
# FRIENDS SYSTEM API
# ================================================

@chat_bp.route('/api/friends')
@login_required
def get_friends():
    """Get user's friends list"""
    try:
        friends = current_user.get_friends()
        friends_data = []
        
        for friend in friends:
            friends_data.append({
                'id': friend.id,
                'user_id': friend.user_id,
                'username': friend.username,
                'is_online': getattr(friend, 'is_online', False)
            })
        
        return jsonify({
            'status': 'success',
            'friends': friends_data
        })
        
    except Exception as e:
        logger.error(f"Get friends error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friends/add', methods=['POST'])
@login_required
def add_friend():
    """Send friend request"""
    try:
        data = request.get_json()
        user_identifier = data.get('user_identifier')
        
        if not user_identifier:
            return jsonify({'error': 'User identifier is required'}), 400
        
        # Find target user by username or user_id
        target_user = User.query.filter(
            or_(User.username == user_identifier, User.user_id == user_identifier)
        ).first()
        
        if not target_user:
            return jsonify({'error': 'User not found'}), 404
        
        if target_user.id == current_user.id:
            return jsonify({'error': 'Cannot add yourself as friend'}), 400
        
        # Check if already friends or request exists
        existing_friendship = Friend.query.filter(
            or_(
                (Friend.user_id == current_user.id) & (Friend.friend_id == target_user.id),
                (Friend.user_id == target_user.id) & (Friend.friend_id == current_user.id)
            )
        ).first()
        
        existing_request = FriendRequest.query.filter(
            or_(
                (FriendRequest.from_user_id == current_user.id) & (FriendRequest.to_user_id == target_user.id),
                (FriendRequest.from_user_id == target_user.id) & (FriendRequest.to_user_id == current_user.id)
            ),
            FriendRequest.status == 'pending'
        ).first()
        
        if existing_friendship or existing_request:
            return jsonify({'error': 'Already friends or request exists'}), 409
        
        # Create friend request
        friend_request = FriendRequest(
            from_user_id=current_user.id,
            to_user_id=target_user.id,
            status='pending'
        )
        db.session.add(friend_request)
        db.session.commit()
        
        # Socket.IO notification
        emit_socketio('friend_request', {
            'type': 'friend_request',
            'from_user_id': current_user.user_id,
            'from_username': current_user.username
        }, room=f"user_{target_user.id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Friend request sent'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Add friend error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friends/<int:friend_id>', methods=['DELETE'])
@login_required
def remove_friend(friend_id):
    """Remove friend from friends list"""
    try:
        friend_user = User.query.get(friend_id)
        if not friend_user:
            return jsonify({'error': 'Friend not found'}), 404
        
        # Remove friendship (both directions)
        Friend.query.filter(
            or_(
                (Friend.user_id == current_user.id) & (Friend.friend_id == friend_user.id),
                (Friend.user_id == friend_user.id) & (Friend.friend_id == current_user.id)
            )
        ).delete()
        db.session.commit()
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Remove friend error: {e}")
        return jsonify({'error': str(e)}), 500

# ================================================
# FRIEND REQUESTS API
# ================================================

@chat_bp.route('/api/friend_requests/pending')
@login_required
def get_pending_requests():
    """Get pending friend requests"""
    try:
        requests = FriendRequest.query.filter_by(
            to_user_id=current_user.id,
            status='pending'
        ).all()
        
        requests_data = []
        for req in requests:
            sender = User.query.get(req.from_user_id)
            requests_data.append({
                'id': req.id,
                'sender_id': sender.user_id,
                'username': sender.username,
                'created_at': req.created_at.isoformat()
            })
        
        return jsonify({
            'status': 'success',
            'requests': requests_data
        })
        
    except Exception as e:
        logger.error(f"Get pending requests error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/<action>', methods=['POST'])
@login_required
def handle_friend_request(request_id, action):
    """Accept or reject friend request"""
    try:
        if action not in ['accept', 'reject']:
            return jsonify({'error': 'Invalid action'}), 400
            
        friend_request = FriendRequest.query.filter_by(
            id=request_id,
            to_user_id=current_user.id,
            status='pending'
        ).first()
        
        if not friend_request:
            return jsonify({'error': 'Friend request not found'}), 404
            
        # Update request status
        friend_request.status = action + 'ed'
        friend_request.updated_at = datetime.utcnow()
        
        if action == 'accept':
            # Create friendship (both directions)
            friendship1 = Friend(user_id=current_user.id, friend_id=friend_request.from_user_id)
            friendship2 = Friend(user_id=friend_request.from_user_id, friend_id=current_user.id)
            db.session.add(friendship1)
            db.session.add(friendship2)
            
            # Notify sender about acceptance
            emit_friend_request_response(
                friend_request.from_user_id, 
                'accepted', 
                current_user.username
            )
            
        elif action == 'reject':
            # Notify sender about rejection
            emit_friend_request_response(
                friend_request.from_user_id, 
                'rejected', 
                current_user.username
            )
        
        # Commit all changes (both accept and reject)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Friend request {action}ed'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Handle friend request error: {e}")
        return jsonify({'error': str(e)}), 500

# ================================================
# UTILITY ENDPOINTS
# ================================================

@chat_bp.route('/api/user/<user_id>/public_key')
@login_required
def get_user_public_key(user_id):
    """Get user's public key for encryption"""
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'status': 'success',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key
    })

@chat_bp.route('/api/polling/messages')
@login_required
def polling_messages():
    """Polling endpoint for new messages (fallback if Socket.IO fails)"""
    try:
        last_id = int(request.args.get('last_id', 0))
        
        # Get active sessions
        active_sessions = ChatSession.query.filter(
            or_(ChatSession.initiator_id == current_user.id, ChatSession.recipient_id == current_user.id),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        session_ids = [session.id for session in active_sessions]
        
        # Get new messages
        new_messages = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.id > last_id,
            Message.sender_id != current_user.id,
            Message.read == False
        ).order_by(Message.id).all()
        
        messages_data = []
        max_id = last_id
        
        for msg in new_messages:
            session = next((s for s in active_sessions if s.id == msg.session_id), None)
            if session:
                max_id = max(max_id, msg.id)
                messages_data.append({
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
            'messages': messages_data,
            'last_id': max_id
        })
        
    except Exception as e:
        logger.error(f"Polling messages error: {e}")
        return jsonify({'error': str(e)}), 500

# ================================================
# SOCKET.IO HANDLERS
# ================================================

def init_socketio_handler(socketio):
    """Initialize Socket.IO event handlers with auto-switch support"""
    
    @socketio.on('connect')
    def on_connect():
        if current_user.is_authenticated:
            join_room(f"user_{current_user.id}")
            emit('user_status', {
                'user_id': current_user.user_id,
                'status': 'online'
            }, broadcast=True)
            logger.info(f"User {current_user.username} connected via Socket.IO")
    
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
            join_room(f"user_{current_user.id}")
            logger.info(f"User {current_user.username} registered for Socket.IO")
    
    # Typing indicators
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
    
    # Session join/leave for typing
    @socketio.on('join_session')
    def on_join_session(data):
        if current_user.is_authenticated and data.get('session_token'):
            join_room(f"session_{data['session_token']}")
    
    @socketio.on('leave_session')
    def on_leave_session(data):
        if current_user.is_authenticated and data.get('session_token'):
            leave_room(f"session_{data['session_token']}")
    
    logger.info("Socket.IO handlers initialized with auto-switch support")
    return socketio
    
def emit_friend_request_response(recipient_id, action, sender_username):
    """Emit friend request response notification"""
    notification_data = {
        'type': 'friend_request_response',
        'action': action,
            'sender_username': sender_username
    }
    emit_socketio('friend_request_response', notification_data, room=f"user_{recipient_id}")