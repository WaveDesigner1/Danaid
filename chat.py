@chat_bp.route('/api/session/<session_token>/key', methods=['GET'])
@login_required
def get_session_key(session_token):
    """Pobiera zaszyfrowany klucz sesji"""
    try:
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        # Validate access
        if not validate_session_access(session_obj, current_user.id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Check for dual encryption format first
        if hasattr(session_obj, 'encrypted_keys_json') and session_obj.encrypted_keys_json:
            try:
                keys_data = json.loads(session_obj.encrypted_keys_json)
                # Try to find key for current user
                user_key = keys_data.get(str(current_user.id))
                if user_key:
                    return jsonify({
                        'status': 'success',
                        'encrypted_key': user_key,
                        'format': 'dual_encryption'
                    })
            except (json.JSONDecodeError, AttributeError):
                pass
        
        # Fallback to legacy format
        if session_obj.encrypted_session_key:
            # Mark as acknowledged
            if not session_obj.key_acknowledged:
                session_obj.key_acknowledged = True
                db.session.commit()
            
            return jsonify({
                'status': 'success',
                'encrypted_key': session_obj.encrypted_session_key,
                'format': 'legacy'
            })
        
        # No key available
        return jsonify({
            'status': 'success',
            'encrypted_key': None,
            'message': 'No session key available'
        })
        
    except Exception as e:
        print(f"❌ Get session key error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/sessions/active', methods=['GET'])
@login_required
def get_active_sessions():
    """Zwraca listę aktywnych sesji użytkownika"""
    try:
        sessions = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            ),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).order_by(desc(ChatSession.last_activity)).all()
        
        sessions_data = [format_session_for_api(s, current_user.id) for s in sessions]
        
        return jsonify({
            'status': 'success',
            'sessions': sessions_data,
            'total': len(sessions_data)
        })
        
    except Exception as e:
        print(f"❌ Get active sessions error: {e}")
        return jsonify({'error': str(e)}), 500

# === MESSAGE HANDLING ===

@chat_bp.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """Wysyła zaszyfrowaną wiadomość"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        session_token = data.get('session_token')
        content = data.get('content')
        iv = data.get('iv')
        
        if not all([session_token, content, iv]):
            return jsonify({'error': 'Missing required fields: session_token, content, iv'}), 400
        
        # Find session
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        # Validate access
        if not validate_session_access(session_obj, current_user.id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if session is active and not expired
        if not session_obj.is_active or session_obj.expires_at <= datetime.utcnow():
            return jsonify({'error': 'Session is not active or expired'}), 400
        
        # Create message
        new_message = Message(
            session_id=session_obj.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            timestamp=datetime.utcnow(),
            read=False
        )
        
        # Update session activity
        session_obj.last_activity = datetime.utcnow()
        
        db.session.add(new_message)
        db.session.commit()
        
        # Format message for response
        message_data = format_message_for_api(new_message, current_user.id)
        
        print(f"✅ Message sent in session {session_token[:8]}... by {current_user.username}")
        
        # TODO: Send real-time notification via Socket.IO
        # socketio.emit('message', {
        #     'type': 'new_message',
        #     'session_token': session_token,
        #     'message': message_data
        # }, room=f'session_{session_token}')
        
        return jsonify({
            'status': 'success',
            'message': message_data,
            'session_token': session_token
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Send message error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/messages/<session_token>', methods=['GET'])
@login_required
def get_messages(session_token):
    """Pobiera wiadomości z sesji"""
    try:
        # Get pagination parameters
        limit = min(int(request.args.get('limit', 50)), 100)  # Max 100 messages
        offset = int(request.args.get('offset', 0))
        
        # Find session
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        # Validate access
        if not validate_session_access(session_obj, current_user.id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get messages with pagination
        messages = Message.query.filter_by(session_id=session_obj.id)\
            .order_by(desc(Message.timestamp))\
            .limit(limit)\
            .offset(offset)\
            .all()
        
        # Reverse to get chronological order
        messages.reverse()
        
        # Format messages
        messages_data = [format_message_for_api(msg, current_user.id) for msg in messages]
        
        # Mark messages as read (for current user)
        unread_messages = Message.query.filter_by(
            session_id=session_obj.id,
            read=False
        ).filter(Message.sender_id != current_user.id).all()
        
        for msg in unread_messages:
            msg.read = True
        
        if unread_messages:
            db.session.commit()
        
        return jsonify({
            'status': 'success',
            'messages': messages_data,
            'total': len(messages_data),
            'has_more': len(messages) == limit
        })
        
    except Exception as e:
        print(f"❌ Get messages error: {e}")
        return jsonify({'error': str(e)}), 500

# === MESSAGE DELETION ===

@chat_bp.route('/api/message/<int:message_id>/delete', methods=['DELETE'])
@login_required
def delete_message(message_id):
    """Usuwa pojedynczą wiadomość (tylko dla nadawcy)"""
    try:
        message = Message.query.get_or_404(message_id)
        
        # Check if user owns the message
        if message.sender_id != current_user.id:
            return jsonify({'error': 'Access denied - not your message'}), 403
        
        # Optional: Check if message is not too old (24h limit)
        time_limit = datetime.utcnow() - timedelta(hours=24)
        if message.timestamp < time_limit:
            return jsonify({'error': 'Cannot delete messages older than 24 hours'}), 400
        
        # Soft delete - replace content
        message.content = "[Wiadomość została usunięta]"
        message.iv = ""  # Clear IV
        
        db.session.commit()
        
        print(f"✅ Message {message_id} deleted by user {current_user.username}")
        
        return jsonify({
            'status': 'success',
            'message': 'Message deleted successfully',
            'message_id': message_id
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Delete message error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/clear', methods=['DELETE'])
@login_required
def clear_session_messages(session_token):
    """Czyści wszystkie wiadomości w sesji"""
    try:
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        # Validate access
        if not validate_session_access(session_obj, current_user.id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Count and delete all messages in session
        messages_count = Message.query.filter_by(session_id=session_obj.id).count()
        Message.query.filter_by(session_id=session_obj.id).delete()
        
        db.session.commit()
        
        print(f"✅ Cleared {messages_count} messages from session {session_token[:8]}... by user {current_user.username}")
        
        return jsonify({
            'status': 'success',
            'message': f'Cleared {messages_count} messages from session',
            'session_token': session_token,
            'messages_deleted': messages_count
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Clear session messages error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/delete', methods=['DELETE'])
@login_required
def delete_chat_session(session_token):
    """Usuwa całą sesję czatu wraz z wiadomościami"""
    try:
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        # Validate access
        if not validate_session_access(session_obj, current_user.id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Count messages before deletion
        messages_count = Message.query.filter_by(session_id=session_obj.id).count()
        
        # Delete all messages in session
        Message.query.filter_by(session_id=session_obj.id).delete()
        
        # Delete session
        db.session.delete(session_obj)
        db.session.commit()
        
        print(f"✅ Deleted session {session_token[:8]}... with {messages_count} messages by user {current_user.username}")
        
        return jsonify({
            'status': 'success',
            'message': 'Chat session deleted successfully',
            'session_token': session_token,
            'messages_deleted': messages_count
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Delete session error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/messages/cleanup', methods=['POST'])
@login_required
def cleanup_old_messages():
    """Czyści stare wiadomości użytkownika (starsze niż 30 dni)"""
    try:
        # Set cutoff date (30 days ago)
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        # Find all user sessions
        user_sessions = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            )
        ).all()
        
        if not user_sessions:
            return jsonify({
                'status': 'success',
                'message': 'No sessions found for cleanup',
                'messages_deleted': 0
            })
        
        session_ids = [s.id for s in user_sessions]
        
        # Count old messages
        old_messages_count = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.timestamp < cutoff_date
        ).count()
        
        # Delete old messages
        Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.timestamp < cutoff_date
        ).delete(synchronize_session=False)
        
        db.session.commit()
        
        print(f"✅ Cleaned up {old_messages_count} old messages for user {current_user.username}")
        
        return jsonify({
            'status': 'success',
            'message': f'{old_messages_count} old messages cleaned up',
            'messages_deleted': old_messages_count,
            'cutoff_date': cutoff_date.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Cleanup old messages error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/messages/stats', methods=['GET'])
@login_required
def get_message_stats():
    """Zwraca statystyki wiadomości użytkownika"""
    try:
        # Find user sessions
        user_sessions = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            )
        ).all()
        
        if not user_sessions:
            return jsonify({
                'status': 'success',
                'stats': {
                    'total_sessions': 0,
                    'total_messages': 0,
                    'messages_sent': 0,
                    'messages_received': 0,
                    'old_messages': 0
                }
            })
        
        session_ids = [s.id for s in user_sessions]
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        # Count different types of messages
        total_messages = Message.query.filter(Message.session_id.in_(session_ids)).count()
        messages_sent = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.sender_id == current_user.id
        ).count()
        messages_received = total_messages - messages_sent
        old_messages = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.timestamp < cutoff_date
        ).count()
        
        stats = {
            'total_sessions': len(user_sessions),
            'total_messages': total_messages,
            'messages_sent': messages_sent,
            'messages_received': messages_received,
            'old_messages': old_messages,
            'cutoff_date': cutoff_date.isoformat()
        }
        
        return jsonify({
            'status': 'success',
            'stats': stats
        })
        
    except Exception as e:
        print(f"❌ Get message stats error: {e}")
        return jsonify({'error': str(e)}), 500

# === FRIENDS MANAGEMENT ===

@chat_bp.route('/api/friends', methods=['GET'])
@login_required
def get_friends():
    """Zwraca listę znajomych użytkownika"""
    try:
        # Get friends where current user is either user_id or friend_id
        friends_data = []
        
        # Friends where current user initiated friendship
        friends1 = db.session.query(Friend, User).join(
            User, Friend.friend_id == User.id
        ).filter(Friend.user_id == current_user.id).all()
        
        # Friends where current user received friendship
        friends2 = db.session.query(Friend, User).join(
            User, Friend.user_id == User.id
        ).filter(Friend.friend_id == current_user.id).all()
        
        # Combine and format
        all_friends = []
        for friend_rel, user in friends1 + friends2:
            if user.id != current_user.id:  # Exclude self
                all_friends.append(format_user_for_api(user))
        
        # Remove duplicates based on user_id
        seen_ids = set()
        unique_friends = []
        for friend in all_friends:
            if friend['user_id'] not in seen_ids:
                seen_ids.add(friend['user_id'])
                unique_friends.append(friend)
        
        return jsonify({
            'status': 'success',
            'friends': unique_friends,
            'total': len(unique_friends)
        })
        
    except Exception as e:
        print(f"❌ Get friends error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friends/add', methods=['POST'])
@login_required
def add_friend():
    """Wysyła zaproszenie do znajomych"""
    try:
        data = request.get_json()
        if not data or 'user_identifier' not in data:
            return jsonify({'error': 'Missing user_identifier'}), 400
        
        user_identifier = data['user_identifier'].strip()
        
        # Try to find user by username or user_id
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
        
        # Check if already friends
        existing_friendship = Friend.query.filter(
            or_(
                and_(Friend.user_id == current_user.id, Friend.friend_id == target_user.id),
                and_(Friend.user_id == target_user.id, Friend.friend_id == current_user.id)
            )
        ).first()
        
        if existing_friendship:
            return jsonify({'error': 'Already friends with this user'}), 400
        
        # Check if friend request already exists
        existing_request = FriendRequest.query.filter(
            or_(
                and_(FriendRequest.from_user_id == current_user.id, FriendRequest.to_user_id == target_user.id),
                and_(FriendRequest.from_user_id == target_user.id, FriendRequest.to_user_id == current_user.id)
            ),
            FriendRequest.status == 'pending'
        ).first()
        
        if existing_request:
            return jsonify({'error': 'Friend request already pending'}), 400
        
        # Create friend request
        friend_request = FriendRequest(
            from_user_id=current_user.id,
            to_user_id=target_user.id,
            status='pending',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.session.add(friend_request)
        db.session.commit()
        
        print(f"✅ Friend request sent from {current_user.username} to {target_user.username}")
        
        return jsonify({
            'status': 'success',
            'message': f'Friend request sent to {target_user.username}',
            'request_id': friend_request.id
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Add friend error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/pending', methods=['GET'])
@login_required
def get_pending_friend_requests():
    """Zwraca oczekujące zaproszenia do znajomych"""
    try:
        # Get pending requests sent TO current user
        requests = db.session.query(FriendRequest, User).join(
            User, FriendRequest.from_user_id == User.id
        ).filter(
            FriendRequest.to_user_id == current_user.id,
            FriendRequest.status == 'pending'
        ).order_by(desc(FriendRequest.created_at)).all()
        
        requests_data = []
        for req, sender in requests:
            requests_data.append({
                'id': req.id,
                'sender_id': req.from_user_id,
                'username': sender.username,
                'sender_user_id': sender.user_id,
                'created_at': req.created_at.isoformat(),
                'status': req.status
            })
        
        return jsonify({
            'status': 'success',
            'requests': requests_data,
            'total': len(requests_data)
        })
        
    except Exception as e:
        print(f"❌ Get friend requests error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """Przyjmuje zaproszenie do znajomych"""
    try:
        friend_request = FriendRequest.query.get_or_404(request_id)
        
        # Check if request is for current user
        if friend_request.to_user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if friend_request.status != 'pending':
            return jsonify({'error': 'Request is not pending'}), 400
        
        # Create friendship (both directions)
        friendship1 = Friend(
            user_id=current_user.id,
            friend_id=friend_request.from_user_id,
            created_at=datetime.utcnow()
        )
        
        friendship2 = Friend(
            user_id=friend_request.from_user_id,
            friend_id=current_user.id,
            created_at=datetime.utcnow()
        )
        
        # Update request status
        friend_request.status = 'accepted'
        friend_request.updated_at = datetime.utcnow()
        
        db.session.add(friendship1)
        db.session.add(friendship2)
        db.session.commit()
        
        # Get sender info for response
        sender = User.query.get(friend_request.from_user_id)
        
        print(f"✅ Friend request accepted: {sender.username} and {current_user.username} are now friends")
        
        return jsonify({
            'status': 'success',
            'message': f'You are now friends with {sender.username}',
            'friend': format_user_for_api(sender)
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Accept friend request error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """Odrzuca zaproszenie do znajomych"""
    try:
        friend_request = FriendRequest.query.get_or_404(request_id)
        
        # Check if request is for current user
        if friend_request.to_user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if friend_request.status != 'pending':
            return jsonify({'error': 'Request is not pending'}), 400
        
        # Update request status
        friend_request.status = 'rejected'
        friend_request.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        sender = User.query.get(friend_request.from_user_id)
        
        print(f"✅ Friend request rejected: {current_user.username} rejected {sender.username}")
        
        return jsonify({
            'status': 'success',
            'message': 'Friend request rejected'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Reject friend request error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/friends/<int:friend_id>', methods=['DELETE'])
@login_required
def remove_friend(friend_id):
    """Usuwa znajomego"""
    try:
        # Find friendships (both directions)
        friendship1 = Friend.query.filter_by(
            user_id=current_user.id, 
            friend_id=friend_id
        ).first()
        
        friendship2 = Friend.query.filter_by(
            user_id=friend_id, 
            friend_id=current_user.id
        ).first()
        
        if not friendship1 and not friendship2:
            return jsonify({'error': 'Friendship not found'}), 404
        
        # Remove both directions
        if friendship1:
            db.session.delete(friendship1)
        if friendship2:
            db.session.delete(friendship2)
        
        db.session.commit()
        
        friend_user = User.query.get(friend_id)
        friend_name = friend_user.username if friend_user else "Unknown"
        
        print(f"✅ Friendship removed: {current_user.username} and {friend_name}")
        
        return jsonify({
            'status': 'success',
            'message': f'Removed {friend_name} from friends'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Remove friend error: {e}")
        return jsonify({'error': str(e)}), 500

# === UTILITY ENDPOINTS ===

@chat_bp.route('/api/user/<user_id>/public_key', methods=['GET'])
@login_required
def get_user_public_key(user_id):
    """Zwraca klucz publiczny użytkownika"""
    try:
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if users are friends (security check)
        friendship = Friend.query.filter(
            or_(
                and_(Friend.user_id == current_user.id, Friend.friend_id == user.id),
                and_(Friend.user_id == user.id, Friend.friend_id == current_user.id)
            )
        ).first()
        
        if not friendship:
            return jsonify({'error': 'Access denied - not friends'}), 403
        
        return jsonify({
            'status': 'success',
            'user_id': user.user_id,
            'username': user.username,
            'public_key': user.public_key
        })
        
    except Exception as e:
        print(f"❌ Get public key error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/user/search', methods=['GET'])
@login_required
def search_users():
    """Wyszukuje użytkowników (do dodawania znajomych)"""
    try:
        query = request.args.get('q', '').strip()
        if not query or len(query) < 2:
            return jsonify({'error': 'Query too short (minimum 2 characters)'}), 400
        
        # Search by username or user_id
        users = User.query.filter(
            or_(
                User.username.ilike(f'%{query}%'),
                User.user_id.like(f'{query}%')
            )
        ).filter(User.id != current_user.id).limit(10).all()
        
        users_data = []
        for user in users:
            # Check if already friends
            is_friend = Friend.query.filter(
                or_(
                    and_(Friend.user_id == current_user.id, Friend.friend_id == user.id),
                    and_(Friend.user_id == user.id, Friend.friend_id == current_user.id)
                )
            ).first() is not None
            
            # Check if request pending
            pending_request = FriendRequest.query.filter(
                or_(
                    and_(FriendRequest.from_user_id == current_user.id, FriendRequest.to_user_id == user.id),
                    and_(FriendRequest.from_user_id == user.id, FriendRequest.to_user_id == current_user.id)
                ),
                FriendRequest.status == 'pending'
            ).first() is not None
            
            user_data = format_user_for_api(user)
            user_data['is_friend'] = is_friend
            user_data['request_pending'] = pending_request
            users_data.append(user_data)
        
        return jsonify({
            'status': 'success',
            'users': users_data,
            'total': len(users_data)
        })
        
    except Exception as e:
        print(f"❌ Search users error: {e}")
        return jsonify({'error': str(e)}), 500

# === ADMIN ENDPOINTS ===

@chat_bp.route('/api/admin/sessions', methods=['GET'])
@login_required
def admin_get_sessions():
    """Lista wszystkich sesji (tylko admin)"""
    try:
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'error': 'Admin access required'}), 403
        
        sessions = ChatSession.query.order_by(desc(ChatSession.created_at)).limit(100).all()
        
        sessions_data = []
        for session in sessions:
            initiator = User.query.get(session.initiator_id)
            recipient = User.query.get(session.recipient_id)
            
        sessions_data = []
        for session in sessions:
            initiator = User.query.get(session.initiator_id)
            recipient = User.query.get(session.recipient_id)
            
            sessions_data.append({
                'id': session.id,
                'token': session.session_token[:8] + '...',  # Partial for security
                'initiator': initiator.username if initiator else 'Unknown',
                'recipient': recipient.username if recipient else 'Unknown',
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat() if session.last_activity else None,
                'is_active': session.is_active,
                'has_key': bool(session.encrypted_session_key),
                'message_count': Message.query.filter_by(session_id=session.id).count()
            })
        
        return jsonify({
            'status': 'success',
            'sessions': sessions_data,
            'total': len(sessions_data)
        })
        
    except Exception as e:
        print(f"❌ Admin get sessions error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/admin/cleanup/expired', methods=['POST'])
@login_required
def admin_cleanup_expired():
    """Czyści wygasłe sesje (tylko admin)"""
    try:
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'error': 'Admin access required'}), 403
        
        # Find expired sessions
        expired_sessions = ChatSession.query.filter(
            ChatSession.expires_at <= datetime.utcnow()
        ).all()
        
        total_messages = 0
        for session in expired_sessions:
            # Count messages before deletion
            message_count = Message.query.filter_by(session_id=session.id).count()
            total_messages += message_count
            
            # Delete messages
            Message.query.filter_by(session_id=session.id).delete()
        
        # Delete expired sessions
        sessions_deleted = len(expired_sessions)
        for session in expired_sessions:
            db.session.delete(session)
        
        db.session.commit()
        
        print(f"✅ Admin cleanup: {sessions_deleted} expired sessions, {total_messages} messages deleted")
        
        return jsonify({
            'status': 'success',
            'message': f'Cleaned up {sessions_deleted} expired sessions and {total_messages} messages',
            'sessions_deleted': sessions_deleted,
            'messages_deleted': total_messages
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Admin cleanup error: {e}")
        return jsonify({'error': str(e)}), 500

# === POLLING FALLBACK (for when Socket.IO fails) ===

@chat_bp.route('/api/polling/messages', methods=['GET'])
@login_required
def polling_messages():
    """Polling endpoint dla nowych wiadomości (fallback gdy Socket.IO nie działa)"""
    try:
        last_id = int(request.args.get('last_id', 0))
        
        # Find user's active sessions
        user_sessions = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            ),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        if not user_sessions:
            return jsonify({
                'status': 'success',
                'messages': [],
                'last_id': last_id
            })
        
        session_ids = [s.id for s in user_sessions]
        
        # Get new messages since last_id
        new_messages = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.id > last_id,
            Message.sender_id != current_user.id  # Only messages from others
        ).order_by(Message.id).limit(50).all()
        
        messages_data = []
        max_id = last_id
        
        for msg in new_messages:
            # Find which session this message belongs to
            session = next((s for s in user_sessions if s.id == msg.session_id), None)
            if session:
                message_data = {
                    'type': 'new_message',
                    'session_token': session.session_token,
                    'message': format_message_for_api(msg, current_user.id)
                }
                messages_data.append(message_data)
                max_id = max(max_id, msg.id)
        
        return jsonify({
            'status': 'success',
            'messages': messages_data,
            'last_id': max_id
        })
        
    except Exception as e:
        print(f"❌ Polling messages error: {e}")
        return jsonify({'error': str(e)}), 500

# === DEBUG ENDPOINTS ===

@chat_bp.route('/api/debug/session/<session_token>', methods=['GET'])
@login_required
def debug_session(session_token):
    """Debug informacje o sesji"""
    try:
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        # Validate access
        if not validate_session_access(session_obj, current_user.id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get session info
        initiator = User.query.get(session_obj.initiator_id)
        recipient = User.query.get(session_obj.recipient_id)
        message_count = Message.query.filter_by(session_id=session_obj.id).count()
        
        debug_info = {
            'session': {
                'id': session_obj.id,
                'token': session_obj.session_token,
                'initiator': initiator.username if initiator else 'Unknown',
                'recipient': recipient.username if recipient else 'Unknown',
                'created_at': session_obj.created_at.isoformat(),
                'last_activity': session_obj.last_activity.isoformat() if session_obj.last_activity else None,
                'expires_at': session_obj.expires_at.isoformat(),
                'is_active': session_obj.is_active,
                'has_legacy_key': bool(session_obj.encrypted_session_key),
                'has_dual_keys': bool(getattr(session_obj, 'encrypted_keys_json', None)),
                'key_acknowledged': session_obj.key_acknowledged,
                'message_count': message_count
            },
            'current_user': {
                'id': current_user.id,
                'username': current_user.username,
                'user_id': current_user.user_id,
                'is_initiator': session_obj.initiator_id == current_user.id
            }
        }
        
        return jsonify({
            'status': 'success',
            'debug': debug_info
        })
        
    except Exception as e:
        print(f"❌ Debug session error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/debug/crypto/test', methods=['POST'])
@login_required
def debug_crypto_test():
    """Test endpoint dla sprawdzania kryptografii"""
    try:
        data = request.get_json()
        test_type = data.get('type', 'basic')
        
        if test_type == 'basic':
            # Basic test response
            return jsonify({
                'status': 'success',
                'message': 'Crypto test endpoint working',
                'user': current_user.username,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        elif test_type == 'encryption':
            # Test message encryption/decryption flow
            test_content = data.get('content', 'Test message')
            test_iv = data.get('iv', 'dGVzdGl2MTIzNDU2Nzg=')  # Base64 encoded test IV
            
            return jsonify({
                'status': 'success',
                'test_data': {
                    'original_content': test_content,
                    'received_iv': test_iv,
                    'content_length': len(test_content),
                    'iv_decoded_length': len(base64.b64decode(test_iv)) if test_iv else 0
                }
            })
        
        else:
            return jsonify({'error': 'Unknown test type'}), 400
        
    except Exception as e:
        print(f"❌ Debug crypto test error: {e}")
        return jsonify({'error': str(e)}), 500

# === MAINTENANCE ENDPOINTS ===

@chat_bp.route('/api/maintenance/sessions/refresh', methods=['POST'])
@login_required
def refresh_expired_sessions():
    """Odświeża sesje które wkrótce wygasną"""
    try:
        # Find sessions expiring in next hour that are still active
        soon_expiring = datetime.utcnow() + timedelta(hours=1)
        
        sessions_to_refresh = ChatSession.query.filter(
            or_(
                ChatSession.initiator_id == current_user.id,
                ChatSession.recipient_id == current_user.id
            ),
            ChatSession.is_active == True,
            ChatSession.expires_at <= soon_expiring,
            ChatSession.expires_at > datetime.utcnow()
        ).all()
        
        refreshed_count = 0
        for session in sessions_to_refresh:
            # Extend expiry by 24 hours
            session.expires_at = datetime.utcnow() + timedelta(hours=24)
            session.last_activity = datetime.utcnow()
            refreshed_count += 1
        
        if refreshed_count > 0:
            db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Refreshed {refreshed_count} sessions',
            'sessions_refreshed': refreshed_count
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Refresh sessions error: {e}")
        return jsonify({'error': str(e)}), 500

# === ERROR HANDLERS ===

@chat_bp.errorhandler(404)
def chat_not_found(error):
    """Handler dla błędów 404 w chat module"""
    return jsonify({'error': 'Chat endpoint not found'}), 404

@chat_bp.errorhandler(500)
def chat_server_error(error):
    """Handler dla błędów 500 w chat module"""
    db.session.rollback()
    return jsonify({'error': 'Internal chat server error'}), 500

# === HEALTH CHECK ===

@chat_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        
        # Get basic stats
        total_users = User.query.count()
        active_sessions = ChatSession.query.filter(
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).count()
        
        total_messages = Message.query.count()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'stats': {
                'total_users': total_users,
                'active_sessions': active_sessions,
                'total_messages': total_messages
            },
            'database': 'connected',
            'version': '1.0.0'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

print("✅ chat.py loaded - Chat system ready")

        # chat.py - Kompletny system czatu dla Danaid Chat
# Obsługa sesji, wiadomości, znajomych i zarządzania czatem

from flask import Blueprint, request, jsonify, session
from flask_login import login_required, current_user
from models import User, ChatSession, Message, Friend, FriendRequest, db
from datetime import datetime, timedelta
from sqlalchemy import or_, and_, desc
import secrets
import json
import base64

# Utwórz Blueprint
chat_bp = Blueprint('chat', __name__)

# === HELPER FUNCTIONS ===

def generate_session_token():
    """Generuje bezpieczny token sesji"""
    return secrets.token_urlsafe(32)

def validate_session_access(session_obj, user_id):
    """Sprawdza czy użytkownik ma dostęp do sesji"""
    return session_obj.initiator_id == user_id or session_obj.recipient_id == user_id

def get_other_user_in_session(session_obj, current_user_id):
    """Zwraca drugiego użytkownika w sesji"""
    if session_obj.initiator_id == current_user_id:
        return User.query.get(session_obj.recipient_id)
    else:
        return User.query.get(session_obj.initiator_id)

def format_user_for_api(user):
    """Formatuje dane użytkownika dla API"""
    if not user:
        return None
    
    return {
        'id': user.id,
        'user_id': user.user_id,
        'username': user.username,
        'is_online': getattr(user, 'is_online', False),
        'last_active': user.last_active.isoformat() if hasattr(user, 'last_active') and user.last_active else None
    }

def format_session_for_api(session_obj, current_user_id):
    """Formatuje sesję dla API"""
    other_user = get_other_user_in_session(session_obj, current_user_id)
    
    return {
        'id': session_obj.id,
        'token': session_obj.session_token,
        'created_at': session_obj.created_at.isoformat(),
        'last_activity': session_obj.last_activity.isoformat() if session_obj.last_activity else None,
        'expires_at': session_obj.expires_at.isoformat(),
        'is_active': session_obj.is_active,
        'has_key': bool(session_obj.encrypted_session_key),
        'key_acknowledged': session_obj.key_acknowledged,
        'other_user': format_user_for_api(other_user)
    }

def format_message_for_api(message, current_user_id):
    """Formatuje wiadomość dla API"""
    return {
        'id': message.id,
        'sender_id': message.sender_id,
        'content': message.content,
        'iv': message.iv,
        'timestamp': message.timestamp.isoformat(),
        'read': message.read,
        'is_mine': message.sender_id == current_user_id
    }

# === SESSION MANAGEMENT ===

@chat_bp.route('/api/session/init', methods=['POST'])
@login_required
def init_session():
    """Inicjalizuje nową sesję czatu lub zwraca istniejącą"""
    try:
        data = request.get_json()
        if not data or 'recipient_id' not in data:
            return jsonify({'error': 'Missing recipient_id'}), 400
        
        recipient_id = data['recipient_id']
        
        # Znajdź użytkownika odbiorcy
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Sprawdź czy użytkownicy są znajomymi
        friendship = Friend.query.filter(
            or_(
                and_(Friend.user_id == current_user.id, Friend.friend_id == recipient.id),
                and_(Friend.user_id == recipient.id, Friend.friend_id == current_user.id)
            )
        ).first()
        
        if not friendship:
            return jsonify({'error': 'Users are not friends'}), 403
        
        # Sprawdź czy istnieje aktywna sesja między tymi użytkownikami
        existing_session = ChatSession.query.filter(
            or_(
                and_(ChatSession.initiator_id == current_user.id, ChatSession.recipient_id == recipient.id),
                and_(ChatSession.initiator_id == recipient.id, ChatSession.recipient_id == current_user.id)
            ),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.utcnow()
        ).first()
        
        if existing_session:
            print(f"✅ Found existing session: {existing_session.session_token[:8]}... between {current_user.username} and {recipient.username}")
            return jsonify({
                'status': 'success',
                'session': format_session_for_api(existing_session, current_user.id),
                'message': 'Existing session found'
            })
        
        # Utwórz nową sesję
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + timedelta(hours=24)  # 24h expiry
        
        new_session = ChatSession(
            session_token=session_token,
            initiator_id=current_user.id,
            recipient_id=recipient.id,
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            expires_at=expires_at,
            is_active=True,
            encrypted_session_key=None,
            key_acknowledged=False
        )
        
        db.session.add(new_session)
        db.session.commit()
        
        print(f"✅ New session created: {session_token[:8]}... between {current_user.username} and {recipient.username}")
        
        return jsonify({
            'status': 'success',
            'session': format_session_for_api(new_session, current_user.id),
            'message': 'New session created'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Session init error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/exchange_key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """Wymienia klucz sesji między użytkownikami"""
    try:
        data = request.get_json()
        
        # Find session
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if not session_obj:
            return jsonify({'error': 'Session not found'}), 404
        
        # Validate access
        if not validate_session_access(session_obj, current_user.id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Handle different key exchange formats
        if 'encrypted_key' in data:
            # Legacy format - single encrypted key
            encrypted_key = data['encrypted_key']
            session_obj.encrypted_session_key = encrypted_key
            session_obj.key_acknowledged = False
            key_generator = current_user.id
            
        elif 'keys' in data:
            # New format - dual encryption with keys for both users
            keys_data = data['keys']
            if isinstance(keys_data, dict):
                # Store as JSON for multiple keys
                session_obj.encrypted_keys_json = json.dumps(keys_data)
                session_obj.key_generator_id = current_user.id
            else:
                return jsonify({'error': 'Invalid keys format'}), 400
            key_generator = current_user.id
            
        else:
            return jsonify({'error': 'Missing encrypted_key or keys'}), 400
        
        # Update session
        session_obj.last_activity = datetime.utcnow()
        db.session.commit()
        
        print(f"✅ Session key exchanged for session {session_token[:8]}... by user {current_user.username}")
        
        return jsonify({
            'status': 'success',
            'message': 'Session key exchanged successfully',
            'key_generator': key_generator,
            'session_token': session_token
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Key exchange error: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/key', methods=['GET'])
@login_required
def get_session_key(session_token):
    """Pobiera zaszyfrowany klucz sesji"""
    try:
        session_obj = ChatSession.query.filter_by(session_token=session_token).first()
        if
