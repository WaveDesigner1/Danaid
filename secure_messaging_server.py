from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime
import logging

# Configure logger
logger = logging.getLogger(__name__)

# Create blueprint
secure_messaging = Blueprint('secure_messaging', __name__)

# Import models - nie importujemy pełnych modeli, tylko używamy tych z głównej aplikacji
# Modele FriendRequest i Message muszą być dodane do models.py jeśli jeszcze ich tam nie ma

@secure_messaging.route('/api/friend_requests', methods=['POST'])
@login_required
def send_friend_request():
    """Send a friend request to another user"""
    data = request.get_json()
    
    if not data or 'recipient_id' not in data:
        return jsonify({
            'status': 'error',
            'message': 'Brak wymaganego parametru recipient_id'
        }), 400
    
    recipient_id = data['recipient_id']
    
    # Check if recipient exists
    from models import User, FriendRequest, db
    recipient = User.query.filter_by(user_id=recipient_id).first()
    if not recipient:
        return jsonify({
            'status': 'error',
            'message': 'Użytkownik nie został znaleziony'
        }), 404
    
    # Check if sender and recipient are the same
    if recipient.id == current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Nie możesz wysłać zaproszenia do samego siebie'
        }), 400
    
    # Check if request already exists
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie do znajomych już istnieje'
        }), 400
    
    # Check if already friends
    if current_user.is_friend_with(recipient.id):
        return jsonify({
            'status': 'error',
            'message': 'Już jesteście znajomymi'
        }), 400
    
    # Create new friend request
    friend_request = FriendRequest(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        status='pending',
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.session.add(friend_request)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Zaproszenie do znajomych wysłane',
        'request_id': friend_request.id
    }), 201

@secure_messaging.route('/api/friend_requests/pending', methods=['GET'])
@login_required
def get_pending_requests():
    """Get all pending friend requests for current user"""
    from models import User, FriendRequest
    pending_requests = FriendRequest.query.filter_by(
        recipient_id=current_user.id,
        status='pending'
    ).all()
    
    requests_list = []
    for req in pending_requests:
        sender = User.query.get(req.sender_id)
        requests_list.append({
            'id': req.id,
            'sender_id': sender.user_id,
            'sender_name': sender.username,
            'created_at': req.created_at.isoformat()
        })
    
    return jsonify({
        'status': 'success',
        'requests': requests_list
    })

@secure_messaging.route('/api/friend_requests/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """Accept a friend request"""
    # Find the friend request
    from models import FriendRequest, db
    friend_request = FriendRequest.query.filter_by(id=request_id, recipient_id=current_user.id).first()
    
    # Check if request exists
    if not friend_request:
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie nie zostało znalezione'
        }), 404
    
    # Check if already processed
    if friend_request.status != 'pending':
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie zostało już przetworzone'
        }), 400
    
    # Update request status
    friend_request.status = 'accepted'
    friend_request.updated_at = datetime.utcnow()
    
    # Create friendship connection (depends on your data model)
    current_user.add_friend(friend_request.sender_id)
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Zaproszenie zaakceptowane'
    })

@secure_messaging.route('/api/friend_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """Reject a friend request"""
    # Find the friend request
    from models import FriendRequest, db
    friend_request = FriendRequest.query.filter_by(id=request_id, recipient_id=current_user.id).first()
    
    # Check if request exists
    if not friend_request:
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie nie zostało znalezione'
        }), 404
    
    # Check if already processed
    if friend_request.status != 'pending':
        return jsonify({
            'status': 'error',
            'message': 'Zaproszenie zostało już przetworzone'
        }), 400
    
    # Update request status
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
    """Get list of online users"""
    # Query users with is_online = True
    from models import User
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
    """Get list of user's friends"""
    friends = current_user.get_friends()
    
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

@secure_messaging.route('/api/messages/<string:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    """Send a message to another user"""
    data = request.get_json()
    
    if not data or 'content' not in data:
        return jsonify({
            'status': 'error',
            'message': 'Brak wymaganego parametru content'
        }), 400
    
    # Check if recipient exists
    from models import User, Message, db
    recipient = User.query.filter_by(user_id=recipient_id).first()
    if not recipient:
        return jsonify({
            'status': 'error',
            'message': 'Użytkownik nie został znaleziony'
        }), 404
    
    # Check if users are friends
    if not current_user.is_friend_with(recipient.id):
        return jsonify({
            'status': 'error',
            'message': 'Możesz wysyłać wiadomości tylko do znajomych'
        }), 403
    
    # Create new message
    message = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        content=data['content'],
        sent_at=datetime.utcnow(),
        is_read=False
    )
    
    db.session.add(message)
    db.session.commit()
    
    # WebSocket notification would be triggered here
    
    return jsonify({
        'status': 'success',
        'message': 'Wiadomość wysłana',
        'message_id': message.id
    }), 201

@secure_messaging.route('/api/messages/<string:user_id>', methods=['GET'])
@login_required
def get_messages(user_id):
    """Get conversation with another user"""
    # Check if user exists
    from models import User, Message, db
    other_user = User.query.filter_by(user_id=user_id).first()
    if not other_user:
        return jsonify({
            'status': 'error',
            'message': 'Użytkownik nie został znaleziony'
        }), 404
    
    # Get messages between users
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == other_user.id)) |
        ((Message.sender_id == other_user.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.sent_at.asc()).all()
    
    # Mark received messages as read
    for msg in messages:
        if msg.recipient_id == current_user.id and not msg.is_read:
            msg.is_read = True
    
    db.session.commit()
    
    # Format messages
    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg.id,
            'sender_id': User.query.get(msg.sender_id).user_id,
            'content': msg.content,
            'sent_at': msg.sent_at.isoformat(),
            'is_read': msg.is_read
        })
    
    return jsonify({
        'status': 'success',
        'messages': message_list
    })

# WebSocket endpoint - this will be handled separately by the websocket_handler.py
def start_websocket_server():
    """Start WebSocket server in a separate thread"""
    import threading
    import asyncio
    from websocket_handler import start_websocket_server
    
    # Create a new event loop for the thread
    def run_websocket_server():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start_websocket_server())
        loop.close()
    
    # Start the server in a separate thread
    thread = threading.Thread(target=run_websocket_server)
    thread.daemon = True
    thread.start()
    
    logger.info("WebSocket server started in separate thread")

def initialize_app(app):
    """Initialize the secure messaging module"""
    # Register the blueprint
    app.register_blueprint(secure_messaging)
    
    # Start WebSocket server
    start_websocket_server()
    
    logger.info("Secure messaging module initialized")
