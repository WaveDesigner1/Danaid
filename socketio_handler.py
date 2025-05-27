"""
Socket.IO handler for real-time messaging
"""
import logging
from typing import Dict, List, Any
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask import request

logger = logging.getLogger(__name__)

class SocketIOHandler:
    """Handles Socket.IO connections for real-time messaging"""
    
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        # Active connections: {user_id: set of session_ids}
        self.active_connections: Dict[str, set] = {}
        # Session to user mapping: {session_id: user_id}
        self.session_users: Dict[str, str] = {}
        # Pending messages for offline users: {user_id: list of messages}
        self.pending_messages: Dict[str, List[Dict[str, Any]]] = {}
        
        # Register Socket.IO event handlers
        self._register_handlers()
    
    def _register_handlers(self):
        """Register all Socket.IO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect(auth):
            """Handle client connection"""
            session_id = request.sid
            logger.info(f"Client connected: {session_id}")
            
            # Send connection acknowledgement
            emit('connection_ack', {
                'message': 'Connected to server',
                'session_id': session_id,
                'timestamp': self._get_iso_timestamp()
            })
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            session_id = request.sid
            user_id = self.session_users.get(session_id)
            
            if user_id:
                self._unregister_user(session_id, user_id)
            
            logger.info(f"Client disconnected: {session_id}")
        
        @self.socketio.on('register_user')
        def handle_register_user(data):
            """Register user with their session"""
            session_id = request.sid
            user_id = data.get('user_id')
            
            if not user_id:
                emit('error', {'message': 'user_id is required'})
                return
            
            # Register the user
            self._register_user(session_id, user_id)
            
            # Send list of online users
            self._send_online_users(user_id)
            
            # Deliver any pending messages
            self._deliver_pending_messages(user_id)
            
            logger.info(f"User {user_id} registered with session {session_id}")
        
        @self.socketio.on('send_message')
        def handle_send_message(data):
            """Handle user message"""
            session_id = request.sid
            sender_id = self.session_users.get(session_id)
            
            if not sender_id:
                emit('error', {'message': 'User not registered'})
                return
            
            recipient_id = data.get('recipient_id')
            session_token = data.get('session_token')
            content = data.get('content')
            iv = data.get('iv')
            header = data.get('header')
            message_id = data.get('message_id')
            
            if not all([recipient_id, session_token, content, iv]):
                emit('error', {'message': 'Missing required message fields'})
                return
            
            # Create message object
            message = {
                'type': 'new_message',
                'session_token': session_token,
                'message': {
                    'id': message_id or str(hash(f"{sender_id}_{recipient_id}_{content}_{iv}")),
                    'sender_id': sender_id,
                    'content': content,
                    'iv': iv,
                    'header': header,
                    'timestamp': self._get_iso_timestamp()
                }
            }
            
            # Try to deliver the message
            delivered = self._send_to_user(recipient_id, message)
            
            # Store for later delivery if recipient is offline
            if not delivered:
                if recipient_id not in self.pending_messages:
                    self.pending_messages[recipient_id] = []
                self.pending_messages[recipient_id].append(message)
                logger.info(f"Stored message for offline user {recipient_id}")
            
            # Send delivery confirmation to sender
            emit('message_delivered', {
                'message_id': message['message']['id'],
                'session_token': session_token,
                'recipient_id': recipient_id,
                'delivered': delivered,
                'timestamp': self._get_iso_timestamp()
            })
        
        @self.socketio.on('send_read_receipt')
        def handle_read_receipt(data):
            """Handle read receipt"""
            session_id = request.sid
            reader_id = self.session_users.get(session_id)
            
            if not reader_id:
                emit('error', {'message': 'User not registered'})
                return
            
            sender_id = data.get('sender_id')
            message_id = data.get('message_id')
            session_token = data.get('session_token')
            
            if not all([sender_id, message_id, session_token]):
                emit('error', {'message': 'Missing required read receipt fields'})
                return
            
            # Create read receipt
            read_receipt = {
                'type': 'read_receipt',
                'message_id': message_id,
                'session_token': session_token,
                'reader_id': reader_id,
                'timestamp': self._get_iso_timestamp()
            }
            
            # Send to message sender
            self._send_to_user(sender_id, read_receipt)
        
        @self.socketio.on('ping')
        def handle_ping():
            """Handle ping from client"""
            emit('pong', {'timestamp': self._get_iso_timestamp()})
    
    def _register_user(self, session_id: str, user_id: str):
        """Register a user session"""
        # Track user's sessions
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        
        was_offline = len(self.active_connections[user_id]) == 0
        self.active_connections[user_id].add(session_id)
        self.session_users[session_id] = user_id
        
        # Join user to their personal room
        join_room(f"user_{user_id}")
        
        # Broadcast user status change if user was offline
        if was_offline:
            self._broadcast_user_status(user_id, True)
    
    def _unregister_user(self, session_id: str, user_id: str):
        """Unregister a user session"""
        # Remove session tracking
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(session_id)
            
            # Clean up if no more sessions
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                self._broadcast_user_status(user_id, False)
        
        # Remove session mapping
        if session_id in self.session_users:
            del self.session_users[session_id]
        
        # Leave user room
        leave_room(f"user_{user_id}")
    
    def _send_to_user(self, user_id: str, message: Dict[str, Any]) -> bool:
        """Send message to a specific user"""
        if user_id not in self.active_connections:
            return False
        
        # Send to user's room
        self.socketio.emit('message', message, room=f"user_{user_id}")
        return True
    
    def _broadcast_user_status(self, user_id: str, is_online: bool):
        """Broadcast user status change to all users"""
        status_message = {
            'type': 'user_status_change',
            'user_id': user_id,
            'is_online': is_online
        }
        
        # Broadcast to all connected users except the user themselves
        for connected_user_id in self.active_connections:
            if connected_user_id != user_id:
                self._send_to_user(connected_user_id, status_message)
    
    def _send_online_users(self, user_id: str):
        """Send list of online users to a user"""
        online_users = [uid for uid in self.active_connections.keys() if uid != user_id]
        
        self._send_to_user(user_id, {
            'type': 'online_users',
            'users': online_users
        })
    
    def _deliver_pending_messages(self, user_id: str):
        """Deliver pending messages to a user"""
        if user_id not in self.pending_messages:
            return
        
        pending = self.pending_messages[user_id]
        if not pending:
            return
        
        # Send each pending message
        for message in pending:
            self._send_to_user(user_id, message)
        
        # Clear pending messages
        self.pending_messages[user_id] = []
        logger.info(f"Delivered {len(pending)} pending messages to user {user_id}")
    
    def _get_iso_timestamp(self) -> str:
        """Get current ISO timestamp"""
        return datetime.utcnow().isoformat() + 'Z'
    
    def is_user_online(self, user_id: str) -> bool:
        """Check if user is online"""
        return user_id in self.active_connections

# Global handler instance (will be initialized in app.py)
socketio_handler = None

def init_socketio_handler(socketio: SocketIO):
    """Initialize the global Socket.IO handler"""
    global socketio_handler
    socketio_handler = SocketIOHandler(socketio)
    return socketio_handler
