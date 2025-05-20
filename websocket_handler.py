"""
Python module to handle WebSocket connections for real-time messaging
"""
import json
import asyncio
import logging
from typing import Dict, Set, Any, Optional, List, Tuple

import websockets
from websockets.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed

logger = logging.getLogger(__name__)

class WebSocketHandler:
    """Handles WebSocket connections for real-time messaging"""
    
    def __init__(self):
        # Active connections: {user_id: set of websocket connections}
        self.active_connections: Dict[str, Set[WebSocketServerProtocol]] = {}
        
        # Pending messages for offline users: {user_id: list of messages}
        self.pending_messages: Dict[str, List[Dict[str, Any]]] = {}
        
        # User status tracker: {user_id: online status}
        self.user_status: Dict[str, bool] = {}

    async def register(self, websocket: WebSocketServerProtocol, user_id: str) -> None:
        """Register a new WebSocket connection for a user"""
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        
        # Add the connection to the user's set
        self.active_connections[user_id].add(websocket)
        
        # Update user status
        was_offline = not self.is_user_online(user_id)
        self.user_status[user_id] = True
        
        # Broadcast user status change if user was offline
        if was_offline:
            await self.broadcast_user_status(user_id, True)
        
        # Deliver any pending messages
        await self.deliver_pending_messages(user_id)
        
        logger.info(f"User {user_id} connected. Active connections: {len(self.active_connections[user_id])}")

    async def unregister(self, websocket: WebSocketServerProtocol, user_id: str) -> None:
        """Unregister a WebSocket connection for a user"""
        # Remove the connection
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            
            # Clean up if no more connections
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                
                # Update user status
                self.user_status[user_id] = False
                
                # Broadcast user status change
                await self.broadcast_user_status(user_id, False)
        
        logger.info(f"User {user_id} disconnected. Remaining connections: {len(self.active_connections.get(user_id, set()))}")

    def is_user_online(self, user_id: str) -> bool:
        """Check if a user is online"""
        return user_id in self.active_connections and bool(self.active_connections[user_id])

    async def broadcast_user_status(self, user_id: str, is_online: bool) -> None:
        """Broadcast user status change to all connected users"""
        # Prepare the message
        status_message = {
            "type": "user_status_change",
            "user_id": user_id,
            "is_online": is_online
        }
        
        # Send to all connected users except the user themselves
        for target_user_id, connections in self.active_connections.items():
            if target_user_id != user_id:  # Don't send to the user themselves
                await self.send_to_user(target_user_id, status_message)

    async def handle_connection(self, websocket: WebSocketServerProtocol, path: str) -> None:
        """Handle a WebSocket connection"""
        # Extract user ID from path (e.g., /ws/chat/123456)
        user_id = path.split('/')[-1]
        
        try:
            # Register the connection
            await self.register(websocket, user_id)
            
            # Handle messages
            async for message in websocket:
                await self.handle_message(user_id, message, websocket)
                
        except ConnectionClosed:
            pass
        finally:
            # Unregister the connection
            await self.unregister(websocket, user_id)

    async def handle_message(self, user_id: str, message: str, websocket: WebSocketServerProtocol) -> None:
        """Handle a message from a user"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            if message_type == 'connection_established':
                # Send acknowledgement
                await websocket.send(json.dumps({
                    "type": "connection_ack",
                    "message": "Connection established"
                }))
                
                # Send the list of online users
                await self.send_online_users(user_id)
                
            elif message_type == 'message':
                # Handle user message
                await self.handle_user_message(user_id, data)
                
            elif message_type == 'read_receipt':
                # Handle read receipt
                await self.handle_read_receipt(user_id, data)
                
            elif message_type == 'pong':
                # Handle ping response, nothing to do
                pass
            
            else:
                # Unknown message type
                logger.warning(f"Unknown message type: {message_type}")
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON message: {message}")
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def handle_user_message(self, sender_id: str, data: Dict[str, Any]) -> None:
        """Handle a user message"""
        # Extract message data
        recipient_id = data.get('recipient_id')
        session_token = data.get('session_token')
        content = data.get('content')
        iv = data.get('iv')
        header = data.get('header')
        
        if not all([recipient_id, session_token, content, iv]):
            logger.error(f"Missing required message fields from user {sender_id}")
            return
        
        # Prepare the message object
        message = {
            "type": "new_message",
            "session_token": session_token,
            "message": {
                "id": data.get('message_id', str(hash(f"{sender_id}_{recipient_id}_{content}_{iv}"))),
                "sender_id": sender_id,
                "content": content,
                "iv": iv,
                "header": header,
                "timestamp": data.get('timestamp', self._get_iso_timestamp())
            }
        }
        
        # Attempt to deliver the message
        delivered = await self.send_to_user(recipient_id, message)
        
        # Store message for later delivery if recipient is offline
        if not delivered:
            if recipient_id not in self.pending_messages:
                self.pending_messages[recipient_id] = []
            
            self.pending_messages[recipient_id].append(message)
            logger.info(f"Stored message for offline user {recipient_id}")
        
        # Send delivery acknowledgement to sender
        await self.send_to_user(sender_id, {
            "type": "message_delivered",
            "message_id": message["message"]["id"],
            "session_token": session_token,
            "recipient_id": recipient_id,
            "delivered": delivered,
            "timestamp": self._get_iso_timestamp()
        })

    async def handle_read_receipt(self, reader_id: str, data: Dict[str, Any]) -> None:
        """Handle a read receipt"""
        # Extract read receipt data
        sender_id = data.get('sender_id')
        message_id = data.get('message_id')
        session_token = data.get('session_token')
        
        if not all([sender_id, message_id, session_token]):
            logger.error(f"Missing required read receipt fields from user {reader_id}")
            return
        
        # Prepare the read receipt
        read_receipt = {
            "type": "read_receipt",
            "message_id": message_id,
            "session_token": session_token,
            "reader_id": reader_id,
            "timestamp": self._get_iso_timestamp()
        }
        
        # Send the read receipt to the message sender
        await self.send_to_user(sender_id, read_receipt)

    async def send_to_user(self, user_id: str, message: Dict[str, Any]) -> bool:
        """Send a message to a user, returns True if delivered"""
        # Check if the user is online
        if user_id not in self.active_connections:
            return False
        
        # Get the user's connections
        connections = self.active_connections[user_id]
        if not connections:
            return False
        
        # Convert message to JSON
        message_json = json.dumps(message)
        
        # Send message to all connections
        send_tasks = [self._safe_send(ws, message_json) for ws in connections]
        results = await asyncio.gather(*send_tasks, return_exceptions=True)
        
        # Return True if at least one connection received the message
        return any(result is True for result in results)

    async def _safe_send(self, websocket: WebSocketServerProtocol, message: str) -> bool:
        """Safely send a message to a WebSocket connection"""
        try:
            await websocket.send(message)
            return True
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False

    async def deliver_pending_messages(self, user_id: str) -> None:
        """Deliver any pending messages for a user"""
        if user_id not in self.pending_messages:
            return
        
        pending = self.pending_messages[user_id]
        if not pending:
            return
        
        # Try to deliver each pending message
        for message in pending:
            await self.send_to_user(user_id, message)
        
        # Clear pending messages for this user
        self.pending_messages[user_id] = []
        
        logger.info(f"Delivered {len(pending)} pending messages to user {user_id}")

    async def send_online_users(self, user_id: str) -> None:
        """Send the list of online users to a user"""
        # Get the list of online users
        online_users = [uid for uid, status in self.user_status.items() if status and uid != user_id]
        
        # Send the list to the user
        await self.send_to_user(user_id, {
            "type": "online_users",
            "users": online_users
        })

    async def start_ping_service(self, interval: int = 30) -> None:
        """Start a service to ping clients periodically to keep connections alive"""
        while True:
            try:
                # Send ping to all connected clients
                for user_id, connections in self.active_connections.items():
                    for websocket in connections:
                        try:
                            await websocket.send(json.dumps({
                                "type": "ping",
                                "timestamp": self._get_iso_timestamp()
                            }))
                        except Exception as e:
                            logger.error(f"Error sending ping to user {user_id}: {e}")
                
                # Wait for the next interval
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in ping service: {e}")
                await asyncio.sleep(5)  # Wait a bit before retrying

    def _get_iso_timestamp(self) -> str:
        """Get current ISO timestamp"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'


# Global WebSocket handler instance
ws_handler = WebSocketHandler()

async def start_websocket_server(host: str = '0.0.0.0', port: int = 8765) -> None:
    """Start the WebSocket server"""
    # Sprawdź, czy serwer już działa
    if ws_handler._running:
        logger.info("WebSocket server is already running")
        return
    
    try:
        # Start the ping service
        ping_task = asyncio.create_task(ws_handler.start_ping_service())
        
        # Start the WebSocket server
        ws_handler._running = True
        logger.info(f"Starting WebSocket server on {host}:{port}")
        
        async with websockets.serve(ws_handler.handle_connection, host, port):
            logger.info(f"WebSocket server started on {host}:{port}")
            await asyncio.Future()  # Run forever
    except Exception as e:
        logger.error(f"Error starting WebSocket server: {e}")
        ws_handler._running = False
        raise
