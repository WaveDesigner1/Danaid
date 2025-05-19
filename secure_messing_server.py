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
