/**
 * SocketManager.js - Socket.IO Communication Manager
 * Signal-inspired: handles all real-time communication
 * Complete with friend system support
 */

class SocketManager {
    constructor() {
        this.socket = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.heartbeatInterval = null;
        this.connectionTimeout = null;
    }

    // Initialize Socket.IO connection
    async initialize() {
        try {
            console.log('Initializing Socket.IO connection...');
            
            if (!window.io) {
                throw new Error('Socket.IO library not loaded');
            }

            // Initialize socket connection
            this.socket = window.io({
                transports: ['websocket', 'polling'],
                upgrade: true,
                rememberUpgrade: true,
                timeout: 10000,
                forceNew: false
            });

            // Set up event handlers
            this.setupEventHandlers();
            
            // Wait for connection
            await this.waitForConnection();
            
            console.log('Socket.IO initialized successfully');
            return true;
            
        } catch (error) {
            console.error('Failed to initialize Socket.IO:', error);
            eventBus.emit(Events.CONNECTION_ERROR, error.message);
            return false;
        }
    }

    // Wait for connection establishment
    waitForConnection() {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('Connection timeout'));
            }, 10000);

            this.socket.once('connect', () => {
                clearTimeout(timeout);
                resolve();
            });

            this.socket.once('connect_error', (error) => {
                clearTimeout(timeout);
                reject(error);
            });
        });
    }

    // Set up all Socket.IO event handlers
    setupEventHandlers() {
        if (!this.socket) return;

        // Connection events
        this.socket.on('connect', () => {
            this.onConnect();
        });

        this.socket.on('disconnect', (reason) => {
            this.onDisconnect(reason);
        });

        this.socket.on('connect_error', (error) => {
            this.onConnectionError(error);
        });

        // Message events
        this.socket.on('message', (data) => {
            this.onMessage(data);
        });

        this.socket.on('notification', (data) => {
            this.onNotification(data);
        });

        // Session events
        this.socket.on('session_switched', (data) => {
            this.onSessionSwitched(data);
        });

        this.socket.on('session_cleared', (data) => {
            this.onSessionCleared(data);
        });

        this.socket.on('session_deleted', (data) => {
            this.onSessionDeleted(data);
        });

        // Typing events
        this.socket.on('typing_status', (data) => {
            this.onTypingStatus(data);
        });

        // User status events
        this.socket.on('user_status', (data) => {
            this.onUserStatus(data);
        });

        // Friend events
        this.socket.on('friend_request', (data) => {
            this.onFriendRequest(data);
        });

        this.socket.on('friend_request_response', (data) => {
            this.onFriendRequestResponse(data);
        });

        console.log('Socket.IO event handlers configured');
    }

    // ================================================
    // CONNECTION EVENT HANDLERS
    // ================================================

    onConnect() {
        console.log('Socket.IO connected');
        this.isConnected = true;
        this.reconnectAttempts = 0;
        
        // Clear connection timeout
        if (this.connectionTimeout) {
            clearTimeout(this.connectionTimeout);
            this.connectionTimeout = null;
        }

        // Register user for targeted notifications
        this.registerUser();
        
        // Start heartbeat
        this.startHeartbeat();
        
        // Emit connection events
        eventBus.emit(Events.CONNECTION_ESTABLISHED);
        eventBus.emit(Events.SOCKET_CONNECTED);
    }

    onDisconnect(reason) {
        console.log('Socket.IO disconnected:', reason);
        this.isConnected = false;
        
        // Stop heartbeat
        this.stopHeartbeat();
        
        // Emit disconnect events
        eventBus.emit(Events.CONNECTION_LOST, reason);
        eventBus.emit(Events.SOCKET_DISCONNECTED, reason);
        
        // Attempt reconnection for certain reasons
        if (reason === 'io server disconnect') {
            console.log('Server disconnected - manual reconnection required');
        } else {
            this.attemptReconnection();
        }
    }

    onConnectionError(error) {
        console.error('Socket.IO connection error:', error);
        eventBus.emit(Events.CONNECTION_ERROR, error);
    }

    // ================================================
    // MESSAGE EVENT HANDLERS
    // ================================================

    onMessage(data) {
        console.log('Socket: Message received', data);
        eventBus.emit(Events.MESSAGE_RECEIVED, data);
    }

    onNotification(data) {
        console.log('Socket: Notification received', data);
        eventBus.emit(Events.UI_NOTIFICATION_SHOW, {
            message: data.message || 'New notification',
            type: data.type || 'info',
            data: data
        });
    }

    // ================================================
    // SESSION EVENT HANDLERS
    // ================================================

    onSessionSwitched(data) {
        console.log('Socket: Session switched', data);
        eventBus.emit(Events.SESSION_SWITCHED, data);
    }

    onSessionCleared(data) {
        console.log('Socket: Session cleared', data);
        eventBus.emit(Events.SESSION_CLEARED, data);
    }

    onSessionDeleted(data) {
        console.log('Socket: Session deleted', data);
        eventBus.emit(Events.SESSION_DELETED, data);
    }

    // ================================================
    // TYPING EVENT HANDLERS
    // ================================================

    onTypingStatus(data) {
        console.log('Socket: Typing status', data);
        if (data.typing) {
            eventBus.emit(Events.MESSAGE_TYPING_START, data);
        } else {
            eventBus.emit(Events.MESSAGE_TYPING_STOP, data);
        }
        eventBus.emit(Events.SOCKET_TYPING_STATUS, data);
    }

    // ================================================
    // USER STATUS EVENT HANDLERS
    // ================================================

    onUserStatus(data) {
        console.log('Socket: User status update', data);
        if (data.status === 'online') {
            eventBus.emit(Events.FRIEND_STATUS_ONLINE, data);
        } else if (data.status === 'offline') {
            eventBus.emit(Events.FRIEND_STATUS_OFFLINE, data);
        }
        eventBus.emit(Events.SOCKET_USER_STATUS, data);
    }

    // ================================================
    // FRIEND SYSTEM EVENT HANDLERS
    // ================================================

    onFriendRequest(data) {
        console.log('Socket: Friend request received', data);
        eventBus.emit(Events.FRIEND_REQUEST, data);
    }

    onFriendRequestResponse(data) {
        console.log('Socket: Friend request response received', data);
        eventBus.emit(Events.FRIEND_REQUEST_RESPONSE, data);
    }

    // ================================================
    // CONNECTION MANAGEMENT
    // ================================================

    // Register user for targeted Socket.IO events
    registerUser() {
        if (this.socket && this.isConnected) {
            this.socket.emit('register_user', {
                timestamp: new Date().toISOString()
            });
            console.log('User registered for Socket.IO events');
        }
    }

    // Attempt reconnection with exponential backoff
    attemptReconnection() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            eventBus.emit(Events.CONNECTION_ERROR, 'Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        
        console.log(`Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);
        eventBus.emit(Events.CONNECTION_RECONNECTING, {
            attempt: this.reconnectAttempts,
            maxAttempts: this.maxReconnectAttempts,
            delay: delay
        });

        setTimeout(() => {
            if (this.socket && !this.isConnected) {
                this.socket.connect();
            }
        }, delay);
    }

    // Start heartbeat to maintain connection
    startHeartbeat() {
        this.stopHeartbeat();
        
        this.heartbeatInterval = setInterval(() => {
            if (this.socket && this.isConnected) {
                this.socket.emit('heartbeat', {
                    timestamp: new Date().toISOString()
                });
            }
        }, 30000);
    }

    // Stop heartbeat
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    // ================================================
    // MESSAGING METHODS
    // ================================================

    // Send typing indicators
    sendTypingStart(sessionToken) {
        if (this.socket && this.isConnected) {
            this.socket.emit('typing_start', {
                session_token: sessionToken,
                timestamp: new Date().toISOString()
            });
        }
    }

    sendTypingStop(sessionToken) {
        if (this.socket && this.isConnected) {
            this.socket.emit('typing_stop', {
                session_token: sessionToken,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Join/leave session rooms
    joinSession(sessionToken) {
        if (this.socket && this.isConnected) {
            this.socket.emit('join_session', {
                session_token: sessionToken
            });
        }
    }

    leaveSession(sessionToken) {
        if (this.socket && this.isConnected) {
            this.socket.emit('leave_session', {
                session_token: sessionToken
            });
        }
    }

    // ================================================
    // MANUAL CONNECTION CONTROL
    // ================================================

    connect() {
        if (this.socket && !this.isConnected) {
            console.log('Manually connecting Socket.IO...');
            this.socket.connect();
        }
    }

    disconnect() {
        if (this.socket && this.isConnected) {
            console.log('Manually disconnecting Socket.IO...');
            this.socket.disconnect();
        }
    }

    forceReconnect() {
        console.log('Forcing Socket.IO reconnection...');
        this.reconnectAttempts = 0;
        
        if (this.socket) {
            this.socket.disconnect();
            setTimeout(() => {
                this.socket.connect();
            }, 1000);
        }
    }

    // ================================================
    // STATUS AND DEBUGGING
    // ================================================

    getStatus() {
        return {
            connected: this.isConnected,
            reconnectAttempts: this.reconnectAttempts,
            socketId: this.socket ? this.socket.id : null,
            transport: this.socket ? this.socket.io.engine.transport.name : null
        };
    }

    getDebugInfo() {
        return {
            ...this.getStatus(),
            maxReconnectAttempts: this.maxReconnectAttempts,
            reconnectDelay: this.reconnectDelay,
            heartbeatActive: !!this.heartbeatInterval,
            socketExists: !!this.socket,
            ioAvailable: !!window.io
        };
    }

    // Cleanup resources
    cleanup() {
        console.log('Cleaning up SocketManager...');
        
        this.stopHeartbeat();
        
        if (this.connectionTimeout) {
            clearTimeout(this.connectionTimeout);
        }
        
        if (this.socket) {
            this.socket.removeAllListeners();
            this.socket.disconnect();
            this.socket = null;
        }
        
        this.isConnected = false;
        this.reconnectAttempts = 0;
    }
}

// Export for global use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SocketManager;
} else {
    window.SocketManager = SocketManager;
}

console.log('🔌 SocketManager loaded with complete friend system support');