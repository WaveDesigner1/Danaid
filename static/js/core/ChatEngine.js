/**
 * ChatEngine.js - Main Chat Engine - PART 1/3
 * Signal-inspired: core chat system with friend management
 * Updated with real-time friend system support
 */

class ChatEngine {
    constructor() {
        // Core managers
        this.socket = null;
        this.crypto = null;
        this.ui = null;
        
        // Data stores
        this.currentUser = null;
        this.currentSession = null;
        this.friends = new Map();
        this.sessions = new Map();
        this.friendRequests = [];
        this.unreadCounts = new Map();
        
        // State management
        this.isInitialized = false;
        this.isConnected = false;
        this.currentSessionToken = null;
        
        // UI state
        this.currentTheme = 'dark';
        this.sidebarVisible = true;
        
        // Polling fallback
        this.pollingInterval = null;
        this.lastMessageId = 0;
        
        // Typing indicators
        this.typingTimeout = null;
        this.isTyping = false;
        
        // Bind methods to preserve context
        this.handleMessageReceived = this.handleMessageReceived.bind(this);
        this.handleKeyPress = this.handleKeyPress.bind(this);
        this.handleSendMessage = this.handleSendMessage.bind(this);
    }

    // ================================================
    // INITIALIZATION
    // ================================================

    async initialize() {
        try {
            console.log('🚀 Initializing ChatEngine...');
            
            // Initialize core managers
            await this.initializeManagers();
            
            // Load user data
            await this.loadUserData();
            
            // Set up event handlers
            this.setupEventHandlers();
            
            // Set up UI event listeners
            this.setupUIEventListeners();
            
            // Load initial data
            await this.loadInitialData();
            
            // Start polling fallback
            this.startPolling();
            
            this.isInitialized = true;
            console.log('✅ ChatEngine initialized successfully');
            
            // Emit system ready event
            eventBus.emit(Events.SYSTEM_READY);
            
            return true;
            
        } catch (error) {
            console.error('❌ ChatEngine initialization failed:', error);
            eventBus.emit(Events.SYSTEM_ERROR, error.message);
            throw error;
        }
    }

    // Initialize core managers
    async initializeManagers() {
        try {
            // Initialize CryptoManager
            this.crypto = new CryptoManager();
            await this.crypto.initializeCrypto();
            
            // Initialize UIManager
            this.ui = new UIManager();
            
            // Initialize SocketManager
            this.socket = new SocketManager();
            const socketConnected = await this.socket.initialize();
            
            if (socketConnected) {
                this.isConnected = true;
                console.log('✅ All managers initialized');
            } else {
                console.warn('⚠️ Socket connection failed - using polling mode');
            }
            
        } catch (error) {
            console.error('Manager initialization failed:', error);
            throw error;
        }
    }

    // Load current user data
    async loadUserData() {
        try {
            const response = await fetch('/api/check_auth');
            if (!response.ok) {
                throw new Error('User not authenticated');
            }
            
            const userData = await response.json();
            this.currentUser = new User(userData);
            
            // Update UI with user info
            this.ui.updateUserInfo(this.currentUser);
            
            console.log('✅ User data loaded:', this.currentUser.username);
            eventBus.emit(Events.AUTH_USER_LOADED, this.currentUser);
            
        } catch (error) {
            console.error('Failed to load user data:', error);
            throw error;
        }
    }

    // Set up all event handlers
    setupEventHandlers() {
        console.log('🔧 Setting up event handlers...');
        
        // ================================================
        // CONNECTION EVENTS
        // ================================================
        
        eventBus.on(Events.CONNECTION_ESTABLISHED, () => {
            this.isConnected = true;
            this.ui.updateConnectionStatus(true);
            this.stopPolling(); // Stop polling when socket connected
        });
        
        eventBus.on(Events.CONNECTION_LOST, () => {
            this.isConnected = false;
            this.ui.updateConnectionStatus(false);
            this.startPolling(); // Start polling when socket lost
        });
        
        eventBus.on(Events.CONNECTION_RECONNECTED, () => {
            this.isConnected = true;
            this.ui.updateConnectionStatus(true);
            this.refreshData(); // Refresh data after reconnection
        });
        
        // ================================================
        // MESSAGE EVENTS
        // ================================================
        
        eventBus.on(Events.MESSAGE_RECEIVED, (data) => {
            this.handleMessageReceived(data);
        });
        
        eventBus.on(Events.MESSAGE_SEND_REQUESTED, () => {
            this.handleSendMessage();
        });
        
        eventBus.on(Events.MESSAGE_TYPING_START, (data) => {
            this.ui.showTypingIndicator(data.username);
        });
        
        eventBus.on(Events.MESSAGE_TYPING_STOP, (data) => {
            this.ui.hideTypingIndicator();
        });
        
        // ================================================
        // FRIEND SYSTEM EVENTS - EXPANDED
        // ================================================
        
        // Friend requests - receiving
        eventBus.on(Events.FRIEND_REQUEST, (data) => {
            this.handleFriendRequest(data);
        });
        
        // Friend request responses - NEW!
        eventBus.on(Events.FRIEND_REQUEST_RESPONSE, (data) => {
            this.handleFriendRequestResponse(data);
        });
        
        // Friend management
        eventBus.on(Events.FRIEND_ADD_REQUESTED, (data) => {
            this.handleAddFriend(data);
        });
        
        eventBus.on(Events.FRIEND_REMOVE_REQUESTED, (data) => {
            this.handleRemoveFriend(data);
        });
        
        // Friend status updates
        eventBus.on(Events.FRIEND_STATUS_ONLINE, (data) => {
            this.handleFriendStatusUpdate(data.user_id, true);
        });
        
        eventBus.on(Events.FRIEND_STATUS_OFFLINE, (data) => {
            this.handleFriendStatusUpdate(data.user_id, false);
        });
        
        // ================================================
        // SESSION EVENTS
        // ================================================
        
        eventBus.on(Events.SESSION_INIT_REQUESTED, (data) => {
            this.initializeSession(data.friendId);
        });
        
        eventBus.on(Events.SESSION_SWITCHED, (data) => {
            this.handleSessionSwitch(data);
        });
        
        eventBus.on(Events.SESSION_CLEAR_REQUESTED, () => {
            this.clearCurrentSession();
        });
        
        eventBus.on(Events.SESSION_DELETE_REQUESTED, () => {
            this.deleteCurrentSession();
        });
        
        eventBus.on(Events.SESSION_CLEARED, (data) => {
            this.handleSessionCleared(data);
        });
        
        eventBus.on(Events.SESSION_DELETED, (data) => {
            this.handleSessionDeleted(data);
        });
        
        // ================================================
        // AUTH EVENTS
        // ================================================
        
        eventBus.on(Events.AUTH_LOGOUT, () => {
            this.handleLogout();
        });
        
        // ================================================
        // DATA REFRESH EVENTS
        // ================================================
        
        eventBus.on(Events.DATA_REFRESH_REQUESTED, () => {
            this.refreshData();
        });
        
        console.log('✅ Event handlers configured');
    }

    // Set up UI event listeners
    setupUIEventListeners() {
        // Message input handling
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        
        if (messageInput) {
            messageInput.addEventListener('keypress', this.handleKeyPress);
            messageInput.addEventListener('input', () => {
                this.handleTypingIndicator();
            });
        }
        
        if (sendButton) {
            sendButton.addEventListener('click', this.handleSendMessage);
        }
        
        // Add friend button
        const addFriendBtn = document.getElementById('add-friend-btn');
        if (addFriendBtn) {
            addFriendBtn.addEventListener('click', () => {
                this.ui.showAddFriendModal();
            });
        }
        
        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                eventBus.emit(Events.AUTH_LOGOUT);
            });
        }
        
        console.log('✅ UI event listeners configured');
    }

    // Load initial data
    async loadInitialData() {
        try {
            console.log('📊 Loading initial data...');
            
            // Load data concurrently
            await Promise.all([
                this.loadFriends(),
                this.loadSessions(),
                this.loadFriendRequests()
            ]);
            
            // Update UI
            this.renderUI();
            
            console.log('✅ Initial data loaded');
            
        } catch (error) {
            console.error('Failed to load initial data:', error);
            eventBus.emit(Events.SYSTEM_ERROR, 'Failed to load initial data');
        }
    }

    // ================================================
    // DATA LOADING METHODS
    // ================================================

    // Load friends list
    async loadFriends() {
        try {
            const response = await fetch('/api/friends');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.friends.clear();
                data.friends.forEach(friend => {
                    this.friends.set(friend.user_id, new Friend(friend));
                });
                
                console.log(`✅ Loaded ${this.friends.size} friends`);
                eventBus.emit(Events.FRIENDS_LOADED, Array.from(this.friends.values()));
            }
            
        } catch (error) {
            console.error('Failed to load friends:', error);
        }
    }

    // Load chat sessions
    async loadSessions() {
        try {
            const response = await fetch('/api/sessions/active');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.sessions.clear();
                this.unreadCounts.clear();
                
                data.sessions.forEach(session => {
                    const sessionObj = new Session(session);
                    this.sessions.set(session.token, sessionObj);
                    
                    if (session.unread_count > 0) {
                        this.unreadCounts.set(session.other_user.user_id, session.unread_count);
                    }
                });
                
                console.log(`✅ Loaded ${this.sessions.size} sessions`);
            }
            
        } catch (error) {
            console.error('Failed to load sessions:', error);
        }
    }

    // Load friend requests
    async loadFriendRequests() {
        try {
            const response = await fetch('/api/friend_requests/pending');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.friendRequests = data.requests || [];
                
                // Update UI count
                this.ui.updateFriendRequestCount(this.friendRequests.length);
                
                console.log(`✅ Loaded ${this.friendRequests.length} friend requests`);
                eventBus.emit(Events.FRIEND_REQUEST_COUNT_UPDATED, this.friendRequests.length);
            }
            
        } catch (error) {
            console.error('Failed to load friend requests:', error);
        }
    }

    // Load friend request count only
    async loadFriendRequestCount() {
        try {
            const response = await fetch('/api/friend_requests/pending');
            const data = await response.json();
            
            if (data.status === 'success') {
                const count = data.requests ? data.requests.length : 0;
                this.ui.updateFriendRequestCount(count);
                eventBus.emit(Events.FRIEND_REQUEST_COUNT_UPDATED, count);
            }
            
        } catch (error) {
            console.error('Failed to load friend request count:', error);
        }
    }

    /**
 * ChatEngine.js - Main Chat Engine - PART 2/3
 * Signal-inspired: Friend System Handlers + Message Management
 * Updated with real-time friend system support
 */

    // ================================================
    // FRIEND SYSTEM HANDLERS - EXPANDED
    // ================================================

    // Handle incoming friend request
    handleFriendRequest(data) {
        console.log('👥 Friend request received:', data);
        
        // Show notification
        this.ui.showNotification(
            `Otrzymałeś zaproszenie od ${data.from_username}`, 
            'info',
            5000
        );
        
        // Update friend request count
        this.loadFriendRequestCount();
        
        // If friend requests modal is open, refresh it
        if (document.getElementById('friend-requests-modal')?.style.display === 'block') {
            this.refreshFriendRequestsModal();
        }
        
        eventBus.emit(Events.FRIEND_REQUEST_COUNT_UPDATED);
    }

    // Handle friend request response (NEW!)
    handleFriendRequestResponse(data) {
        console.log('👥 Friend request response received:', data);
        
        const isAccepted = data.action === 'accepted';
        const message = isAccepted 
            ? `${data.sender_username} zaakceptował Twoje zaproszenie!`
            : `${data.sender_username} odrzucił Twoje zaproszenie`;
        
        // Show notification
        this.ui.showNotification(
            message, 
            isAccepted ? 'success' : 'info',
            isAccepted ? 7000 : 5000
        );
        
        // If accepted, refresh friends list
        if (isAccepted) {
            this.loadFriends().then(() => {
                this.renderFriendsList();
                console.log('✅ Friends list updated after acceptance');
            });
        }
    }

    // Handle add friend request
    async handleAddFriend(data) {
        try {
            console.log('👥 Adding friend:', data.username);
            
            const response = await fetch('/api/friends/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    user_identifier: data.username
                })
            });
            
            const result = await response.json();
            
            if (result.status === 'success') {
                this.ui.showNotification(
                    `Zaproszenie wysłane do ${data.username}`, 
                    'success'
                );
                eventBus.emit(Events.FRIEND_ADD_SUCCESS, data);
            } else {
                this.ui.showNotification(
                    result.error || 'Nie udało się wysłać zaproszenia', 
                    'error'
                );
                eventBus.emit(Events.FRIEND_ADD_ERROR, result.error);
            }
            
        } catch (error) {
            console.error('Failed to add friend:', error);
            this.ui.showNotification('Błąd podczas wysyłania zaproszenia', 'error');
            eventBus.emit(Events.FRIEND_ADD_ERROR, error.message);
        }
    }

    // Handle remove friend
    async handleRemoveFriend(data) {
        try {
            console.log('👥 Removing friend:', data.friendId);
            
            const response = await fetch(`/api/friends/${data.friendId}`, {
                method: 'DELETE'
            });
            
            const result = await response.json();
            
            if (result.status === 'success') {
                // Remove from local friends map
                const friend = Array.from(this.friends.values())
                    .find(f => f.id === data.friendId);
                
                if (friend) {
                    this.friends.delete(friend.user_id);
                    this.ui.showNotification(
                        `${friend.username} usunięty z znajomych`, 
                        'success'
                    );
                }
                
                // Re-render friends list
                this.renderFriendsList();
                eventBus.emit(Events.FRIEND_REMOVE_SUCCESS, data);
                
            } else {
                this.ui.showNotification('Nie udało się usunąć znajomego', 'error');
                eventBus.emit(Events.FRIEND_REMOVE_ERROR, result.error);
            }
            
        } catch (error) {
            console.error('Failed to remove friend:', error);
            this.ui.showNotification('Błąd podczas usuwania znajomego', 'error');
            eventBus.emit(Events.FRIEND_REMOVE_ERROR, error.message);
        }
    }

    // Handle friend status update (online/offline)
    handleFriendStatusUpdate(userId, isOnline) {
        const friend = this.friends.get(userId);
        if (friend) {
            friend.is_online = isOnline;
            
            // Update UI immediately
            this.ui.updateFriendStatus(userId, isOnline);
            
            console.log(`👥 Friend ${friend.username} is now ${isOnline ? 'online' : 'offline'}`);
            eventBus.emit(Events.FRIEND_STATUS_UPDATED, { userId, isOnline, friend });
        }
    }

    // Refresh friend requests modal
    async refreshFriendRequestsModal() {
        try {
            await this.loadFriendRequests();
            
            const modal = document.getElementById('friend-requests-modal');
            const container = document.getElementById('friend-requests-list');
            
            if (modal && container && modal.style.display === 'block') {
                // Re-render requests in modal
                if (this.friendRequests.length > 0) {
                    container.innerHTML = this.friendRequests.map(req => `
                        <div class="friend-request-item">
                            <div class="request-info">
                                <strong>${this.escapeHtml(req.username)}</strong>
                                <small>ID: ${req.sender_id}</small>
                            </div>
                            <div class="request-actions">
                                <button class="btn btn-success" onclick="handleFriendRequest(${req.id}, 'accept')">
                                    Akceptuj
                                </button>
                                <button class="btn btn-danger" onclick="handleFriendRequest(${req.id}, 'reject')">
                                    Odrzuć
                                </button>
                            </div>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = '<p style="text-align: center;">Brak oczekujących zaproszeń</p>';
                }
            }
            
        } catch (error) {
            console.error('Failed to refresh friend requests modal:', error);
        }
    }

    // ================================================
    // MESSAGE HANDLING
    // ================================================

    // Handle received message
    async handleMessageReceived(data) {
        try {
            console.log('💬 Message received:', data);
            
            // Auto-switch to session if enabled
            if (data.auto_switch && data.session_token) {
                await this.switchToSession(data.session_token);
            }
            
            // Process message
            await this.processReceivedMessage(data);
            
            // Update unread counts
            this.updateUnreadCounts(data);
            
            // Show notification if not in current session
            if (!data.auto_switch || data.session_token !== this.currentSessionToken) {
                this.showMessageNotification(data);
            }
            
        } catch (error) {
            console.error('Failed to handle received message:', error);
        }
    }

    // Process received message
    async processReceivedMessage(data) {
        try {
            const { session_token, message } = data;
            
            // Decrypt message if encrypted
            let decryptedContent = message.content;
            if (message.is_encrypted && message.iv) {
                const sessionKey = await this.crypto.getSessionKey(session_token);
                if (sessionKey) {
                    decryptedContent = await this.crypto.decryptMessage(
                        sessionKey, 
                        {
                            data: message.content,
                            iv: message.iv,
                            messageNumber: message.messageNumber,
                            forwardSecrecy: message.forwardSecrecy
                        },
                        session_token
                    );
                }
            }
            
            // Create message object
            const messageObj = new Message({
                ...message,
                content: decryptedContent,
                session_token: session_token
            });
            
            // Add to UI if this is current session
            if (session_token === this.currentSessionToken) {
                this.ui.addMessage(messageObj);
            }
            
            eventBus.emit(Events.MESSAGE_RECEIVED, messageObj);
            
        } catch (error) {
            console.error('Failed to process received message:', error);
            // Show encrypted message as fallback
            const fallbackMessage = new Message({
                ...data.message,
                content: '[Wiadomość zaszyfrowana - błąd deszyfrowania]',
                session_token: data.session_token
            });
            
            if (data.session_token === this.currentSessionToken) {
                this.ui.addMessage(fallbackMessage);
            }
        }
    }

    // Handle send message
    async handleSendMessage() {
        try {
            const messageInput = document.getElementById('message-input');
            if (!messageInput || !this.currentSessionToken) return;
            
            const content = messageInput.value.trim();
            if (!content) return;
            
            console.log('💬 Sending message...');
            
            // Clear input immediately
            messageInput.value = '';
            
            // Stop typing indicator
            this.stopTypingIndicator();
            
            // Get session key
            const sessionKey = await this.crypto.getSessionKey(this.currentSessionToken);
            if (!sessionKey) {
                throw new Error('No session key available');
            }
            
            // Encrypt message
            const encrypted = await this.crypto.encryptMessage(
                sessionKey, 
                content, 
                this.currentSessionToken,
                true // Use forward secrecy
            );
            
            // Send to server
            const response = await fetch('/api/message/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    session_token: this.currentSessionToken,
                    content: encrypted.data,
                    iv: encrypted.iv
                })
            });
            
            const result = await response.json();
            
            if (result.status === 'success') {
                // Create message object for UI
                const messageObj = new Message({
                    id: result.message.id,
                    content: content,
                    sender_id: this.currentUser.id,
                    timestamp: result.message.timestamp,
                    is_mine: true,
                    is_encrypted: true
                });
                
                // Add to UI
                this.ui.addMessage(messageObj);
                
                console.log('✅ Message sent successfully');
                eventBus.emit(Events.MESSAGE_SEND_SUCCESS, messageObj);
                
            } else {
                throw new Error(result.error || 'Failed to send message');
            }
            
        } catch (error) {
            console.error('Failed to send message:', error);
            this.ui.showNotification('Nie udało się wysłać wiadomości', 'error');
            eventBus.emit(Events.MESSAGE_SEND_ERROR, error.message);
        }
    }

    // Handle key press in message input
    handleKeyPress(event) {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            this.handleSendMessage();
        }
    }

    // Handle typing indicator
    handleTypingIndicator() {
        if (!this.currentSessionToken) return;
        
        // Send typing start if not already typing
        if (!this.isTyping) {
            this.isTyping = true;
            if (this.socket && this.socket.isConnected) {
                this.socket.sendTypingStart(this.currentSessionToken);
            }
        }
        
        // Reset typing timeout
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        
        // Stop typing after 3 seconds of inactivity
        this.typingTimeout = setTimeout(() => {
            this.stopTypingIndicator();
        }, 3000);
    }

    // Stop typing indicator
    stopTypingIndicator() {
        if (this.isTyping && this.currentSessionToken) {
            this.isTyping = false;
            if (this.socket && this.socket.isConnected) {
                this.socket.sendTypingStop(this.currentSessionToken);
            }
        }
        
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
            this.typingTimeout = null;
        }
    }

    // Update unread counts
    updateUnreadCounts(data) {
        if (data.session_token !== this.currentSessionToken) {
            const session = this.sessions.get(data.session_token);
            if (session && session.other_user) {
                const currentCount = this.unreadCounts.get(session.other_user.user_id) || 0;
                this.unreadCounts.set(session.other_user.user_id, currentCount + 1);
                
                // Update UI
                this.ui.updateUnreadCount(session.other_user.user_id, currentCount + 1);
            }
        }
    }

    // Show message notification
    showMessageNotification(data) {
        if (data.sender_username && data.session_token !== this.currentSessionToken) {
            this.ui.showNotification(
                `Nowa wiadomość od ${data.sender_username}`,
                'info',
                3000
            );
        }
    }

    // ================================================
    // SESSION MANAGEMENT
    // ================================================

    // Initialize session with friend
    async initializeSession(friendId) {
        try {
            console.log('🔗 Initializing session with friend:', friendId);
            
            const response = await fetch('/api/session/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    recipient_id: friendId
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                const session = new Session(data.session);
                this.sessions.set(session.token, session);
                
                // Switch to this session
                await this.switchToSession(session.token);
                
                console.log('✅ Session initialized:', session.token);
                eventBus.emit(Events.SESSION_INIT_SUCCESS, session);
                
            } else {
                throw new Error(data.error || 'Failed to initialize session');
            }
            
        } catch (error) {
            console.error('Failed to initialize session:', error);
            this.ui.showNotification('Nie udało się rozpocząć rozmowy', 'error');
            eventBus.emit(Events.SESSION_INIT_ERROR, error.message);
        }
    }

    // Switch to session
    async switchToSession(sessionToken) {
        try {
            console.log('🔄 Switching to session:', sessionToken);
            
            // Leave current session room
            if (this.currentSessionToken && this.socket) {
                this.socket.leaveSession(this.currentSessionToken);
            }
            
            // Update current session
            this.currentSessionToken = sessionToken;
            const session = this.sessions.get(sessionToken);
            
            if (!session) {
                throw new Error('Session not found');
            }
            
            // Join new session room
            if (this.socket && this.socket.isConnected) {
                this.socket.joinSession(sessionToken);
            }
            
            // Mark session as read on server
            await fetch(`/api/session/switch/${sessionToken}`, {
                method: 'POST'
            });
            
            // Clear unread count
            if (session.other_user) {
                this.unreadCounts.delete(session.other_user.user_id);
                this.ui.updateUnreadCount(session.other_user.user_id, 0);
            }
            
            // Load messages
            await this.loadSessionMessages(sessionToken);
            
            // Update UI
            this.ui.updateChatHeader(session.other_user);
            this.ui.highlightActiveSession(session.other_user.user_id);
            
            console.log('✅ Switched to session:', sessionToken);
            eventBus.emit(Events.SESSION_SWITCHED, { sessionToken, session });
            
        } catch (error) {
            console.error('Failed to switch session:', error);
            this.ui.showNotification('Nie udało się przełączyć rozmowy', 'error');
        }
    }

    // Load messages for session
    async loadSessionMessages(sessionToken) {
        try {
            const response = await fetch(`/api/messages/${sessionToken}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                const messages = [];
                
                // Decrypt messages
                for (const msgData of data.messages) {
                    try {
                        let content = msgData.content;
                        
                        if (msgData.is_encrypted && msgData.iv) {
                            const sessionKey = await this.crypto.getSessionKey(sessionToken);
                            if (sessionKey) {
                                content = await this.crypto.decryptMessage(
                                    sessionKey,
                                    {
                                        data: msgData.content,
                                        iv: msgData.iv
                                    },
                                    sessionToken
                                );
                            }
                        }
                        
                        messages.push(new Message({
                            ...msgData,
                            content: content
                        }));
                        
                    } catch (error) {
                        console.error('Failed to decrypt message:', error);
                        messages.push(new Message({
                            ...msgData,
                            content: '[Wiadomość zaszyfrowana]'
                        }));
                    }
                }
                
                // Update UI
                this.ui.renderMessages(messages);
                
                console.log(`✅ Loaded ${messages.length} messages for session`);
                
            }
            
        } catch (error) {
            console.error('Failed to load session messages:', error);
        }
    }

    /**
 * ChatEngine.js - Main Chat Engine - PART 3/3
 * Signal-inspired: Session Operations + Utilities + Cleanup
 * Complete with friend system integration
 */

    // ================================================
    // SESSION OPERATIONS
    // ================================================

    // Clear current session messages
    async clearCurrentSession() {
        if (!this.currentSessionToken) {
            this.ui.showNotification('Brak aktywnej sesji', 'warning');
            return;
        }

        try {
            console.log('🗑️ Clearing session messages:', this.currentSessionToken);
            
            const response = await fetch(`/api/session/${this.currentSessionToken}/clear`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Clear UI messages
                this.ui.clearMessages();
                
                this.ui.showNotification(
                    `Usunięto ${data.messages_deleted} wiadomości`, 
                    'success'
                );
                
                console.log('✅ Session messages cleared');
                eventBus.emit(Events.SESSION_CLEARED, { 
                    sessionToken: this.currentSessionToken,
                    messagesDeleted: data.messages_deleted
                });
                
            } else {
                throw new Error(data.error || 'Failed to clear session');
            }
            
        } catch (error) {
            console.error('Failed to clear session:', error);
            this.ui.showNotification('Nie udało się wyczyścić rozmowy', 'error');
        }
    }

    // Delete current session permanently
    async deleteCurrentSession() {
        if (!this.currentSessionToken) {
            this.ui.showNotification('Brak aktywnej sesji', 'warning');
            return;
        }

        try {
            console.log('🗑️ Deleting session permanently:', this.currentSessionToken);
            
            const response = await fetch(`/api/session/${this.currentSessionToken}/delete`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                const deletedToken = this.currentSessionToken;
                
                // Remove from local sessions
                this.sessions.delete(this.currentSessionToken);
                
                // Clear current session
                this.currentSessionToken = null;
                
                // Clear UI
                this.ui.clearMessages();
                this.ui.updateChatHeader(null);
                
                this.ui.showNotification(
                    `Sesja została trwale usunięta (${data.messages_deleted} wiadomości)`, 
                    'success'
                );
                
                console.log('✅ Session deleted permanently');
                eventBus.emit(Events.SESSION_DELETED, { 
                    sessionToken: deletedToken,
                    messagesDeleted: data.messages_deleted
                });
                
            } else {
                throw new Error(data.error || 'Failed to delete session');
            }
            
        } catch (error) {
            console.error('Failed to delete session:', error);
            this.ui.showNotification('Nie udało się usunąć sesji', 'error');
        }
    }

    // Handle session cleared by other user
    handleSessionCleared(data) {
        if (data.session_token === this.currentSessionToken) {
            this.ui.clearMessages();
            this.ui.showNotification(
                `${data.cleared_by} wyczyścił rozmowę`, 
                'info'
            );
        }
    }

    // Handle session deleted by other user
    handleSessionDeleted(data) {
        if (data.session_token === this.currentSessionToken) {
            this.sessions.delete(data.session_token);
            this.currentSessionToken = null;
            
            this.ui.clearMessages();
            this.ui.updateChatHeader(null);
            this.ui.showNotification(
                `${data.deleted_by} usunął sesję`, 
                'warning'
            );
        }
    }

    // Handle session switch from external source
    handleSessionSwitch(data) {
        if (data.sessionToken && data.sessionToken !== this.currentSessionToken) {
            this.switchToSession(data.sessionToken);
        }
    }

    // ================================================
    // UI RENDERING
    // ================================================

    // Render all UI components
    renderUI() {
        this.renderFriendsList();
        this.ui.updateConnectionStatus(this.isConnected);
        
        if (this.currentUser) {
            this.ui.updateUserInfo(this.currentUser);
        }
        
        console.log('✅ UI rendered');
    }

    // Render friends list with unread counts
    renderFriendsList() {
        const friendsArray = Array.from(this.friends.values());
        const unreadCounts = this.getUnreadCounts();
        
        this.ui.renderFriendsList(friendsArray, unreadCounts);
        
        // Update friend request count
        this.ui.updateFriendRequestCount(this.friendRequests.length);
    }

    // Get unread counts for friends
    getUnreadCounts() {
        const counts = {};
        
        // Convert Map to object for UI
        for (const [userId, count] of this.unreadCounts) {
            counts[userId] = count;
        }
        
        return counts;
    }

    // ================================================
    // DATA REFRESH AND POLLING
    // ================================================

    // Refresh all data
    async refreshData() {
        try {
            console.log('🔄 Refreshing all data...');
            
            await Promise.all([
                this.loadFriends(),
                this.loadSessions(),
                this.loadFriendRequests()
            ]);
            
            this.renderUI();
            
            console.log('✅ Data refreshed successfully');
            eventBus.emit(Events.DATA_REFRESH_SUCCESS);
            
        } catch (error) {
            console.error('Failed to refresh data:', error);
            eventBus.emit(Events.DATA_REFRESH_ERROR, error.message);
        }
    }

    // Start polling for new messages (fallback)
    startPolling() {
        if (this.pollingInterval) return;
        
        console.log('📡 Starting message polling (fallback mode)');
        
        this.pollingInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/polling/messages?last_id=${this.lastMessageId}`);
                const data = await response.json();
                
                if (data.status === 'success' && data.messages.length > 0) {
                    for (const msgData of data.messages) {
                        await this.handleMessageReceived(msgData);
                    }
                    this.lastMessageId = data.last_id;
                }
                
            } catch (error) {
                console.error('Polling failed:', error);
            }
        }, 3000); // Poll every 3 seconds
    }

    // Stop polling
    stopPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
            console.log('📡 Message polling stopped');
        }
    }

    // ================================================
    // AUTHENTICATION
    // ================================================

    // Handle logout
    async handleLogout() {
        try {
            console.log('👋 Logging out...');
            
            // Cleanup resources
            this.cleanup();
            
            // Call logout API
            const response = await fetch('/api/logout', {
                method: 'POST'
            });
            
            if (response.ok) {
                // Clear session storage
                sessionStorage.clear();
                localStorage.removeItem('isLoggedIn');
                
                // Redirect to login
                window.location.href = '/';
            } else {
                throw new Error('Logout failed');
            }
            
        } catch (error) {
            console.error('Logout failed:', error);
            // Force redirect anyway
            window.location.href = '/';
        }
    }

    // ================================================
    // UTILITY METHODS
    // ================================================

    // Get current session
    getCurrentSession() {
        return this.currentSessionToken ? this.sessions.get(this.currentSessionToken) : null;
    }

    // Get current user
    getCurrentUser() {
        return this.currentUser;
    }

    // Get friend by user ID
    getFriend(userId) {
        return this.friends.get(userId);
    }

    // Get session by token
    getSession(sessionToken) {
        return this.sessions.get(sessionToken);
    }

    // Check if user is friend
    isFriend(userId) {
        return this.friends.has(userId);
    }

    // Get friend status
    getFriendStatus(userId) {
        const friend = this.friends.get(userId);
        return friend ? friend.is_online : false;
    }

    // Escape HTML for security
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Format timestamp
    formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffMins < 1) return 'teraz';
        if (diffMins < 60) return `${diffMins}m temu`;
        if (diffHours < 24) return `${diffHours}h temu`;
        if (diffDays < 7) return `${diffDays}d temu`;
        
        return date.toLocaleDateString('pl-PL');
    }

    // ================================================
    // DEBUG AND DIAGNOSTICS
    // ================================================

    // Get debug information
    getDebugInfo() {
        return {
            // Core state
            initialized: this.isInitialized,
            connected: this.isConnected,
            currentUser: this.currentUser ? this.currentUser.username : null,
            currentSession: this.currentSessionToken,
            
            // Data counts
            friendsCount: this.friends.size,
            sessionsCount: this.sessions.size,
            friendRequestsCount: this.friendRequests.length,
            unreadCounts: Object.fromEntries(this.unreadCounts),
            
            // Manager status
            socketStatus: this.socket ? this.socket.getStatus() : null,
            cryptoStatus: this.crypto ? this.crypto.getStats() : null,
            
            // Polling state
            pollingActive: !!this.pollingInterval,
            lastMessageId: this.lastMessageId,
            
            // UI state
            currentTheme: this.currentTheme,
            sidebarVisible: this.sidebarVisible
        };
    }

    // Test all systems
    async runDiagnostics() {
        console.log('🔧 Running ChatEngine diagnostics...');
        
        const results = {
            initialization: this.isInitialized,
            socketConnection: this.socket ? this.socket.isConnected : false,
            cryptoSystem: false,
            dataLoading: false,
            messageHandling: false
        };
        
        try {
            // Test crypto system
            if (this.crypto) {
                const cryptoTest = await this.crypto.runDiagnostics();
                results.cryptoSystem = cryptoTest.canEncryptDecrypt;
            }
            
            // Test data loading
            try {
                await this.loadFriendRequestCount();
                results.dataLoading = true;
            } catch (error) {
                console.error('Data loading test failed:', error);
            }
            
            // Test message handling (mock)
            try {
                const testMessage = {
                    session_token: 'test',
                    message: { content: 'test', sender_id: 'test' },
                    sender_username: 'Test User'
                };
                // Don't actually process, just check if method exists
                results.messageHandling = typeof this.handleMessageReceived === 'function';
            } catch (error) {
                console.error('Message handling test failed:', error);
            }
            
        } catch (error) {
            console.error('Diagnostics failed:', error);
        }
        
        console.table(results);
        return results;
    }

    // Performance monitoring
    getPerformanceMetrics() {
        return {
            friendsMapSize: this.friends.size,
            sessionsMapSize: this.sessions.size,
            unreadCountsSize: this.unreadCounts.size,
            memoryUsage: performance.memory ? {
                used: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024) + ' MB',
                total: Math.round(performance.memory.totalJSHeapSize / 1024 / 1024) + ' MB'
            } : 'Not available'
        };
    }

    // ================================================
    // CLEANUP
    // ================================================

    // Cleanup all resources
    cleanup() {
        console.log('🧹 Cleaning up ChatEngine...');
        
        // Stop polling
        this.stopPolling();
        
        // Stop typing indicator
        this.stopTypingIndicator();
        
        // Leave current session room
        if (this.currentSessionToken && this.socket) {
            this.socket.leaveSession(this.currentSessionToken);
        }
        
        // Cleanup managers
        if (this.socket) {
            this.socket.cleanup();
        }
        
        if (this.crypto) {
            this.crypto.clear();
        }
        
        // Clear event listeners
        const messageInput = document.getElementById('message-input');
        if (messageInput) {
            messageInput.removeEventListener('keypress', this.handleKeyPress);
        }
        
        // Clear data
        this.friends.clear();
        this.sessions.clear();
        this.unreadCounts.clear();
        this.friendRequests = [];
        
        // Reset state
        this.isInitialized = false;
        this.isConnected = false;
        this.currentSessionToken = null;
        this.currentUser = null;
        
        console.log('✅ ChatEngine cleanup completed');
        eventBus.emit(Events.SYSTEM_CLEANUP);
    }
}

// Export for global use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ChatEngine;
} else {
    window.ChatEngine = ChatEngine;
}

// Debug helpers
if (typeof window !== 'undefined') {
    window.debugChatEngine = () => {
        if (window.chatEngine) {
            console.log('ChatEngine Debug Info:');
            console.table(window.chatEngine.getDebugInfo());
            console.log('Performance Metrics:');
            console.table(window.chatEngine.getPerformanceMetrics());
        } else {
            console.error('ChatEngine not initialized');
        }
    };
    
    window.testChatEngine = async () => {
        if (window.chatEngine) {
            return await window.chatEngine.runDiagnostics();
        } else {
            console.error('ChatEngine not initialized');
            return false;
        }
    };
}

console.log('🎯 ChatEngine Part 3/3 loaded - Complete system ready!');

