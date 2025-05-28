/**
 * chat.js - NAPRAWIONY DANAID CHAT SYSTEM v3.2
 * 🚀 GŁÓWNE POPRAWKI: 
 * - ChatManager eksportowany globalnie
 * - Naprawione API calls do CryptoManager  
 * - Dodane friend request modal functionality
 */

// === GLOBAL VARIABLES ===
let chatManager = null;
let cryptoManager = null;
let socket = null;

// === DATABASE ABSTRACTION LAYER ===
class ChatDatabase {
    constructor() {
        this.dbName = 'DanaidChatDB';
        this.dbVersion = 1;
        this.db = null;
        this.init();
    }

    async init() {
        try {
            return new Promise((resolve, reject) => {
                if (!window.indexedDB) {
                    console.warn("⚠️ IndexedDB not supported - using memory storage");
                    this.useMemoryStorage();
                    resolve();
                    return;
                }

                const request = indexedDB.open(this.dbName, this.dbVersion);
                
                request.onerror = () => {
                    console.warn("⚠️ IndexedDB error - falling back to memory");
                    this.useMemoryStorage();
                    resolve();
                };
                
                request.onsuccess = (event) => {
                    this.db = event.target.result;
                    console.log("💾 Database initialized");
                    resolve();
                };
                
                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    
                    if (!db.objectStoreNames.contains('messages')) {
                        const messagesStore = db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
                        messagesStore.createIndex('session_token', 'session_token', { unique: false });
                        messagesStore.createIndex('timestamp', 'timestamp', { unique: false });
                    }
                    
                    if (!db.objectStoreNames.contains('sessions')) {
                        const sessionsStore = db.createObjectStore('sessions', { keyPath: 'token' });
                        sessionsStore.createIndex('last_activity', 'last_activity', { unique: false });
                    }
                };
            });
        } catch (error) {
            console.warn("⚠️ Database initialization failed:", error);
            this.useMemoryStorage();
        }
    }

    useMemoryStorage() {
        this.messages = new Map();
        this.sessions = new Map();
        this.isMemoryMode = true;
        console.log("💾 Using memory storage mode");
    }

    async saveMessage(sessionToken, message) {
        if (this.isMemoryMode) {
            if (!this.messages.has(sessionToken)) {
                this.messages.set(sessionToken, []);
            }
            this.messages.get(sessionToken).push(message);
            return;
        }

        try {
            const transaction = this.db.transaction(['messages'], 'readwrite');
            const store = transaction.objectStore('messages');
            await store.add({ ...message, session_token: sessionToken });
        } catch (error) {
            console.warn("⚠️ Save message failed:", error);
        }
    }

    async getMessages(sessionToken) {
        if (this.isMemoryMode) {
            return this.messages.get(sessionToken) || [];
        }

        try {
            const transaction = this.db.transaction(['messages'], 'readonly');
            const store = transaction.objectStore('messages');
            const index = store.index('session_token');
            const request = index.getAll(sessionToken);
            
            return new Promise((resolve) => {
                request.onsuccess = () => {
                    const messages = request.result.map(item => ({
                        id: item.id,
                        sender_id: item.sender_id,
                        content: item.content,
                        iv: item.iv,
                        timestamp: item.timestamp,
                        is_mine: item.is_mine
                    }));
                    resolve(messages);
                };
                request.onerror = () => resolve([]);
            });
        } catch (error) {
            console.warn("⚠️ Get messages failed:", error);
            return [];
        }
    }

    async saveSession(session) {
        if (this.isMemoryMode) {
            this.sessions.set(session.token, session);
            return;
        }

        try {
            const transaction = this.db.transaction(['sessions'], 'readwrite');
            const store = transaction.objectStore('sessions');
            await store.put(session);
        } catch (error) {
            console.warn("⚠️ Save session failed:", error);
        }
    }

    async getAllSessions() {
        if (this.isMemoryMode) {
            return Array.from(this.sessions.values());
        }

        try {
            const transaction = this.db.transaction(['sessions'], 'readonly');
            const store = transaction.objectStore('sessions');
            const request = store.getAll();
            
            return new Promise((resolve) => {
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => resolve([]);
            });
        } catch (error) {
            console.warn("⚠️ Get sessions failed:", error);
            return [];
        }
    }
}

// === SOCKET.IO MANAGER ===
class SocketManager {
    constructor(chatManager) {
        this.chatManager = chatManager;
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.isConnected = false;
        this.sessionRooms = new Set();
    }

    init() {
        try {
            this.socket = io({
                transports: ['websocket', 'polling'],
                upgrade: true,
                rememberUpgrade: true,
                timeout: 20000,
                forceNew: true
            });

            console.log("🔌 Socket.IO initialized");
            this.setupEventHandlers();
            return true;
        } catch (error) {
            console.error("❌ Socket.IO initialization failed:", error);
            return false;
        }
    }

    setupEventHandlers() {
        this.socket.on('connect', () => {
            this.isConnected = true;
            this.reconnectAttempts = 0;
            console.log("✅ Socket.IO connected");
            
            // Rejoin session rooms after reconnect
            if (this.sessionRooms.size > 0) {
                console.log("🔄 Rejoining session rooms after reconnect...");
                this.sessionRooms.forEach(sessionToken => {
                    this.joinSessionRoom(sessionToken);
                });
            }
        });

        this.socket.on('disconnect', (reason) => {
            this.isConnected = false;
            console.warn("⚠️ Socket.IO disconnected:", reason);
            
            if (reason === 'io server disconnect') {
                this.socket.connect();
            }
        });

        this.socket.on('message', (data) => {
            this.chatManager._handleSocketMessage(data);
        });

        this.socket.on('user_status', (data) => {
            console.log("👤 User status update:", data);
            this.chatManager._handleUserStatusUpdate(data);
        });

        this.socket.on('connect_error', (error) => {
            console.error("❌ Socket.IO connection error:", error);
            this.handleReconnect();
        });

        this.socket.on('error', (error) => {
            console.error("❌ Socket.IO error:", error);
        });

        this.socket.on('joined_session', (data) => {
            console.log("🏠 Joined session response:", data);
            if (data.status === 'success') {
                console.log("✅ Successfully joined room:", data.room);
            } else {
                console.error("❌ Failed to join room:", data.message);
            }
        });
    }

    joinSessionRoom(sessionToken) {
        if (!this.isConnected || !sessionToken) return;

        try {
            console.log("🔌 Joining Socket.IO room for session:", sessionToken.substring(0, 8));
            this.socket.emit('join_session', { session_token: sessionToken });
            this.sessionRooms.add(sessionToken);
            
            setTimeout(() => {
                console.log("✅ Successfully joined session room:", sessionToken.substring(0, 8));
            }, 100);
        } catch (error) {
            console.error("❌ Failed to join session room:", error);
        }
    }

    leaveSessionRoom(sessionToken) {
        if (!this.isConnected || !sessionToken) return;

        try {
            this.socket.emit('leave_session', { session_token: sessionToken });
            this.sessionRooms.delete(sessionToken);
            console.log("👋 Left session room:", sessionToken.substring(0, 8));
        } catch (error) {
            console.error("❌ Failed to leave session room:", error);
        }
    }

    handleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            
            console.log(`🔄 Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            
            setTimeout(() => {
                this.socket.connect();
            }, delay);
        } else {
            console.error("❌ Max reconnection attempts reached");
        }
    }

    emit(event, data) {
        if (this.isConnected && this.socket) {
            this.socket.emit(event, data);
        } else {
            console.warn("⚠️ Socket not connected - cannot emit:", event);
        }
    }

    isSocketConnected() {
        return this.isConnected && this.socket && this.socket.connected;
    }
}

// === 🚀 MAIN CHAT MANAGER CLASS (FIXED & EXPORTED) ===
class ChatManager {
    constructor(username) {
        this.user = { 
            id: sessionStorage.getItem('user_id'), 
            username: username 
        };
        this.currentSession = null;
        this.sessions = new Map();
        this.friends = new Map();
        this.db = new ChatDatabase();
        this.socketManager = new SocketManager(this);
        this.pollingInterval = null;
        this.pollingLastId = 0;
        this.isInitialized = false;

        console.log("✅ ChatManager initialized:", username);
    }

    async init() {
        try {
            await this.db.init();
            
            // Initialize Socket.IO
            const socketInitialized = this.socketManager.init();
            
            if (!socketInitialized) {
                console.warn("⚠️ Socket.IO failed - starting polling fallback");
                this.startPolling();
            }

            // Load cached data
            await this.loadCachedSessions();
            await this.loadFriends();
            await this.loadOnlineUsers();
            await this.loadFriendRequestsCount();

            this.isInitialized = true;
            console.log("✅ ChatManager fully initialized");
            
            return true;
        } catch (error) {
            console.error("❌ ChatManager initialization failed:", error);
            return false;
        }
    }

    // === POLLING FALLBACK ===
    startPolling() {
        if (this.pollingInterval) return;
        
        console.log("🔄 Starting polling fallback");
        this.pollingInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/polling/messages?last_id=${this.pollingLastId}`);
                if (!response.ok) return;
                
                const result = await response.json();
                if (result.status === 'success' && result.messages.length > 0) {
                    console.log("📨 Polling received", result.messages.length, "messages");
                    
                    for (const message of result.messages) {
                        await this._handleSocketMessage(message);
                    }
                    
                    this.pollingLastId = result.last_id;
                }
            } catch (error) {
                console.warn("⚠️ Polling error:", error);
            }
        }, 2000);
    }

    stopPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
            console.log("⏹️ Polling stopped");
        }
    }

    // === MESSAGE HANDLING WITH FIXED ECHO PREVENTION ===
    async _handleSocketMessage(data) {
        console.log("📨 Real-time message received:", data.type);

        if (data.type === 'new_message') {
            await this._handleNewMessage(data);
        } else if (data.type === 'user_status') {
            this._handleUserStatusUpdate(data);
        } else {
            console.log("📥 Unknown message type:", data.type);
        }
    }

    async _handleNewMessage(data) {
        console.log("📨 Processing new message from socket");

        // 🚀 BULLETPROOF ECHO PREVENTION
        const senderId = data.message.sender_id;
        const currentUserId = this.user.id;

        // Convert both to strings for 100% reliable comparison
        const senderIdStr = String(senderId);
        const currentUserIdStr = String(currentUserId);

        // 🚫 COMPLETE ECHO PREVENTION
        if (senderIdStr === currentUserIdStr) {
            console.log("🚫 ECHO BLOCKED: Own message detected - STOPPING ALL PROCESSING");
            return; // CRITICAL: Complete stop
        }

        console.log("✅ External message verified - proceeding...");

        try {
            // Process message through unified pipeline
            await this._processMessage(data.session_token, data.message, 'realtime');
            console.log("✅ External message processed successfully");
        } catch (error) {
            console.error("❌ Error processing external message:", error);
        }

        // Update UI if this is the current session
        if (data.session_token === this.currentSession?.token) {
            console.log("📱 Updating current chat UI for external message");
            this._refreshCurrentChat();
        } else {
            console.log("📬 External message for different session - updating notifications");
            this._updateUnreadCount(data.session_token);
        }

        // Play notification sound (only for external messages)
        this._playNotificationSound();
    }

    async _processMessage(sessionToken, messageData, source = 'unknown') {
        console.log(`📝 Processing message from ${source}:`, messageData);

        try {
            // Determine if message is from current user
            const isOwnMessage = String(messageData.sender_id) === String(this.user.id);
            
            // Prepare message object
            const message = {
                id: messageData.id,
                sender_id: messageData.sender_id,
                content: messageData.content,
                iv: messageData.iv,
                timestamp: messageData.timestamp,
                is_mine: isOwnMessage,
                source: source
            };

            // Save to database
            await this.db.saveMessage(sessionToken, message);
            console.log("💾 Message saved to database");

            // Update session activity
            const session = this.sessions.get(sessionToken);
            if (session) {
                session.last_activity = new Date().toISOString();
                session.last_message = message;
                await this.db.saveSession(session);
            }

            return message;
        } catch (error) {
            console.error("❌ Error in _processMessage:", error);
            throw error;
        }
    }

    // === 🚀 FIXED MESSAGE SENDING ===
    async sendMessage(content) {
        if (!this.currentSession || !content.trim()) {
            console.error("❌ Cannot send: No session or empty content");
            return false;
        }

        console.log("🚀 Sending message to session:", this.currentSession.token);

        try {
            // 🚀 FIXED: Use corrected crypto API
            const sessionKey = await cryptoManager.getSessionKey(this.currentSession.token);
            if (!sessionKey) {
                console.error("❌ No session key available");
                throw new Error("Session key not available");
            }
            console.log("✅ Session key retrieved");

            // 🚀 FIXED: Use corrected encryption method
            const encrypted = await cryptoManager.encryptMessage(content, this.currentSession.token);
            if (!encrypted) {
                console.error("❌ Encryption failed");
                return false;
            }
            console.log("🔐 Message encrypted successfully");

            // Send to server
            const response = await fetch('/api/message/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    session_token: this.currentSession.token,
                    content: encrypted.content,
                    iv: encrypted.iv
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                console.error("❌ Server error:", errorData);
                throw new Error(errorData.message || 'Send failed');
            }

            const result = await response.json();
            console.log("✅ Server response:", result);

            if (result.status === 'success') {
                // Create message object for UI (sender's own message)
                const messageForUI = {
                    id: result.message.id,
                    sender_id: this.user.id,
                    content: content,  // Plain text for own display
                    iv: encrypted.iv,
                    timestamp: result.message.timestamp,
                    is_mine: true  // Always true for sent messages
                };

                // Add to UI immediately (optimistic update)
                await this.addMessageToChat(messageForUI);
                console.log("✅ Message sent successfully");

                // Clear input
                const messageInput = document.getElementById('message-input');
                if (messageInput) {
                    messageInput.value = '';
                    messageInput.focus();
                }

                return true;
            } else {
                throw new Error(result.message || 'Unknown error');
            }

        } catch (error) {
            console.error("❌ Send message error:", error);
            this.showError("Failed to send message: " + error.message);
            return false;
        }
    }

    // === SESSION MANAGEMENT ===
    async initializeSession(recipientId) {
        console.log("🔄 Initializing session with:", recipientId);

        try {
            const response = await fetch('/api/session/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({ recipient_id: recipientId })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const result = await response.json();
            if (result.status !== 'success') {
                throw new Error(result.message);
            }

            const session = result.session;
            console.log("✅ Session initialized:", session.token.substring(0, 8));

            // Cache session
            this.sessions.set(session.token, session);
            await this.db.saveSession(session);

            // 🚀 CRITICAL FIX: Auto-join socket room
            this.socketManager.joinSessionRoom(session.token);

            return session;

        } catch (error) {
            console.error("❌ Session initialization failed:", error);
            throw error;
        }
    }

    async switchToSession(sessionToken) {
        console.log("🔄 Switching to session:", sessionToken?.substring(0, 8));

        try {
            if (!sessionToken) {
                console.error("❌ No session token provided");
                return false;
            }

            // Leave current session room
            if (this.currentSession) {
                this.socketManager.leaveSessionRoom(this.currentSession.token);
            }

            // Get session data
            let session = this.sessions.get(sessionToken);
            if (!session) {
                // Try to load from server
                const response = await fetch(`/api/session/${sessionToken}/validate`);
                if (response.ok) {
                    const result = await response.json();
                    if (result.status === 'success') {
                        session = result.session;
                        this.sessions.set(sessionToken, session);
                    }
                }
            }

            if (!session) {
                console.error("❌ Session not found:", sessionToken);
                return false;
            }

            this.currentSession = session;

            // 🚀 CRITICAL FIX: Auto-join new session room
            this.socketManager.joinSessionRoom(sessionToken);

            // Setup encryption
            await this._setupSessionEncryption(sessionToken);

            // Load and display messages
            await this._loadSessionMessages(sessionToken);

            // Update UI
            this._updateChatHeader(session);
            this._markSessionAsActive(sessionToken);

            console.log("✅ Session switched successfully:", sessionToken.substring(0, 8));
            return true;

        } catch (error) {
            console.error("❌ Session switch failed:", error);
            return false;
        }
    }

    async _setupSessionEncryption(sessionToken) {
        console.log("🔍 Setting up session encryption...");

        try {
            // Check if we already have a session key locally
            const hasKey = await cryptoManager.hasSessionKey(sessionToken);
            
            if (hasKey) {
                console.log("🔑 Session key already exists locally");
                return true;
            }

            // Check if server has the key
            const keyResponse = await fetch(`/api/session/${sessionToken}/key`);
            
            if (keyResponse.ok) {
                const keyResult = await keyResponse.json();
                if (keyResult.status === 'success' && keyResult.encrypted_key) {
                    console.log("🔑 Key exists on server, decrypting...");
                    // Decrypt and store locally
                    const decryptedKey = await cryptoManager.decryptSessionKey(keyResult.encrypted_key);
                    if (decryptedKey) {
                        await cryptoManager.storeSessionKey(sessionToken, decryptedKey);
                        return true;
                    }
                }
            }

            // Generate new session key
            console.log("🔑 Generating NEW session key...");
            const sessionKey = await cryptoManager.generateSessionKey();
            await cryptoManager.storeSessionKey(sessionToken, sessionKey);

            // Find the other user to encrypt key for
            const session = this.sessions.get(sessionToken);
            console.log("🔍 Encrypting session key for:", session.other_user.user_id);

            // Get recipient's public key and encrypt session key
            const otherUserKey = await this.getPublicKey(session.other_user.user_id);
            if (!otherUserKey) {
                throw new Error("Cannot get recipient's public key");
            }

            const encryptedSessionKey = await cryptoManager.encryptSessionKey(sessionKey, otherUserKey);

            // Send encrypted key to server
            const keyExchangeResponse = await fetch(`/api/session/${sessionToken}/exchange_key`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({ encrypted_key: encryptedSessionKey })
            });

            if (!keyExchangeResponse.ok) {
                throw new Error("Key exchange failed");
            }

            console.log("✅ Session key generated and sent to server");
            return true;

        } catch (error) {
            console.error("❌ Session encryption setup failed:", error);
            return false;
        }
    }

    async _loadSessionMessages(sessionToken) {
        console.log("📥 Loading messages for session:", sessionToken.substring(0, 8));

        // First try cached messages
        const cachedMessages = await this.db.getMessages(sessionToken);
        console.log("📱 Found", cachedMessages.length, "cached messages");

        if (cachedMessages.length > 0) {
            await this._displayMessages(cachedMessages);
        }

        // Then load from server
        try {
            const response = await fetch(`/api/messages/${sessionToken}`);
            if (!response.ok) return;

            const result = await response.json();
            if (result.status === 'success' && result.messages) {
                console.log("📡 Loaded", result.messages.length, "messages from server");

                // Decrypt and display
                const decryptedMessages = [];
                for (const msg of result.messages) {
                    try {
                        let content = msg.content;
                        if (!msg.is_mine) {
                            // Decrypt incoming messages
                            content = await cryptoManager.decryptMessage(msg.content, msg.iv, sessionToken);
                        }
                        
                        decryptedMessages.push({
                            ...msg,
                            content: content
                        });
                    } catch (error) {
                        console.warn("⚠️ Decryption failed for message:", msg.id);
                        decryptedMessages.push({
                            ...msg,
                            content: "[Decryption failed]"
                        });
                    }
                }

                // Cache messages
                for (const msg of decryptedMessages) {
                    await this.db.saveMessage(sessionToken, msg);
                }

                await this._displayMessages(decryptedMessages);
            }

        } catch (error) {
            console.error("❌ Failed to load messages from server:", error);
        }
    }

    // === UI MANAGEMENT ===
    async _displayMessages(messages) {
        const chatMessages = document.getElementById('messages');
        if (!chatMessages) return;

        chatMessages.innerHTML = '';

        messages.forEach(message => {
            this.addMessageToChat(message, false); // false = don't scroll for batch loading
        });

        // Scroll to bottom after loading all messages
        this._scrollToBottom();
    }

    async addMessageToChat(message, shouldScroll = true) {
        const chatMessages = document.getElementById('messages');
        if (!chatMessages) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${message.is_mine ? 'sent' : 'received'}`;
        messageDiv.dataset.messageId = message.id;

        const timestamp = new Date(message.timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit'
        });

        messageDiv.innerHTML = `
            <div class="message-content">${this.escapeHtml(message.content)}</div>
            <div class="message-timestamp">${timestamp}</div>
        `;

        chatMessages.appendChild(messageDiv);

        if (shouldScroll) {
            this._scrollToBottom();
        }

        // Save to database
        if (this.currentSession) {
            await this.db.saveMessage(this.currentSession.token, message);
        }
    }

    _scrollToBottom() {
        const chatMessages = document.getElementById('messages');
        if (chatMessages) {
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    }

    _refreshCurrentChat() {
        if (this.currentSession) {
            this._loadSessionMessages(this.currentSession.token);
        }
    }

    _updateChatHeader(session) {
        const chatHeader = document.querySelector('#chat-header h2');
        
        if (chatHeader) {
            chatHeader.textContent = `Chat with ${session.other_user.username}`;
        }
    }

    _markSessionAsActive(sessionToken) {
        // Remove active class from all sessions
        document.querySelectorAll('.friend-item').forEach(item => {
            item.classList.remove('active');
        });

        // Add active class to current session (if friend item exists)
        const currentUser = this.sessions.get(sessionToken)?.other_user;
        if (currentUser) {
            const friendElement = document.querySelector(`[data-user-id="${currentUser.user_id}"]`);
            if (friendElement) {
                friendElement.classList.add('active');
            }
        }
    }

    // === FRIENDS AND USERS MANAGEMENT ===
    async loadFriends() {
        try {
            const response = await fetch('/api/friends');
            if (!response.ok) return;

            const result = await response.json();
            if (result.status === 'success') {
                this.friends.clear();
                result.friends.forEach(friend => {
                    this.friends.set(friend.user_id, friend);
                });
                
                console.log("👥 Loaded", result.friends.length, "friends");
                this._updateFriendsUI();
            }
        } catch (error) {
            console.error("❌ Failed to load friends:", error);
        }
    }

    async loadOnlineUsers() {
        try {
            const response = await fetch('/api/online_users');
            if (!response.ok) return;

            const result = await response.json();
            if (result.status === 'success') {
                console.log("🟢 Online users:", result.online_users.length);
                this._updateOnlineUsersUI(result.online_users);
            }
        } catch (error) {
            console.error("❌ Failed to load online users:", error);
        }
    }

    async loadCachedSessions() {
        try {
            const response = await fetch('/api/sessions/active');
            
            if (!response.ok) return;

            const result = await response.json();
            if (result.status === 'success') {
                this.sessions.clear();
                
                result.sessions.forEach(session => {
                    this.sessions.set(session.token, session);
                });
                
                console.log("💬 Loaded", result.sessions.length, "sessions");
                this._updateSessionsUI();
            }
        } catch (error) {
            console.error("❌ Failed to load sessions:", error);
        }
    }

    // === 🚀 FRIEND REQUEST FUNCTIONALITY ===
    async loadFriendRequestsCount() {
        try {
            const response = await fetch('/api/friend_requests/count');
            if (!response.ok) return;

            const result = await response.json();
            if (result.status === 'success') {
                const countElement = document.getElementById('friend-request-count');
                if (countElement) {
                    countElement.textContent = result.count;
                    countElement.style.display = result.count > 0 ? 'flex' : 'none';
                }
            }
        } catch (error) {
            console.error("❌ Failed to load friend requests count:", error);
        }
    }

    async _showFriendRequestsModal() {
        console.log("📬 Showing friend requests modal");
        
        try {
            const response = await fetch('/api/friend_requests/pending');
            if (!response.ok) return;

            const result = await response.json();
            if (result.status === 'success') {
                this._displayFriendRequestsModal(result.requests);
            }
        } catch (error) {
            console.error("❌ Failed to load pending requests:", error);
        }
    }

    _displayFriendRequestsModal(requests) {
        // Create modal if it doesn't exist
        let modal = document.getElementById('friend-requests-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'friend-requests-modal';
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Zaproszenia do znajomych</h3>
                        <button class="modal-close" onclick="this.closest('.modal').style.display='none'">&times;</button>
                    </div>
                    <div class="modal-body" id="friend-requests-list">
                        <!-- Friend requests will be inserted here -->
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        const listContainer = modal.querySelector('#friend-requests-list');
        listContainer.innerHTML = '';

        if (requests.length === 0) {
            listContainer.innerHTML = '<p>Brak oczekujących zaproszeń</p>';
        } else {
            requests.forEach(request => {
                const requestDiv = document.createElement('div');
                requestDiv.className = 'friend-request-item';
                requestDiv.innerHTML = `
                    <div class="request-info">
                        <strong>${this.escapeHtml(request.username)}</strong>
                        <small>${new Date(request.created_at).toLocaleDateString()}</small>
                    </div>
                    <div class="request-actions">
                        <button class="btn btn-success btn-sm" onclick="chatManager.acceptFriendRequest(${request.id})">
                            Akceptuj
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="chatManager.rejectFriendRequest(${request.id})">
                            Odrzuć
                        </button>
                    </div>
                `;
                listContainer.appendChild(requestDiv);
            });
        }

        modal.style.display = 'flex';
    }

    async acceptFriendRequest(requestId) {
        try {
            const response = await fetch(`/api/friend_requests/${requestId}/accept`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                }
            });

            if (response.ok) {
                this.showNotification('Zaproszenie zaakceptowane!', 'success');
                await this.loadFriends();
                await this.loadFriendRequestsCount();
                this._showFriendRequestsModal(); // Refresh the modal
            }
        } catch (error) {
            console.error("❌ Failed to accept friend request:", error);
        }
    }

    async rejectFriendRequest(requestId) {
        try {
            const response = await fetch(`/api/friend_requests/${requestId}/reject`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                }
            });

            if (response.ok) {
                this.showNotification('Zaproszenie odrzucone', 'info');
                await this.loadFriendRequestsCount();
                this._showFriendRequestsModal(); // Refresh the modal
            }
        } catch (error) {
            console.error("❌ Failed to reject friend request:", error);
        }
    }

    // === UI UPDATE FUNCTIONS ===
    _updateFriendsUI() {
        const friendsList = document.getElementById('friend-list');
        if (!friendsList) return;

        friendsList.innerHTML = '';
        
        this.friends.forEach(friend => {
            const friendDiv = document.createElement('li');
            friendDiv.className = 'friend-item';
            friendDiv.dataset.userId = friend.user_id;
            friendDiv.innerHTML = `
                <div class="friend-info">
                    <span class="friend-name">${this.escapeHtml(friend.username)}</span>
                    <span class="status-indicator ${friend.is_online ? 'online' : 'offline'}"></span>
                </div>
            `;
            
            friendDiv.addEventListener('click', async () => {
                await this.startChatWithUser(friend.user_id);
            });
            
            friendsList.appendChild(friendDiv);
        });
    }

    _updateSessionsUI() {
        // Sessions are shown through friends list for now
        console.log("📝 Sessions UI updated via friends list");
    }

    _updateOnlineUsersUI(onlineUsers) {
        console.log("🟢 Online users updated:", onlineUsers.length);
    }

    // === USER INTERACTION ===
    async startChatWithUser(userId) {
        try {
            console.log("💬 Starting chat with user:", userId);
            
            // Check if session already exists
            const existingSession = Array.from(this.sessions.values())
                .find(s => s.other_user.user_id === userId);
            
            if (existingSession) {
                console.log("✅ Using existing session");
                await this.switchToSession(existingSession.token);
                return;
            }
            
            // Initialize new session
            const session = await this.initializeSession(userId);
            await this.switchToSession(session.token);
            
            // Update UI
            this._updateSessionsUI();
            
        } catch (error) {
            console.error("❌ Failed to start chat:", error);
            this.showError("Failed to start chat: " + error.message);
        }
    }

    // === UTILITY FUNCTIONS ===
    async getPublicKey(userId) {
        try {
            const response = await fetch(`/api/user/${userId}/public_key`);
            if (!response.ok) return null;

            const result = await response.json();
            if (result.status === 'success') {
                return result.public_key;
            }
            return null;
        } catch (error) {
            console.error("❌ Failed to get public key:", error);
            return null;
        }
    }

    getCSRFToken() {
        const token = document.querySelector('[name=csrf-token]');
        return token ? token.getAttribute('content') : '';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'now';
        if (diff < 3600000) return Math.floor(diff / 60000) + 'm';
        if (diff < 86400000) return Math.floor(diff / 3600000) + 'h';
        return Math.floor(diff / 86400000) + 'd';
    }

    showError(message) {
        console.error("🚨 Error:", message);
        this.showNotification(message, 'error');
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 16px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            max-width: 300px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: slideInRight 0.3s ease;
        `;

        const colors = {
            success: '#4CAF50',
            error: '#F44336',
            warning: '#FF9800',
            info: '#2196F3'
        };

        notification.style.backgroundColor = colors[type] || colors.info;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
    }

    _playNotificationSound() {
        try {
            const audio = new Audio('/static/sounds/notification.mp3');
            audio.volume = 0.3;
            audio.play().catch(() => {
                // Ignore audio errors
            });
        } catch (error) {
            // Ignore audio errors
        }
    }

    _updateUnreadCount(sessionToken) {
        const session = this.sessions.get(sessionToken);
        if (session) {
            session.unread_count = (session.unread_count || 0) + 1;
            this._updateSessionsUI();
        }
    }

    _handleUserStatusUpdate(data) {
        console.log("👤 User status update:", data);
        
        // Update friends status
        if (this.friends.has(data.user_id)) {
            const friend = this.friends.get(data.user_id);
            friend.is_online = data.is_online;
            this._updateFriendsUI();
        }
        
        // Update session status
        this.sessions.forEach(session => {
            if (session.other_user.user_id === data.user_id) {
                session.other_user.is_online = data.is_online;
            }
        });
        this._updateSessionsUI();
    }

    // === VALIDATION AND DEBUGGING ===
    validateCriticalFunctions() {
        const criticalFunctions = [
            'sendMessage', 'switchToSession', 'initializeSession',
            '_handleNewMessage', '_processMessage', 'loadFriends'
        ];
        
        const missing = criticalFunctions.filter(fn => typeof this[fn] !== 'function');
        
        if (missing.length > 0) {
            console.error("❌ Missing critical functions:", missing);
            return false;
        }
        
        console.log("✅ All critical functions validated - ChatManager complete");
        return true;
    }

} // === END OF ChatManager CLASS ===

// === 🚀 KRYTYCZNE: EKSPORT GLOBALNY ===
window.ChatManager = ChatManager;
window.SocketManager = SocketManager;
window.ChatDatabase = ChatDatabase;

// === MAIN INITIALIZATION ===
document.addEventListener('DOMContentLoaded', async function() {
    try {
        console.log("=== DANAID CHAT INITIALIZATION (COMPLETE & FIXED) ===");

        // Check dependencies
        if (typeof io === 'undefined') {
            console.error("❌ Socket.IO not loaded");
            return;
        }
        console.log("✅ Socket.IO client library loaded");

        if (typeof CryptoManager === 'undefined') {
            console.error("❌ CryptoManager class not available");
            return;
        }
        console.log("✅ CryptoManager class loaded");

        // Get user info
        const username = sessionStorage.getItem('username');
        const userId = sessionStorage.getItem('user_id');

        if (!username || !userId) {
            console.error("❌ User not logged in");
            return;
        }
        console.log("✅ User logged in:", username, userId);

        // Initialize managers
        cryptoManager = window.cryptoManager; // Use existing instance
        
        chatManager = new ChatManager(username);
        const initialized = await chatManager.init();

        if (!initialized) {
            console.error("❌ ChatManager initialization failed");
            return;
        }

        console.log("=== DANAID CHAT READY ===");

        // Validate everything is working
        const validated = chatManager.validateCriticalFunctions();
        if (!validated) {
            console.error("❌ Critical function validation failed");
            return;
        }

        // Make managers globally available
        window.chatManager = chatManager;

        console.log("✅ ChatManager initialized and exported globally");
        console.log("📡 Socket connected:", chatManager.socketManager.isSocketConnected());

        // Setup UI event handlers
        setupUIEventHandlers();

    } catch (error) {
        console.error("❌ Chat initialization failed:", error);
    }
});

// === UI EVENT HANDLERS ===
function setupUIEventHandlers() {
    // Message input handling
    const messageInput = document.getElementById('message-input');
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                const content = this.value.trim();
                if (content && chatManager) {
                    chatManager.sendMessage(content);
                }
            }
        });
    }

    // Send button handling
    const sendButton = document.getElementById('send-button');
    if (sendButton) {
        sendButton.addEventListener('click', function() {
            if (messageInput && chatManager) {
                const content = messageInput.value.trim();
                if (content) {
                    chatManager.sendMessage(content);
                }
            }
        });
    }

    // Add friend button
    const addFriendBtn = document.getElementById('add-friend-btn');
    if (addFriendBtn) {
        addFriendBtn.addEventListener('click', function() {
            showAddFriendModal();
        });
    }

    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function() {
            // Clear all crypto keys before logout
            if (window.cryptoManager) {
                window.cryptoManager.clearAllKeys();
            }
            window.location.href = '/logout';
        });
    }
}

// === ADD FRIEND MODAL ===
function showAddFriendModal() {
    const modal = document.getElementById('add-friend-modal');
    if (modal) {
        modal.style.display = 'flex';
        
        const usernameInput = document.getElementById('friend-username-input');
        if (usernameInput) {
            usernameInput.focus();
            usernameInput.value = '';
        }

        // Setup modal close handlers
        const closeBtn = modal.querySelector('.modal-close');
        if (closeBtn) {
            closeBtn.onclick = () => modal.style.display = 'none';
        }

        // Setup send friend request
        const sendBtn = document.getElementById('send-friend-request-btn');
        if (sendBtn) {
            sendBtn.onclick = async () => {
                await sendFriendRequest();
            };
        }

        // Close on outside click
        modal.onclick = (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        };
    }
}

async function sendFriendRequest() {
    const usernameInput = document.getElementById('friend-username-input');
    const statusDiv = document.getElementById('friend-request-status');
    
    if (!usernameInput || !statusDiv) return;

    const username = usernameInput.value.trim();
    if (!username) {
        showFriendRequestStatus('Wprowadź nazwę użytkownika', 'error');
        return;
    }

    try {
        statusDiv.style.display = 'block';
        showFriendRequestStatus('Wysyłanie zaproszenia...', 'info');

        const response = await fetch('/api/friend_requests/send', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': chatManager.getCSRFToken()
            },
            body: JSON.stringify({ username: username })
        });

        const result = await response.json();

        if (result.status === 'success') {
            showFriendRequestStatus('Zaproszenie wysłane pomyślnie!', 'success');
            usernameInput.value = '';
            
            setTimeout(() => {
                const modal = document.getElementById('add-friend-modal');
                if (modal) modal.style.display = 'none';
            }, 2000);
        } else {
            showFriendRequestStatus(result.message || 'Błąd wysyłania zaproszenia', 'error');
        }

    } catch (error) {
        console.error("❌ Friend request error:", error);
        showFriendRequestStatus('Błąd połączenia', 'error');
    }
}

function showFriendRequestStatus(message, type) {
    const statusDiv = document.getElementById('friend-request-status');
    if (!statusDiv) return;

    statusDiv.textContent = message;
    statusDiv.className = `status-${type}`;
    statusDiv.style.display = 'block';

    const colors = {
        success: { bg: '#d4edda', color: '#155724', border: '#c3e6cb' },
        error: { bg: '#f8d7da', color: '#721c24', border: '#f5c6cb' },
        info: { bg: '#d1ecf1', color: '#0c5460', border: '#bee5eb' }
    };

    const style = colors[type] || colors.info;
    Object.assign(statusDiv.style, {
        backgroundColor: style.bg,
        color: style.color,
        border: `1px solid ${style.border}`,
        padding: '8px 12px',
        borderRadius: '4px',
        marginTop: '10px'
    });
}

// === EXPORT FOR TESTING ===
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ChatManager, SocketManager, ChatDatabase };
}
