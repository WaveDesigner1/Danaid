/**
 * chat.js - DANAID CHAT SYSTEM v3.0 (FIXED ECHO PREVENTION)
 * Część 1/3: Inicjalizacja, podstawowe klasy i konfiguracja
 * 🔧 MAJOR FIX: Właściwa obsługa echo prevention z user_id
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
                console.log("🔄 Rejoining session room after reconnect...");
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

// === MAIN CHAT MANAGER CLASS START ===
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

/**
 * chat.js - DANAID CHAT SYSTEM v3.0
 * Część 2/3: Obsługa wiadomości, sesji i NAPRAWIONY echo prevention
 * 🔧 CRITICAL FIX: Właściwe porównywanie sender_id z user_id
 * 
 * UWAGA: To jest KONTYNUACJA klasy ChatManager z Part 1
 */

    // === MESSAGE HANDLING WITH FIXED ECHO PREVENTION ===
    async _handleSocketMessage(data) {
        console.log("📨 Real-time message received:", data.type);
        console.log("🔍 Raw socket data:", data);

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
        console.log("🔍 Full message data:", data);

        // 🚀 BULLETPROOF ECHO PREVENTION - Multiple security checks
        const senderId = data.message.sender_id;
        const currentUserId = this.user.id;  // This is user_id (e.g., 655415)

        // Convert both to strings for 100% reliable comparison
        const senderIdStr = String(senderId);
        const currentUserIdStr = String(currentUserId);

        console.log("🔍 DETAILED Echo Prevention Check:", {
            senderId: senderId,
            senderIdType: typeof senderId,
            currentUserId: currentUserId,
            currentUserIdType: typeof currentUserId,
            senderIdStr: senderIdStr,
            currentUserIdStr: currentUserIdStr,
            stringEqual: senderIdStr === currentUserIdStr,
            numericEqual: senderId == currentUserId,
            strictEqual: senderId === currentUserId
        });

        // 🚫 ULTIMATE ECHO PREVENTION - ALL POSSIBLE COMPARISONS
        if (senderIdStr === currentUserIdStr || 
            senderId === currentUserId ||
            senderId == currentUserId ||
            parseInt(senderId) === parseInt(currentUserId) ||
            Number(senderId) === Number(currentUserId)) {
            
            console.log("🚫 ECHO COMPLETELY BLOCKED: Own message detected");
            console.log("🛑 STOPPING ALL PROCESSING - This is sender's own message");
            console.log("❌ IGNORING MESSAGE ENTIRELY");
            return; // CRITICAL: Complete stop - no further processing
        }

        console.log("✅ Message verified as from DIFFERENT user - proceeding...");
        console.log("👤 External sender:", senderId, "| Current user:", currentUserId);

        // Additional session validation
        if (!this.currentSession) {
            console.log("⚠️ No current session - caching message for later");
        }

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
        console.log("🔔 Notification played for external message");
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

            console.log("📝 Message classification:", {
                sender_id: messageData.sender_id,
                current_user_id: this.user.id,
                is_mine: isOwnMessage,
                source: source
            });

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

    // === FIXED MESSAGE SENDING ===
    async sendMessage(content) {
        if (!this.currentSession || !content.trim()) {
            console.error("❌ Cannot send: No session or empty content");
            return false;
        }

        console.log("🚀 Sending message to session:", this.currentSession.token);

        try {
            // Check if session key exists
            const sessionKey = await cryptoManager.getSessionKey(this.currentSession.token);
            if (!sessionKey) {
                console.error("❌ No session key available");
                throw new Error("Session key not available");
            }
            console.log("✅ Session key already exists locally");

            // Encrypt message
            const encrypted = await cryptoManager.encryptMessage(content, this.currentSession.token);
            if (!encrypted) {
                console.error("❌ Encryption failed");
                return false;
            }
            console.log("🔐 Message encrypted, sending to server...");

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

            console.log("📡 Server response status:", response.status);

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
                    sender_id: this.user.id,  // Use user_id for consistency
                    content: content,  // Plain text for own display
                    iv: encrypted.iv,
                    timestamp: result.message.timestamp,
                    is_mine: true  // Always true for sent messages
                };

                // Add to UI immediately (optimistic update)
                await this.addMessageToChat(messageForUI);
                console.log("✅ Message sent successfully");

                // Clear input
                const messageInput = document.getElementById('messageInput');
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

            // Join socket room
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

            // Join new session room
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
        console.log("🔍 Checking if key already exists before generating new...");

        try {
            // Check if we already have a session key locally
            let sessionKey = await cryptoManager.getSessionKey(sessionToken);
            
            if (sessionKey) {
                console.log("🔑 Key already exists on server, using it instead of generating new");
                return true;
            }

            // Check if server has the key
            const keyResponse = await fetch(`/api/session/${sessionToken}/key`);
            
            if (keyResponse.ok) {
                const keyResult = await keyResponse.json();
                if (keyResult.status === 'success' && keyResult.encrypted_key) {
                    console.log("🔑 Key already exists on server, using it instead of generating new");
                    // Decrypt and store locally
                    const decryptedKey = await cryptoManager.decryptSessionKey(keyResult.encrypted_key);
                    if (decryptedKey) {
                        await cryptoManager.storeSessionKey(sessionToken, decryptedKey);
                        return true;
                    }
                }
            } else {
                console.log("⚠️ No existing key found, will generate new");
            }

            // Generate new session key
            console.log("🔑 Generating NEW session key...");
            sessionKey = await cryptoManager.generateSessionKey();
            await cryptoManager.storeSessionKey(sessionToken, sessionKey);

            // Find the other user to encrypt key for
            const session = this.sessions.get(sessionToken);
            console.log("🔍 Current user:", this.user.id, this.user.username);
            console.log("🔍 Other user:", session.other_user.user_id, session.other_user.username);
            console.log("🔍 Encrypting session key FOR:", session.other_user.user_id);

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

            console.log("✅ New session key generated and sent to server");
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

/**
 * chat.js - DANAID CHAT SYSTEM v3.0
 * Część 3/3: UI, utility functions i inicjalizacja
 * 🔧 FIXED: Complete echo prevention system
 * 
 * UWAGA: To jest dalsze KONTYNUACJA klasy ChatManager z Part 2
 */

    // === UI MANAGEMENT ===
    async _displayMessages(messages) {
        const chatMessages = document.getElementById('chatMessages');
        if (!chatMessages) return;

        chatMessages.innerHTML = '';

        messages.forEach(message => {
            this.addMessageToChat(message, false); // false = don't scroll for batch loading
        });

        // Scroll to bottom after loading all messages
        this._scrollToBottom();
    }

    async addMessageToChat(message, shouldScroll = true) {
        const chatMessages = document.getElementById('chatMessages');
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
        const chatMessages = document.getElementById('chatMessages');
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
        const chatHeader = document.querySelector('.chat-header h3');
        const statusIndicator = document.querySelector('.status-indicator');
        
        if (chatHeader) {
            chatHeader.textContent = session.other_user.username;
        }
        
        if (statusIndicator) {
            statusIndicator.className = `status-indicator ${session.other_user.is_online ? 'online' : 'offline'}`;
        }
    }

    _markSessionAsActive(sessionToken) {
        // Remove active class from all sessions
        document.querySelectorAll('.session-item').forEach(item => {
            item.classList.remove('active');
        });

        // Add active class to current session
        const sessionElement = document.querySelector(`[data-session="${sessionToken}"]`);
        if (sessionElement) {
            sessionElement.classList.add('active');
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
            const cachedSessions = await this.db.getAllSessions();
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

    // === UI UPDATE FUNCTIONS ===
    _updateFriendsUI() {
        const friendsList = document.getElementById('friendsList');
        if (!friendsList) return;

        friendsList.innerHTML = '';
        
        this.friends.forEach(friend => {
            const friendDiv = document.createElement('div');
            friendDiv.className = 'friend-item';
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
        const sessionsList = document.getElementById('sessionsList');
        if (!sessionsList) return;

        sessionsList.innerHTML = '';
        
        Array.from(this.sessions.values())
            .sort((a, b) => new Date(b.last_activity) - new Date(a.last_activity))
            .forEach(session => {
                const sessionDiv = document.createElement('div');
                sessionDiv.className = 'session-item';
                sessionDiv.dataset.session = session.token;
                
                const unreadBadge = session.unread_count > 0 ? 
                    `<span class="unread-badge">${session.unread_count}</span>` : '';
                
                sessionDiv.innerHTML = `
                    <div class="session-info">
                        <span class="session-user">${this.escapeHtml(session.other_user.username)}</span>
                        <span class="status-indicator ${session.other_user.is_online ? 'online' : 'offline'}"></span>
                        ${unreadBadge}
                    </div>
                    <div class="session-time">${this.formatTime(session.last_activity)}</div>
                `;
                
                sessionDiv.addEventListener('click', () => {
                    this.switchToSession(session.token);
                });
                
                sessionsList.appendChild(sessionDiv);
            });
    }

    _updateOnlineUsersUI(onlineUsers) {
        const onlineList = document.getElementById('onlineUsersList');
        if (!onlineList) return;

        onlineList.innerHTML = '';
        
        onlineUsers.forEach(user => {
            const userDiv = document.createElement('div');
            userDiv.className = 'online-user-item';
            userDiv.innerHTML = `
                <span class="user-name">${this.escapeHtml(user.username)}</span>
                <span class="status-indicator online"></span>
            `;
            
            userDiv.addEventListener('click', async () => {
                await this.startChatWithUser(user.user_id);
            });
            
            onlineList.appendChild(userDiv);
        });
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
        // Add your error display logic here
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #ff4444;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            z-index: 10000;
        `;
        document.body.appendChild(errorDiv);
        
        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.parentNode.removeChild(errorDiv);
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

    // === PERFORMANCE MONITORING ===
    measurePerformance(name, fn) {
        return async (...args) => {
            const start = performance.now();
            const result = await fn.apply(this, args);
            const duration = performance.now() - start;
            
            if (duration > 100) {
                console.log(`Slow operation detected: ${name} took ${duration.toFixed(2)}ms`);
            }
            
            return result;
        };
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

} // === KONIEC KLASY ChatManager ===

// === MAIN INITIALIZATION ===
document.addEventListener('DOMContentLoaded', async function() {
    try {
        console.log("=== DANAID CHAT INICJALIZACJA (ZOPTYMALIZOWANA) ===");

        // Check dependencies
        if (typeof io === 'undefined') {
            console.error("❌ Socket.IO not loaded");
            return;
        }
        console.log("✅ Socket.IO client library załadowana");

        if (typeof CryptoManager === 'undefined') {
            console.error("❌ CryptoManager not loaded");
            return;
        }
        console.log("✅ CryptoManager załadowany");

        if (typeof ChatManager === 'undefined') {
            console.error("❌ ChatManager not loaded");
            return;
        }
        console.log("✅ ChatManager załadowany");

        // Get user info
        const username = sessionStorage.getItem('username');
        const userId = sessionStorage.getItem('user_id');

        if (!username || !userId) {
            console.error("❌ User not logged in");
            return;
        }
        console.log("✅ Użytkownik jest zalogowany");

        // Initialize managers
        cryptoManager = new CryptoManager();
        await cryptoManager.init();

        chatManager = new ChatManager(username);
        const initialized = await chatManager.init();

        if (!initialized) {
            console.error("❌ ChatManager initialization failed");
            return;
        }

        console.log("=== DANAID CHAT ZOPTYMALIZOWANY GOTOWY ===");

        // Validate everything is working
        chatManager.validateCriticalFunctions();

        // Setup global error handling
        window.addEventListener('unhandledrejection', event => {
            console.error('Unhandled promise rejection:', event.reason);
        });

        // Make managers globally available for debugging
        window.chatManager = chatManager;
        window.cryptoManager = cryptoManager;

        console.log("✅ Socket.IO initialized");
        console.log("📡 Socket connected:", chatManager.socketManager.isSocketConnected());

    } catch (error) {
        console.error("❌ Chat initialization failed:", error);
    }
});

// === EVENT HANDLERS ===
document.addEventListener('keypress', function(e) {
    if (e.key === 'Enter' && e.target.id === 'messageInput') {
        e.preventDefault();
        const content = e.target.value.trim();
        if (content && chatManager) {
            chatManager.sendMessage(content);
        }
    }
});

// Send button handler
document.addEventListener('click', function(e) {
    if (e.target.id === 'sendButton') {
        const messageInput = document.getElementById('messageInput');
        if (messageInput && chatManager) {
            const content = messageInput.value.trim();
            if (content) {
                chatManager.sendMessage(content);
            }
        }
    }
});

// === EXPORT FOR TESTING ===
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ChatManager, SocketManager, ChatDatabase };
}

