// Full chat.js with dual encryption modifications
class ChatManager {
    constructor() {
        this.socket = null;
        this.currentSession = null;
        this.user = null;
        this.friends = [];
        this.sessions = [];
        this.messages = new Map();
        this.elements = {};
        this.pollingInterval = null;
        
        // Processing queues and caches
        this.processingMessages = new Set(); // FIXED: Use Set instead of array
        this.apiCache = new Map();
        this.messageHistory = new Map();
        this.unreadCounts = new Map();
        
        // UI state
        this.currentChatPartner = null;
        this.isTyping = false;
        this.lastActivity = Date.now();
        
        // Performance optimization
        this.messageLoadBatch = 50;
        this.maxCachedMessages = 1000;
    }

    async init() {
        try {
            console.log("🚀 Initializing ChatManager");
            
            this.user = await this._getCurrentUser();
            console.log("✅ User loaded:", this.user.username);
            
            this._initElements();
            this._setupEventListeners();
            
            await this._loadFriends();
            await this._loadSessions();
            await this._initSocket();
            
            this._startPeriodicTasks();
            
            console.log("✅ ChatManager initialized successfully");
        } catch (error) {
            console.error("❌ Failed to initialize ChatManager:", error);
            this._showNotification('Failed to initialize chat system', 'error');
        }
    }

    // =================
    // SESSION MANAGEMENT WITH DUAL ENCRYPTION
    // =================
    
    async _initSession(recipientId) {
        console.log("🚀 Initializing session with:", recipientId);
        
        try {
            // Request session from server
            const response = await fetch('/api/session/init', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient_id: recipientId })
            });
            
            if (!response.ok) {
                throw new Error(`Session init failed: ${response.status}`);
            }
            
            const data = await response.json();
            this.currentSession = data.session;
            
            console.log("✅ Session initialized:", data.session.token.slice(0, 8) + "...");
            
            // DUAL ENCRYPTION: Ensure session key exists
            await this._ensureSessionKey();
            
            // Load message history
            await this._loadMessages(data.session.token);
            
            // Update UI
            this._updateChatUI();
            
        } catch (error) {
            console.error("❌ Session initialization failed:", error);
            this._showNotification('Failed to start chat session', 'error');
            throw error;
        }
    }

    // MODIFIED: Enhanced session key management with dual encryption
    async _ensureSessionKey() {
        if (!this.currentSession) {
            throw new Error('No current session');
        }

        const sessionToken = this.currentSession.token;
        console.log("🔑 Ensuring session key exists for:", sessionToken.slice(0, 8) + "...");

        // Check if we already have session key locally
        if (await this._getSessionKeyOptimized(sessionToken)) {
            console.log("✅ Session key already exists locally");
            return;
        }

        // Check server for existing keys
        try {
            const response = await fetch(`/api/session/${sessionToken}/key`);
            if (response.ok) {
                const data = await response.json();
                if (data.encrypted_key) {
                    console.log("🔍 Found existing session key on server, decrypting...");
                    
                    // Decrypt existing key with our private key
                    const decryptedKey = await window.cryptoManager.decryptSessionKey(data.encrypted_key);
                    window.cryptoManager.storeSessionKey(sessionToken, decryptedKey);
                    console.log("✅ Existing session key decrypted and stored");
                    return;
                }
            }
        } catch (error) {
            console.log("⚠️ No existing key or decryption failed, will generate new");
        }

        // DUAL ENCRYPTION: Generate new session key for both users
        console.log("🔧 Generating new session key with dual encryption...");
        await this._generateDualEncryptedSessionKey(sessionToken);
    }

    // NEW: Dual encryption key generation
    async _generateDualEncryptedSessionKey(sessionToken) {
        try {
            // 1. Generate AES session key
            const sessionKey = await window.cryptoManager.generateSessionKey();
            const sessionKeyBase64 = await window.cryptoManager.exportSessionKey(sessionKey);
            
            // 2. Store locally for immediate use
            window.cryptoManager.storeSessionKey(sessionToken, sessionKeyBase64);
            console.log("💾 Session key stored locally");
            
            // 3. Get public keys for both participants
            const currentUserId = this.user.id;
            const otherUserId = this.currentSession.other_user.id;
            
            const recipients = {};
            recipients[currentUserId] = await this._getUserPublicKey(this.user.user_id);
            recipients[otherUserId] = await this._getUserPublicKey(this.currentSession.other_user.user_id);
            
            console.log(`🔑 Got public keys for users: ${currentUserId}, ${otherUserId}`);
            
            // 4. Encrypt session key for both users
            const encryptedKeys = await window.cryptoManager.encryptSessionKeyForMultipleUsers(
                recipients,
                sessionKey
            );
            
            console.log("🔐 Session key encrypted for users:", Object.keys(encryptedKeys));
            
            // 5. Send to server
            const response = await fetch(`/api/session/${sessionToken}/exchange_key`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    keys: encryptedKeys
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`Server error: ${errorData.message || response.status}`);
            }
            
            const result = await response.json();
            console.log("✅ Dual-encrypted session key sent to server");
            console.log(`   Generator: ${result.key_generator}`);
            
            // Clear API cache for this session key
            this.apiCache.delete(`session_key_${sessionToken}`);
            
        } catch (error) {
            // Cleanup on error
            window.cryptoManager.removeSessionKey(sessionToken);
            console.error("❌ Dual encrypted key generation failed:", error);
            throw new Error(`Session key setup failed: ${error.message}`);
        }
    }

    // =================
    // MESSAGE HANDLING
    // =================
    
    async sendMessage() {
        const content = this.elements.messageInput?.value.trim();
        if (!content || !this.currentSession) return;

        console.log('🚀 Sending message to session:', this.currentSession.token.slice(0, 8) + '...');

        // Disable input temporarily
        this.elements.messageInput.disabled = true;
        this.elements.sendButton.disabled = true;

        try {
            // Ensure session key exists (with dual encryption)
            await this._ensureSessionKey();

            // Get session key for encryption
            const sessionKey = await this._getSessionKeyOptimized(this.currentSession.token);
            if (!sessionKey) {
                throw new Error('No session key available after ensuring');
            }

            // Encrypt message
            const encrypted = await window.cryptoManager.encryptMessage(sessionKey, content);
            console.log('🔐 Message encrypted');

            // Send to server
            const response = await fetch('/api/message/send', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    session_token: this.currentSession.token,
                    content: encrypted.data,
                    iv: encrypted.iv
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${response.status} - ${errorText}`);
            }

            const data = await response.json();

            if (data.status === 'success') {
                // Clear input
                this.elements.messageInput.value = '';

                // Add to UI optimistically
                const newMessage = {
                    id: data.message.id,
                    sender_id: parseInt(this.user.id),
                    content: content, // Store decrypted for local display
                    timestamp: data.message.timestamp,
                    is_mine: true
                };

                this._addMessageToUI(newMessage);
                await this._storeMessage(this.currentSession.token, newMessage);

                console.log('✅ Message sent successfully');
            } else {
                this._showNotification(data.message || 'Send failed', 'error');
            }

        } catch (error) {
            console.error("❌ Send message error:", error);
            this._showNotification('Failed to send message: ' + error.message, 'error');
        } finally {
            // Re-enable input
            this.elements.messageInput.disabled = false;
            this.elements.sendButton.disabled = false;
            this.elements.messageInput.focus();
        }
    }

    // MODIFIED: Improved message processing with proper cleanup
    async _processMessage(sessionToken, message, source = 'unknown') {
        const messageKey = `${sessionToken}-${message.id || message.timestamp}`;
        
        // FIXED: Use Set for better performance and cleanup
        if (this.processingMessages.has(messageKey)) {
            console.log("Message already processing, skipping");
            return;
        }
        
        this.processingMessages.add(messageKey);
        
        try {
            let processedMessage = { ...message };
            
            // IMPROVED: Better encryption detection
            const needsDecryption = this._shouldDecryptMessage(message);
            
            if (needsDecryption) {
                const sessionKey = await this._getSessionKeyOptimized(sessionToken);
                
                if (sessionKey) {
                    try {
                        const decryptedContent = await window.cryptoManager.decryptMessage(sessionKey, {
                            data: message.content,
                            iv: message.iv
                        });
                        processedMessage.content = decryptedContent;
                        console.log("✅ Message decrypted successfully");
                    } catch (decryptError) {
                        console.error("❌ Decryption failed:", decryptError.message);
                        processedMessage.content = `[Decryption failed: ${decryptError.message}]`;
                    }
                } else {
                    console.log("⚠️ No session key available for decryption");
                    processedMessage.content = '[No session key - please refresh]';
                }
            }
            
            // Store processed message
            await this._storeMessage(sessionToken, processedMessage);
            
            // Update UI if it's for current session
            if (sessionToken === this.currentSession?.token) {
                this._addMessageToUI(processedMessage);
            }
            
        } catch (error) {
            console.error("❌ Message processing error:", error);
            // Store error message so user sees something
            await this._storeMessage(sessionToken, {
                ...message,
                content: `[Processing error: ${error.message}]`
            });
        } finally {
            // FIXED: Always cleanup, even on error
            this.processingMessages.delete(messageKey);
        }
    }

    // IMPROVED: Better encryption detection
    _shouldDecryptMessage(message) {
        // If no IV, definitely not encrypted
        if (!message.iv) return false;
        
        // Use explicit flag if available
        if (message.hasOwnProperty('is_encrypted')) {
            return message.is_encrypted;
        }
        
        // If content is very short and looks like plain text, probably not encrypted
        if (message.content.length < 20 && /^[a-zA-Z0-9\s\.\,\!\?]+$/.test(message.content)) {
            return false;
        }
        
        // If we have IV and content looks like base64, probably encrypted
        const base64Pattern = /^[A-Za-z0-9+/]+=*$/;
        return base64Pattern.test(message.content.replace(/\s/g, ''));
    }

    // =================
    // SOCKET.IO HANDLING - IMPROVED
    // =================
    
    async _initSocket() {
        try {
            const config = await this._getSocketConfig();
            
            this.socket = io(config.socketUrl || window.location.origin, {
                path: config.path || '/socket.io/',
                transports: ['websocket', 'polling'],
                upgrade: true,
                reconnection: true,
                reconnectionAttempts: 5,
                reconnectionDelay: 1000,
                secure: window.location.protocol === 'https:'
            });

            this._setupSocketEvents();

        } catch (error) {
            console.error("❌ Socket initialization failed:", error);
            this._enablePollingFallback();
        }
    }

    // IMPROVED: Better Socket.IO event handling
    _setupSocketEvents() {
        this.socket.on('connect', () => {
            console.log("✅ Socket.IO connected");
            this.socket.emit('register_user', { user_id: this.user.id });
            
            // Clear polling fallback when socket connects
            if (this.pollingInterval) {
                clearInterval(this.pollingInterval);
                this.pollingInterval = null;
            }
        });

        this.socket.on('message', async (data) => {
            try {
                console.log("📨 Real-time message received:", data.type);
                await this._handleSocketMessage(data);
            } catch (error) {
                console.error("❌ Socket message handling error:", error);
                // Don't let one bad message break the socket
            }
        });

        this.socket.on('connect_error', (error) => {
            console.error("❌ Socket.IO connection error:", error);
            this._enablePollingFallback();
        });

        this.socket.on('disconnect', (reason) => {
            console.log(`🔌 Socket.IO disconnected: ${reason}`);
            
            // Always enable polling fallback on disconnect
            this._enablePollingFallback();
            
            // Auto-reconnect for server-initiated disconnects
            if (reason === 'io server disconnect') {
                setTimeout(() => {
                    if (!this.socket.connected) {
                        this.socket.connect();
                    }
                }, 1000);
            }
        });
    }

    // IMPROVED: Better message handling
    async _handleSocketMessage(data) {
        switch (data.type) {
            case 'new_message':
                await this._handleNewMessage(data);
                break;
            case 'friend_request':
                this._handleFriendRequest(data);
                break;
            case 'user_status_change':
                this._handleStatusChange(data);
                break;
            default:
                console.log("Unknown socket message type:", data.type);
        }
    }

    // IMPROVED: Enhanced new message handling
    async _handleNewMessage(data) {
        // Skip own messages
        if (data.message.sender_id == this.user.id) return;
        
        try {
            // Validate session access
            if (!this._hasSessionAccess(data.session_token)) {
                console.warn("Received message for unauthorized session");
                return;
            }
            
            // Process message
            await this._processMessage(data.session_token, data.message, 'realtime');
            
            // Update unread count if not current session
            if (data.session_token !== this.currentSession?.token) {
                this._updateUnreadCount(data.session_token);
            }
            
            this._playNotificationSound();
            
        } catch (error) {
            console.error("❌ Error handling new message:", error);
            this._showNotification('Error receiving message', 'error', 3000);
        }
    }

    // NEW: Session access validation
    _hasSessionAccess(sessionToken) {
        const session = this.sessions.find(s => s.token === sessionToken);
        return !!session;
    }

    // =================
    // FRIENDS MANAGEMENT - PRESERVED FROM ORIGINAL
    // =================
    
    async _loadFriends() {
        try {
            const response = await fetch('/api/friends');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.friends = data.friends || [];
                this._renderFriendsList();
                console.log(`✅ Loaded ${this.friends.length} friends`);
            }
        } catch (error) {
            console.error("❌ Failed to load friends:", error);
            this._showNotification('Failed to load friends list', 'error');
        }
    }

    async addFriend(userIdOrUsername) {
        try {
            const response = await fetch('/api/friends/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_identifier: userIdOrUsername })
            });

            const data = await response.json();

            if (data.status === 'success') {
                this._showNotification('Friend request sent successfully', 'success');
                await this._loadFriends(); // Refresh friends list
            } else {
                this._showNotification(data.message || 'Failed to send friend request', 'error');
            }
        } catch (error) {
            console.error('❌ Add friend error:', error);
            this._showNotification('Failed to send friend request', 'error');
        }
    }

    async removeFriend(friendId) {
        if (!confirm('Are you sure you want to remove this friend?')) return;

        try {
            const response = await fetch(`/api/friends/${friendId}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.status === 'success') {
                this._showNotification('Friend removed successfully', 'success');
                await this._loadFriends();
            } else {
                this._showNotification(data.message || 'Failed to remove friend', 'error');
            }
        } catch (error) {
            console.error('❌ Remove friend error:', error);
            this._showNotification('Failed to remove friend', 'error');
        }
    }

    async _loadFriendRequests() {
        try {
            const response = await fetch('/api/friends/requests');
            const data = await response.json();
            
            if (data.status === 'success') {
                this._renderFriendRequests(data.requests);
            }
        } catch (error) {
            console.error("❌ Failed to load friend requests:", error);
        }
    }

    async respondToFriendRequest(requestId, action) {
        try {
            const response = await fetch(`/api/friends/requests/${requestId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action })
            });

            const data = await response.json();

            if (data.status === 'success') {
                this._showNotification(`Friend request ${action}ed`, 'success');
                await this._loadFriendRequests();
                if (action === 'accept') {
                    await this._loadFriends();
                }
            } else {
                this._showNotification(data.message || `Failed to ${action} friend request`, 'error');
            }
        } catch (error) {
            console.error(`❌ ${action} friend request error:`, error);
            this._showNotification(`Failed to ${action} friend request`, 'error');
        }
    }

    // =================
    // SESSION MANAGEMENT - PRESERVED
    // =================
    
    async _loadSessions() {
        try {
            const response = await fetch('/api/sessions/active');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.sessions = data.sessions || [];
                this._renderSessionsList();
                console.log(`✅ Loaded ${this.sessions.length} sessions`);
            }
        } catch (error) {
            console.error("❌ Failed to load sessions:", error);
        }
    }

    async _selectFriend(userId) {
        const friend = this.friends.find(f => f.user_id === userId);
        if (friend) {
            this.currentChatPartner = friend;
            await this._initSession(userId);
        }
    }

    // =================
    // POLLING FALLBACK - PRESERVED
    // =================
    
    _enablePollingFallback() {
        if (this.pollingInterval) return; // Already polling
        
        console.log("🔄 Enabling polling fallback");
        
        let lastMessageId = 0;
        
        this.pollingInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/polling/messages?last_id=${lastMessageId}`);
                
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.messages && data.messages.length > 0) {
                        for (const msgData of data.messages) {
                            await this._handleNewMessage(msgData);
                        }
                        lastMessageId = data.last_id;
                    }
                }
            } catch (error) {
                console.error("❌ Polling error:", error);
            }
        }, 3000); // Poll every 3 seconds
    }

    // =================
    // MESSAGE LOADING AND CACHING - PRESERVED
    // =================
    
    async _loadMessages(sessionToken, limit = 50, offset = 0) {
        try {
            const response = await fetch(`/api/messages/${sessionToken}?limit=${limit}&offset=${offset}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                // Process messages in batch
                for (const message of data.messages) {
                    await this._processMessage(sessionToken, message, 'history');
                }
                
                console.log(`✅ Loaded ${data.messages.length} messages for session`);
            }
        } catch (error) {
            console.error("❌ Failed to load messages:", error);
            this._showNotification('Failed to load message history', 'error');
        }
    }

    async _storeMessage(sessionToken, message) {
        if (!this.messages.has(sessionToken)) {
            this.messages.set(sessionToken, []);
        }
        
        const sessionMessages = this.messages.get(sessionToken);
        
        // Avoid duplicates
        const existingIndex = sessionMessages.findIndex(m => m.id === message.id);
        if (existingIndex >= 0) {
            sessionMessages[existingIndex] = message; // Update existing
        } else {
            sessionMessages.push(message);
            
            // Keep only recent messages in memory
            if (sessionMessages.length > this.maxCachedMessages) {
                sessionMessages.splice(0, sessionMessages.length - this.maxCachedMessages);
            }
        }
        
        // Sort by timestamp
        sessionMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    }

    // =================
    // UI MANAGEMENT - PRESERVED
    // =================
    
    _initElements() {
        this.elements = {
            messageInput: document.getElementById('message-input'),
            sendButton: document.getElementById('send-button'),
            messagesContainer: document.getElementById('messages-container'),
            friendsList: document.getElementById('friends-list'),
            sessionsList: document.getElementById('sessions-list'),
            friendRequests: document.getElementById('friend-requests'),
            addFriendBtn: document.getElementById('add-friend-btn'),
            addFriendInput: document.getElementById('add-friend-input'),
            chatHeader: document.getElementById('chat-header'),
            typingIndicator: document.getElementById('typing-indicator'),
            connectionStatus: document.getElementById('connection-status')
        };
    }

    _setupEventListeners() {
        // Message sending
        this.elements.sendButton?.addEventListener('click', () => this.sendMessage());
        this.elements.messageInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Add friend
        this.elements.addFriendBtn?.addEventListener('click', () => {
            const userInput = this.elements.addFriendInput?.value.trim();
            if (userInput) {
                this.addFriend(userInput);
                this.elements.addFriendInput.value = '';
            }
        });

        // Typing indicator
        this.elements.messageInput?.addEventListener('input', () => {
            this._handleTyping();
        });

        // Window focus/blur for activity tracking
        window.addEventListener('focus', () => {
            this.lastActivity = Date.now();
        });

        window.addEventListener('beforeunload', () => {
            if (this.socket) {
                this.socket.disconnect();
            }
        });
    }

    _addMessageToUI(message) {
        if (!this.elements.messagesContainer) return;
        
        const messageEl = document.createElement('div');
        messageEl.className = `message ${message.is_mine ? 'mine' : 'theirs'}`;
        messageEl.dataset.messageId = message.id;

        const timeStr = new Date(message.timestamp).toLocaleTimeString();
        
        messageEl.innerHTML = `
            <div class="message-content">${this._escapeHtml(message.content)}</div>
            <div class="message-time">${timeStr}</div>
            ${message.is_mine ? '<div class="message-status">✓</div>' : ''}
        `;
        
        this.elements.messagesContainer.appendChild(messageEl);
        this.elements.messagesContainer.scrollTop = this.elements.messagesContainer.scrollHeight;
    }

    _renderFriendsList() {
        if (!this.elements.friendsList) return;
        
        this.elements.friendsList.innerHTML = this.friends.map(friend => `
            <div class="friend-item" data-user-id="${friend.user_id}">
                <div class="friend-info">
                    <span class="friend-name">${this._escapeHtml(friend.username)}</span>
                    <span class="friend-id">${friend.user_id}</span>
                </div>
                <div class="friend-actions">
                    <span class="friend-status ${friend.is_online ? 'online' : 'offline'}">
                        ${friend.is_online ? '🟢' : '⚪'}
                    </span>
                    <button class="chat-btn" data-user-id="${friend.user_id}">💬</button>
                    <button class="remove-friend-btn" data-friend-id="${friend.id}">❌</button>
                </div>
            </div>
        `).join('');
        
        // Add event listeners
        this.elements.friendsList.querySelectorAll('.chat-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const userId = btn.dataset.userId;
                this._selectFriend(userId);
            });
        });
        
        this.elements.friendsList.querySelectorAll('.remove-friend-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const friendId = btn.dataset.friendId;
                this.removeFriend(friendId);
            });
        });
    }

    _renderFriendRequests(requests) {
        if (!this.elements.friendRequests) return;
        
        this.elements.friendRequests.innerHTML = requests.map(req => `
            <div class="friend-request-item">
                <span class="request-from">${this._escapeHtml(req.from_username)}</span>
                <div class="request-actions">
                    <button class="accept-btn" data-request-id="${req.id}">✅ Accept</button>
                    <button class="decline-btn" data-request-id="${req.id}">❌ Decline</button>
                </div>
            </div>
        `).join('');
        
        // Add event listeners
        this.elements.friendRequests.querySelectorAll('.accept-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const requestId = btn.dataset.requestId;
                this.respondToFriendRequest(requestId, 'accept');
            });
        });
        
        this.elements.friendRequests.querySelectorAll('.decline-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const requestId = btn.dataset.requestId;
                this.respondToFriendRequest(requestId, 'decline');
            });
        });
    }

    _updateChatUI() {
        if (this.currentSession && this.elements.chatHeader) {
            const otherUser = this.currentSession.other_user;
            this.elements.chatHeader.innerHTML = `
                <div class="chat-partner-info">
                    <span class="partner-name">${this._escapeHtml(otherUser.username)}</span>
                    <span class="partner-id">${otherUser.user_id}</span>
                </div>
                <div class="session-info">
                    <span class="session-status">🔐 Encrypted</span>
                </div>
            `;
        }
    }

    _showNotification(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <span class="notification-message">${this._escapeHtml(message)}</span>
            <button class="notification-close">×</button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove
        const removeNotification = () => {
            if (notification.parentNode) {
                notification.remove();
            }
        };
        
        // Close button
        notification.querySelector('.notification-close').addEventListener('click', removeNotification);
        
        // Auto-remove after duration
        setTimeout(removeNotification, duration);
    }

    _playNotificationSound() {
        try {
            // Simple notification beep
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.value = 800;
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0, audioContext.currentTime);
            gainNode.gain.linearRampToValueAtTime(0.1, audioContext.currentTime + 0.01);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.5);
        } catch (error) {
            // Fallback - no sound
            console.log("Could not play notification sound");
        }
    }

    // =================
    // UTILITY FUNCTIONS - PRESERVED
    // =================

    async _getCurrentUser() {
        const response = await fetch('/api/check_auth');
        if (!response.ok) {
            throw new Error('Not authenticated');
        }
        return await response.json();
    }

    async _getUserPublicKey(userId) {
        const cacheKey = `public_key_${userId}`;
        
        if (this.apiCache.has(cacheKey)) {
            const cached = this.apiCache.get(cacheKey);
            if (Date.now() - cached.timestamp < 3600000) { // 1 hour cache
                return cached.key;
            }
        }
        
        const response = await fetch(`/api/user/${userId}/public_key`);
        if (!response.ok) {
            throw new Error(`Failed to get public key for user ${userId}`);
        }
        
        const keyData = await response.json();
        
        // Cache result
        this.apiCache.set(cacheKey, {
            key: keyData.public_key,
            timestamp: Date.now()
        });
        
        return keyData.public_key;
    }

    async _getSessionKeyOptimized(sessionToken) {
        // Check memory first
        const sessionKey = window.cryptoManager.getSessionKey(sessionToken);
        if (sessionKey) {
            return await window.cryptoManager.importSessionKey(sessionKey);
        }
        return null;
    }

    async _getSocketConfig() {
        return {
            socketUrl: window.location.origin,
            path: '/socket.io/',
            transports: ['websocket', 'polling']
        };
    }

    _handleTyping() {
        if (!this.isTyping) {
            this.isTyping = true;
            // Send typing indicator to other user
            if (this.socket && this.currentSession) {
                this.socket.emit('typing_start', {
                    session_token: this.currentSession.token
                });
            }
        }
        
        // Clear existing timeout
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        
        // Set new timeout
        this.typingTimeout = setTimeout(() => {
            this.isTyping = false;
            if (this.socket && this.currentSession) {
                this.socket.emit('typing_stop', {
                    session_token: this.currentSession.token
                });
            }
        }, 1000);
    }

    _updateUnreadCount(sessionToken) {
        const currentCount = this.unreadCounts.get(sessionToken) || 0;
        this.unreadCounts.set(sessionToken, currentCount + 1);
        
        // Update UI badge
        const sessionElement = document.querySelector(`[data-session-token="${sessionToken}"]`);
        if (sessionElement) {
            let badge = sessionElement.querySelector('.unread-badge');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'unread-badge';
                sessionElement.appendChild(badge);
            }
            badge.textContent = currentCount + 1;
        }
    }

    _startPeriodicTasks() {
        // Update last activity
        setInterval(() => {
            this.lastActivity = Date.now();
        }, 30000); // Every 30 seconds
        
        // Clean up old cached messages
        setInterval(() => {
            this._cleanupOldMessages();
        }, 300000); // Every 5 minutes
        
        // Refresh friends list periodically
        setInterval(() => {
            this._loadFriends();
        }, 60000); // Every minute
    }

    _cleanupOldMessages() {
        const cutoffTime = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago
        
        for (const [sessionToken, messages] of this.messages.entries()) {
            const filteredMessages = messages.filter(msg => 
                new Date(msg.timestamp).getTime() > cutoffTime
            );
            
            if (filteredMessages.length !== messages.length) {
                this.messages.set(sessionToken, filteredMessages);
                console.log(`🧹 Cleaned up old messages for session ${sessionToken.slice(0, 8)}...`);
            }
        }
    }

    _handleStatusChange(data) {
        const { user_id, is_online } = data;
        
        // Update friend status
        const friend = this.friends.find(f => f.user_id === user_id);
        if (friend) {
            friend.is_online = is_online;
            this._renderFriendsList();
        }
        
        // Update chat header if it's current chat partner
        if (this.currentChatPartner && this.currentChatPartner.user_id === user_id) {
            this._updateChatUI();
        }
    }

    _handleFriendRequest(data) {
        this._showNotification(`New friend request from ${data.from_username}`, 'info');
        this._loadFriendRequests();
    }

    _renderSessionsList() {
        if (!this.elements.sessionsList) return;
        
        this.elements.sessionsList.innerHTML = this.sessions.map(session => {
            const otherUser = session.initiator_id === this.user.id ? 
                session.recipient : session.initiator;
            
            const unreadCount = this.unreadCounts.get(session.token) || 0;
            
            return `
                <div class="session-item" data-session-token="${session.token}">
                    <div class="session-info">
                        <span class="session-partner">${this._escapeHtml(otherUser.username)}</span>
                        <span class="session-time">${new Date(session.last_activity).toLocaleString()}</span>
                    </div>
                    ${unreadCount > 0 ? `<span class="unread-badge">${unreadCount}</span>` : ''}
                </div>
            `;
        }).join('');
        
        // Add click handlers
        this.elements.sessionsList.querySelectorAll('.session-item').forEach(item => {
            item.addEventListener('click', () => {
                const sessionToken = item.dataset.sessionToken;
                const session = this.sessions.find(s => s.token === sessionToken);
                if (session) {
                    const otherUser = session.initiator_id === this.user.id ? 
                        session.recipient : session.initiator;
                    this._selectFriend(otherUser.user_id);
                    
                    // Clear unread count
                    this.unreadCounts.delete(sessionToken);
                    this._renderSessionsList();
                }
            });
        });
    }

    _escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // =================
    // PUBLIC API
    // =================

    getCurrentSession() {
        return this.currentSession;
    }

    getCurrentUser() {
        return this.user;
    }

    getFriends() {
        return this.friends;
    }

    getMessages(sessionToken) {
        return this.messages.get(sessionToken) || [];
    }

    isConnected() {
        return this.socket && this.socket.connected;
    }

    // Force refresh of all data
    async refresh() {
        try {
            await this._loadFriends();
            await this._loadSessions();
            await this._loadFriendRequests();
            this._showNotification('Data refreshed', 'success', 2000);
        } catch (error) {
            console.error('❌ Refresh failed:', error);
            this._showNotification('Failed to refresh data', 'error');
        }
    }

    // Manual cleanup
    cleanup() {
        if (this.socket) {
            this.socket.disconnect();
        }
        
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
        }
        
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        
        // Clear caches
        this.apiCache.clear();
        this.messages.clear();
        this.unreadCounts.clear();
        this.processingMessages.clear();
        
        console.log('🧹 ChatManager cleaned up');
    }
}

// Global initialization
let chatManager = null;

document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Check if user is authenticated and has crypto keys
        const auth = await fetch('/api/check_auth');
        if (!auth.ok) {
            window.location.href = '/';
            return;
        }
        
        // Initialize crypto manager
        if (!window.cryptoManager) {
            window.cryptoManager = new CryptoManager();
        }
        
        const hasKeys = await window.cryptoManager.loadKeys();
        if (!hasKeys) {
            alert('Please login with your private key file');
            window.location.href = '/';
            return;
        }
        
        // Initialize chat manager
        chatManager = new ChatManager();
        await chatManager.init();
        
        // Make globally available
        window.chatManager = chatManager;
        
        console.log('✅ Chat application initialized successfully');
        
    } catch (error) {
        console.error('❌ Failed to initialize chat application:', error);
        alert('Failed to initialize chat application: ' + error.message);
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (chatManager) {
        chatManager.cleanup();
    }
});
