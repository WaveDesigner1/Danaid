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
