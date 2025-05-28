/**
 * chat.js - ZOPTYMALIZOWANY Chat Manager z poprawkami deszyfrowania + Socket.IO Auto-join Fix
 * Usunięto duplikacje, dodano cache, debouncing, unified message processing
 * Poprawiono funkcje _needsDecryption, _processMessage, dodano _debugDecryption
 * NAPRAWIONO: _ensureSessionKey i _performKeyExchange dla key mismatch
 * 🚀 DODANO: Socket.IO auto-join do session rooms - REAL-TIME MESSAGING FIX
 */
class ChatManager {
  constructor() {
    // Core properties
    this.socket = null;
    this.currentSession = null;
    this.friends = [];
    this.sessions = [];
    this.messages = new Map();
    this.user = this._loadUserData();
    this.db = null;
    this.pollingInterval = null;
    
    // === KEYBOARD SHORTCUTS ===
document.addEventListener('keydown', (e) => {
  // Ctrl+R or F5 - Refresh messages
  if ((e.ctrlKey && e.key === 'r') || e.key === 'F5') {
    if (window.chatManager && window.chatManager.currentSession) {
      e.preventDefault();
      window.chatManager.refreshMessages();
    }
  }
  
  // Ctrl+Shift+Delete - Clear conversation
  if (e.ctrlKey && e.shiftKey && e.key === 'Delete') {
    if (window.chatManager && window.chatManager.currentSession) {
      e.preventDefault();
      window.chatManager.clearConversation();
    }
  }
  
  // Ctrl+Shift+D - Debug info
  if (e.ctrlKey && e.shiftKey && e.key === 'D') {
    if (window.chatManager) {
      e.preventDefault();
      window.chatManager.debugInfo();
    }
  }
});

// === PERFORMANCE MONITORING ===
if (typeof PerformanceObserver !== 'undefined') {
  const observer = new PerformanceObserver((list) => {
    const entries = list.getEntries();
    entries.forEach((entry) => {
      if (entry.duration > 100) { // Log slow operations
        console.warn(`Slow operation detected: ${entry.name} took ${entry.duration.toFixed(2)}ms`);
      }
    });
  });
  
  try {
    observer.observe({ entryTypes: ['measure', 'navigation'] });
  } catch (e) {
    // Observer not supported in this browser
  }
}

// Initialize ChatManager
window.chatManager = new ChatManager();

// Backward compatibility
window.ChatInterface = ChatManager;
window.chatInterface = window.chatManager;

// Debug helper for console
window.debugChat = () => window.chatManager.debugInfo();

// 🔍 VALIDATION CHECK - ensure all critical functions are present
if (typeof window !== 'undefined') {
  setTimeout(() => {
    const chatManager = window.chatManager;
    const criticalFunctions = [
      '_joinSessionRoom',
      '_initSession', 
      '_ensureSessionKey',
      '_performKeyExchange',
      '_processMessage',
      '_needsDecryption',
      'sendMessage',
      'refreshMessages',
      'checkRealTimeStatus'
    ];
    
    const missing = criticalFunctions.filter(fn => typeof chatManager[fn] !== 'function');
    
    if (missing.length === 0) {
      console.log('✅ All critical functions validated - ChatManager complete');
    } else {
      console.error('❌ Missing functions:', missing);
    }
    
    // Check Socket.IO integration
    if (chatManager.socket) {
      console.log('✅ Socket.IO initialized');
      console.log('📡 Socket connected:', chatManager.socket.connected);
    } else {
      console.warn('⚠️ Socket.IO not initialized');
    }
  }, 1000);
} NOWE PROPERTIES DLA OPTYMALIZACJI ===
    this.keyExchangePromises = new Map(); // Debouncing key exchange
    this.apiCache = new Map(); // Cache API responses
    this.messageProcessingQueue = []; // Queue for message processing
    
    // UI elements
    this.elements = {};
    
    // Callbacks
    this.onMessageReceived = null;
    this.onFriendsUpdated = null;
    this.onSessionsUpdated = null;
    
    // Initialize all components
    this._initDatabase();
    this._initDOM();
    this._initSocket();
    this._initEvents();
    this._initClearButton();
    this._loadInitialData();
    
    console.log("✅ Optimized ChatManager initialized:", this.user.username);
    
    // Check real-time status after 5 seconds
    setTimeout(() => {
      const rtStatus = this.checkRealTimeStatus();
      console.log("📡 Real-time status:", rtStatus);
      
      if (rtStatus.status === 'real-time') {
        this._showNotification('✅ Real-time messaging active', 'success', 2000);
      } else if (rtStatus.status === 'polling') {
        this._showNotification('⚠️ Using polling mode', 'warning', 3000);
      } else {
        this._showNotification('❌ Messaging offline', 'error', 3000);
      }
    }, 5000);
  }

  // === INITIALIZATION ===
  _loadUserData() {
    return {
      id: sessionStorage.getItem('user_id'),
      username: sessionStorage.getItem('username'),
      isAdmin: sessionStorage.getItem('is_admin') === 'true',
      isLoggedIn: sessionStorage.getItem('isLoggedIn') === 'true'
    };
  }

  _initDOM() {
    this.elements = {
      friendsList: document.getElementById('friend-list'),
      messagesContainer: document.getElementById('messages'),
      messageInput: document.getElementById('message-input'),
      sendButton: document.getElementById('send-button'),
      chatHeader: document.getElementById('chat-header'),
      addFriendBtn: document.getElementById('add-friend-btn'),
      logoutBtn: document.getElementById('logout-btn'),
      requestBadge: document.getElementById('friend-request-count')
    };

    // Add admin link if user is admin
    if (this.user.isAdmin) {
      this._addAdminLink();
    }
  }

  _addAdminLink() {
    const userControls = document.querySelector('.user-controls');
    if (userControls && !document.getElementById('admin-link')) {
      const adminLink = document.createElement('a');
      adminLink.id = 'admin-link';
      adminLink.href = '/admin_dashboard';
      adminLink.innerHTML = '<i class="fas fa-cog"></i> Admin';
      adminLink.className = 'btn btn-secondary btn-sm';
      userControls.insertBefore(adminLink, userControls.firstChild);
    }
  }

  async _initDatabase() {
    try {
      const request = indexedDB.open('ChatMessages', 1);
      
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('messages')) {
          db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
        }
      };
      
      request.onsuccess = (event) => {
        this.db = event.target.result;
        this._loadStoredMessages();
        console.log("💾 Database initialized");
      };
    } catch (error) {
      console.error("Database init error:", error);
    }
  }

  async _loadStoredMessages() {
    if (!this.db) return;
    
    try {
      const tx = this.db.transaction(['messages'], 'readonly');
      const store = tx.objectStore('messages');
      const messages = await new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      // Group messages by session
      messages.forEach(msg => {
        if (!this.messages.has(msg.sessionToken)) {
          this.messages.set(msg.sessionToken, []);
        }
        this.messages.get(msg.sessionToken).push(msg);
      });
      
      console.log(`📥 Loaded messages for ${this.messages.size} sessions`);
    } catch (error) {
      console.error("Message loading error:", error);
    }
  }

  // === SOCKET.IO INTEGRATION ===
  async _initSocket() {
    try {
      // Get Socket.IO config (with cache)
      const config = await this._getSocketConfig();
      
      // Initialize Socket.IO
      this.socket = io(config.socketUrl, {
        path: config.path || '/socket.io/',
        transports: ['websocket', 'polling'],
        upgrade: true,
        reconnection: true,
        secure: window.location.protocol === 'https:'
      });
      
      this._setupSocketEvents();
      console.log("🔌 Socket.IO initialized");
    } catch (error) {
      console.error("Socket init error:", error);
    }
  }

  async _getSocketConfig() {
    const cacheKey = 'socket_config';
    
    // Check cache first
    if (this.apiCache.has(cacheKey)) {
      const cached = this.apiCache.get(cacheKey);
      if (Date.now() - cached.timestamp < 600000) { // 10 min cache
        return cached.config;
      }
    }
    
    try {
      const response = await fetch('/api/websocket/config');
      if (response.ok) {
        const config = await response.json();
        if (window.location.protocol === 'https:' && config.socketUrl?.startsWith('http:')) {
          config.socketUrl = config.socketUrl.replace('http:', 'https:');
        }
        
        // Cache result
        this.apiCache.set(cacheKey, {
          config: config,
          timestamp: Date.now()
        });
        
        return config;
      }
    } catch (e) {
      console.warn("Using default Socket.IO config");
    }
    
    const defaultConfig = {
      socketUrl: `${window.location.protocol}//${window.location.host}`,
      path: '/socket.io/'
    };
    
    // Cache default config
    this.apiCache.set(cacheKey, {
      config: defaultConfig,
      timestamp: Date.now()
    });
    
    return defaultConfig;
  }

  _setupSocketEvents() {
    // 🚀 NAPRAWIONY CONNECT HANDLER z auto-rejoin
    this.socket.on('connect', () => {
      console.log("✅ Socket.IO connected");
      this.socket.emit('register_user', { user_id: this.user.id });
      
      // 🔥 AUTO-REJOIN CURRENT SESSION IF EXISTS
      if (this.currentSession && this.currentSession.token) {
        console.log('🔄 Rejoining session room after reconnect...');
        this._joinSessionRoom(this.currentSession.token);
      }
    });

    this.socket.on('disconnect', (reason) => {
      console.log(`🔌 Socket.IO disconnected: ${reason}`);
      // Auto-reconnect handled by Socket.IO
    });

    // 🚀 DODANY: joined_session event handler
    this.socket.on('joined_session', (data) => {
      console.log('✅ Successfully joined session room:', data.session_token?.slice(0, 8));
      if (data.status === 'success') {
        this._showNotification('🔐 Secure channel established', 'success', 2000);
      }
    });

    this.socket.on('message', (data) => {
      console.log("📨 Real-time message received:", data.type);
      this._handleSocketMessage(data);
    });

    this.socket.on('connect_error', (error) => {
      console.error("❌ Socket.IO error:", error);
      // Fallback to polling if Socket.IO fails
      this._enablePollingFallback();
    });
  }

  // 🚀 DODANA: _joinSessionRoom function
  async _joinSessionRoom(sessionToken) {
    if (!this.socket || !this.socket.connected) {
      console.warn('Socket not connected, cannot join room');
      return false;
    }
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        console.error('❌ Join session timeout');
        resolve(false); // Don't reject - continue anyway
      }, 5000);
      
      console.log('🔌 Joining Socket.IO room for session:', sessionToken.slice(0, 8));
      
      this.socket.emit('join_session', { 
        session_token: sessionToken 
      }, (response) => {
        clearTimeout(timeout);
        if (response && response.status === 'success') {
          console.log('✅ Successfully joined session room');
          resolve(true);
        } else {
          console.error('❌ Failed to join session room:', response);
          resolve(false); // Don't reject - continue anyway
        }
      });
    });
  }

  _handleSocketMessage(data) {
    switch (data.type) {
      case 'new_message':
        this._handleNewMessage(data);
        break;
      case 'friend_request':
        this._handleFriendRequest(data);
        break;
      case 'user_status_change':
        this._handleStatusChange(data);
        break;
      case 'online_users':
        this._handleOnlineUsers(data);
        break;
    }
  }

  // === ZUNIFIKOWANA FUNKCJA DESZYFROWANIA ===
  async _handleNewMessage(data) {
    // Avoid echo
    if (data.message.sender_id == this.user.id) return;
    
    // Process message through unified pipeline
    await this._processMessage(data.session_token, data.message, 'realtime');
    
    // Update UI if current session
    if (data.session_token === this.currentSession?.token) {
      this._refreshCurrentChat();
    } else {
      this._updateUnreadCount(data.session_token);
    }
    
    this._playNotificationSound();
  }

  // === POPRAWIONA FUNKCJA _needsDecryption ===
  _needsDecryption(message) {
    // Brak IV = na pewno nie zaszyfrowane
    if (!message.iv) {
      console.log("🔍 No IV - plain text");
      return false;
    }
    
    // Bardzo krótkie (mniej niż 20 znaków) = prawdopodobnie plain text
    if (message.content.length < 20) {
      console.log("🔍 Very short message - probably plain text");
      return false;
    }
    
    // Sprawdź czy to wygląda jak base64 (typowe dla AES-GCM output)
    const base64Pattern = /^[A-Za-z0-9+/]+={0,2}$/;
    if (base64Pattern.test(message.content)) {
      console.log("🔐 Base64 pattern detected - needs decryption");
      return true;
    }
    
    // Sprawdź czy to wygląda jak hex (alternatywny format)
    const hexPattern = /^[a-fA-F0-9]+$/;
    if (hexPattern.test(message.content) && message.content.length > 32) {
      console.log("🔐 Hex pattern detected - needs decryption");
      return true;
    }
    
    // Sprawdź czy ma nietypowe znaki dla normalnego tekstu
    const hasUnusualChars = /[^\w\s\.\,\!\?\-\(\)\[\]\"\']+/.test(message.content);
    if (hasUnusualChars && message.content.length > 30) {
      console.log("🔐 Unusual characters detected - might be encrypted");
      return true;
    }
    
    // Jeśli nic nie pasuje, prawdopodobnie plain text
    console.log("📝 Looks like plain text");
    return false;
  }

  // === DODATKOWA FUNKCJA DEBUG ===
  async _debugDecryption(sessionToken, message) {
    console.log("=== DEBUG DECRYPTION ===");
    console.log("Session token:", sessionToken.slice(0, 8) + "...");
    console.log("Message content preview:", message.content.slice(0, 100) + "...");
    console.log("Message IV:", message.iv);
    console.log("Content length:", message.content.length);
    console.log("Needs decryption:", this._needsDecryption(message));
    
    const sessionKeyBase64 = window.cryptoManager.getSessionKey(sessionToken);
    console.log("Has session key:", !!sessionKeyBase64);
    
    if (sessionKeyBase64 && this._needsDecryption(message)) {
      try {
        const sessionKey = await window.cryptoManager.importSessionKey(sessionKeyBase64);
        console.log("✅ Session key imported successfully");
        
        const decrypted = await window.cryptoManager.decryptMessage(sessionKey, {
          data: message.content,
          iv: message.iv
        });
        console.log("✅ Decryption successful:", decrypted.slice(0, 50) + "...");
        return decrypted;
      } catch (error) {
        console.error("❌ Decryption failed:", error.message);
        return "[Decryption failed: " + error.message + "]";
      }
    }
    
    return message.content;
  }

  // === POPRAWIONA FUNKCJA _processMessage ===
  async _processMessage(sessionToken, message, source = 'unknown') {
    try {
      console.log(`📨 Processing ${source} message for session: ${sessionToken.slice(0, 8)}`);
      
      // Check if already processed (deduplication)
      const messageKey = `${sessionToken}-${message.id || message.timestamp}`;
      if (this.messageProcessingQueue.includes(messageKey)) {
        console.log("⚠️ Message already being processed, skipping");
        return;
      }
      this.messageProcessingQueue.push(messageKey);
      
      let processedMessage = { ...message };
      
      // === IMPROVED DECRYPTION LOGIC ===
      const needsDecryption = this._needsDecryption(message);
      console.log(`🔍 Message needs decryption: ${needsDecryption}`);
      
      if (needsDecryption) {
        const sessionKey = await this._getSessionKeyOptimized(sessionToken);
        
        if (sessionKey) {
          try {
            console.log("🔐 Attempting decryption...");
            const decryptedContent = await window.cryptoManager.decryptMessage(sessionKey, {
              data: message.content,
              iv: message.iv
            });
            processedMessage.content = decryptedContent;
            console.log("✅ Message decrypted successfully:", decryptedContent.slice(0, 30) + "...");
          } catch (decryptError) {
            console.error("⚠️ Decryption failed:", decryptError.message);
            
            // Try debug decryption for more info
            processedMessage.content = await this._debugDecryption(sessionToken, message);
          }
        } else {
          console.log("⚠️ No session key available");
          console.log("⚠️ No session key available");
          console.log("🔍 DEBUG - Session token:", sessionToken.slice(0, 8));
          console.log("🔍 DEBUG - Crypto manager exists:", !!window.cryptoManager);
          console.log("🔍 DEBUG - Has session key?:", window.cryptoManager?.hasSessionKey(sessionToken));
          console.log("🔍 DEBUG - Raw session key:", window.cryptoManager?.getSessionKey(sessionToken)?.slice(0, 20));
          processedMessage.content = '[Encrypted - key not available]';
        }
      } else {
        console.log("📝 Message is plain text, no decryption needed");
      }
      
      // Store processed message
      await this._storeMessage(sessionToken, processedMessage);
      
      // Remove from processing queue
      const queueIndex = this.messageProcessingQueue.indexOf(messageKey);
      if (queueIndex > -1) {
        this.messageProcessingQueue.splice(queueIndex, 1);
      }
      
    } catch (error) {
      console.error("❌ Message processing error:", error);
      
      // Store error message
      const errorMessage = { ...message, content: '[Processing failed: ' + error.message + ']' };
      await this._storeMessage(sessionToken, errorMessage);
    }
  }

  // === DODATKOWA FUNKCJA TESTOWA ===
  async testDecryption(sessionToken, messageContent, iv) {
    console.log("=== MANUAL DECRYPTION TEST ===");
    
    const fakeMessage = {
      content: messageContent,
      iv: iv,
      id: 'test',
      timestamp: new Date().toISOString()
    };
    
    console.log("Testing message:", fakeMessage);
    
    const result = await this._debugDecryption(sessionToken, fakeMessage);
    console.log("Final result:", result);
    
    return result;
  }

  _handleFriendRequest(data) {
    this._loadPendingRequests();
    this._showNotification(`New friend request from ${data.from_user.username}`, 'info');
  }

  _handleStatusChange(data) {
    this._updateUserStatus(data.user_id, data.is_online);
  }

  _handleOnlineUsers(data) {
    this.friends.forEach(friend => {
      friend.is_online = data.users.includes(friend.user_id);
    });
    this._renderFriendsList();
  }

  // === POLLING FALLBACK ===
  _enablePollingFallback() {
    if (this.pollingInterval) return; // Already enabled
    
    console.log("🔄 Enabling polling fallback...");
    
    let lastMessageId = 0;
    
    this.pollingInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/polling/messages?last_id=${lastMessageId}`);
        if (response.ok) {
          const data = await response.json();
          
          if (data.status === 'success' && data.messages.length > 0) {
            data.messages.forEach(msg => {
              if (msg.type === 'new_message') {
                this._handleNewMessage(msg);
              }
            });
            
            lastMessageId = data.last_id;
          }
        }
      } catch (error) {
        console.error("Polling error:", error);
      }
    }, 3000); // Poll every 3 seconds
  }

  // === EVENT HANDLERS ===
  _initEvents() {
    if (!this.elements.sendButton || !this.elements.messageInput) return;
    
    // Send message
    this.elements.sendButton.addEventListener('click', () => this.sendMessage());
    
    // Enter to send
    this.elements.messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });
    
    // Add friend
    this.elements.addFriendBtn?.addEventListener('click', () => {
      this._showAddFriendModal();
    });
    
    // Logout
    this.elements.logoutBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      this.logout();
    });
    
    // Friend requests notification
    this.elements.requestBadge?.parentElement?.addEventListener('click', () => {
      this._showFriendRequestsModal();
    });
    
    // Modal events
    this._initModalEvents();
    
    // Add refresh button to message input area
    const messageInputArea = document.querySelector('.message-input-area');
    if (messageInputArea && !document.getElementById('refresh-messages-btn')) {
      const refreshBtn = document.createElement('button');
      refreshBtn.id = 'refresh-messages-btn';
      refreshBtn.className = 'btn btn-secondary btn-sm';
      refreshBtn.innerHTML = '<i class="fas fa-sync"></i>';
      refreshBtn.title = 'Refresh messages (Ctrl+R)';
      refreshBtn.style.marginRight = '8px';
      
      refreshBtn.addEventListener('click', () => this.refreshMessages());
      
      messageInputArea.insertBefore(refreshBtn, messageInputArea.firstChild);
    }
  }

  _initClearButton() {
    const clearBtn = document.getElementById('clear-conversation-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        if (this.currentSession) {
          this.clearConversation();
        }
      });
    }
  }

  _initModalEvents() {
    // Add friend modal
    const sendRequestBtn = document.getElementById('send-friend-request-btn');
    sendRequestBtn?.addEventListener('click', () => this._sendFriendRequest());
    
    // Close modals
    document.querySelectorAll('.modal .close, .modal-close').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.target.closest('.modal').style.display = 'none';
      });
    });
    
    // Click outside to close
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal')) {
        e.target.style.display = 'none';
      }
    });
  }

  // === DATA LOADING ===
  async _loadInitialData() {
    try {
      await Promise.all([
        this._loadFriends(),
        this._loadSessions(),
        this._loadPendingRequests()
      ]);
      
      // Select first session if available
      if (this.sessions.length > 0) {
        await this._selectSession(this.sessions[0]);
      }
    } catch (error) {
      console.error("Initial data loading error:", error);
    }
  }

  async _loadFriends() {
    try {
      const response = await fetch('/api/friends');
      const data = await response.json();
      
      if (data.status === 'success') {
        this.friends = data.friends;
        this._renderFriendsList();
        console.log(`👥 Loaded ${this.friends.length} friends`);
      }
    } catch (error) {
      console.error("Friends loading error:", error);
    }
  }

  async _loadSessions() {
    try {
      const response = await fetch('/api/sessions/active');
      const data = await response.json();
      
      if (data.status === 'success') {
        this.sessions = data.sessions;
        console.log(`💬 Loaded ${this.sessions.length} sessions`);
        
        if (this.onSessionsUpdated) {
          this.onSessionsUpdated(this.sessions);
        }
      }
    } catch (error) {
      console.error("Sessions loading error:", error);
    }
  }

  async _loadPendingRequests() {
    try {
      const response = await fetch('/api/friend_requests/pending');
      const data = await response.json();
      
      if (data.status === 'success') {
        this._updateRequestBadge(data.requests.length);
      }
    } catch (error) {
      console.error("Pending requests loading error:", error);
    }
  }

  // === UI RENDERING ===
  _renderFriendsList() {
    if (!this.elements.friendsList) return;
    
    this.elements.friendsList.innerHTML = '';
    
    this.friends.forEach(friend => {
      const li = document.createElement('li');
      li.className = 'friend-item';
      li.dataset.userId = friend.user_id;
      
      const session = this.sessions.find(s => s.other_user.user_id === friend.user_id);
      const unreadCount = session?.unread_count || 0;
      
      li.innerHTML = `
        <div class="friend-avatar">
          ${friend.username.charAt(0).toUpperCase()}
          <div class="status-indicator ${friend.is_online ? 'online' : 'offline'}"></div>
        </div>
        <div class="friend-info">
          <div class="friend-name">${friend.username}</div>
          <div class="friend-status ${friend.is_online ? 'online' : 'offline'}">
            ${friend.is_online ? 'Online' : 'Offline'}
          </div>
        </div>
        ${unreadCount > 0 ? `<div class="unread-count">${unreadCount}</div>` : ''}
      `;
      
      li.addEventListener('click', () => this._selectFriend(friend));
      this.elements.friendsList.appendChild(li);
    });
  }

  // === ZAKTUALIZOWANA FUNKCJA _selectFriend ===
  async _selectFriend(friend) {
    // Update UI
    document.querySelectorAll('.friend-item').forEach(item => {
      item.classList.remove('active');
    });
    
    const friendElement = document.querySelector(`[data-user-id="${friend.user_id}"]`);
    friendElement?.classList.add('active');
    
    // Update header with status AND show clear button
    if (this.elements.chatHeader) {
      this.elements.chatHeader.innerHTML = `
        <div class="chat-header-info">
          <h2>${friend.username}</h2>
          <span class="chat-status ${friend.is_online ? 'online' : 'offline'}">
            ${friend.is_online ? 'Online' : 'Offline'}
          </span>
          <span id="session-status" class="session-status">Connecting...</span>
        </div>
        <div class="chat-header-actions">
          <button id="clear-conversation-btn" class="btn btn-warning btn-sm visible" title="Clear all messages">
            <i class="fas fa-trash"></i> Clear
          </button>
        </div>
      `;
      
      // Re-attach clear button handler
      this._initClearButton();
    }
    
    // Initialize session
    await this._initSession(friend.user_id);
  }

  _updateSessionStatus(status) {
    const statusElement = document.getElementById('session-status');
    if (!statusElement) return;
    
    const statusConfig = {
      'ready': { text: '🔒 Encrypted', class: 'ready' },
      'pending': { text: '🔑 Setting up...', class: 'pending' },
      'error': { text: '❌ Error', class: 'error' }
    };
    
    const config = statusConfig[status] || statusConfig.pending;
    statusElement.textContent = config.text;
    statusElement.className = `session-status ${config.class}`;
  }

  // 🚀 NAPRAWIONA _initSession z auto-join
  async _initSession(recipientId) {
    try {
      const response = await fetch('/api/session/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipientId })
      });
      
      const data = await response.json();
      
      if (data.status === 'success') {
        this.currentSession = data.session;
        
        // 🔥 KRYTYCZNY FIX: AUTO-JOIN DO SOCKET.IO ROOM
        if (this.socket && this.socket.connected) {
          await this._joinSessionRoom(data.session.token);
        }
        
        // ⭐ NAJPIERW KLUCZ - CZEKAJ NA NIEGO:
        await this._ensureSessionKey();
        this._updateSessionStatus('ready');
        
        // ⭐ POTEM WIADOMOŚCI:
        await this._loadMessages(data.session.token);
        
        console.log("✅ Session initialized:", data.session.token);
      } else {
        this._showNotification(data.message || 'Session error', 'error');
      }
    } catch (error) {
      console.error("Session init error:", error);
      this._showNotification('Connection error', 'error');
    }
  }

  async _selectSession(session) {
    this.currentSession = session;
    await this._loadMessages(session.token);
    
    const friend = this.friends.find(f => f.user_id === session.other_user.user_id);
    if (friend) {
      await this._selectFriend(friend);
    }
  }

  // === ZOPTYMALIZOWANE POBIERANIE KLUCZA SESJI ===
  async _getSessionKeyOptimized(sessionToken) {
    // Cache check
    const cacheKey = `session_key_${sessionToken}`;
    if (this.apiCache.has(cacheKey)) {
      const cached = this.apiCache.get(cacheKey);
      if (Date.now() - cached.timestamp < 300000) { // 5 min cache
        return cached.key;
      }
    }
    
    // Get from crypto manager
    const sessionKeyBase64 = window.cryptoManager.getSessionKey(sessionToken);
    if (sessionKeyBase64) {
      try {
        const sessionKey = await window.cryptoManager.importSessionKey(sessionKeyBase64);
        
        // Cache result
        this.apiCache.set(cacheKey, {
          key: sessionKey,
          timestamp: Date.now()
        });
        
        return sessionKey;
      } catch (error) {
        console.error("Session key import error:", error);
        return null;
      }
    }
