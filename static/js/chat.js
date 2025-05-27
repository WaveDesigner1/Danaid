/**
 * chat.js - ZOPTYMALIZOWANY Chat Manager z poprawkami deszyfrowania
 * Usunięto duplikacje, dodano cache, debouncing, unified message processing
 * Poprawiono funkcje _needsDecryption, _processMessage, dodano _debugDecryption
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
    
    // === NOWE PROPERTIES DLA OPTYMALIZACJI ===
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
    this.socket.on('connect', () => {
      console.log("✅ Socket.IO connected");
      this.socket.emit('register_user', { user_id: this.user.id });
    });

    this.socket.on('disconnect', (reason) => {
      console.log(`🔌 Socket.IO disconnected: ${reason}`);
      // Auto-reconnect handled by Socket.IO
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
    
    return null;
  }

  // === ZOPTYMALIZOWANA WYMIANA KLUCZY Z DEBOUNCING ===
  async _ensureSessionKey() {
    if (!this.currentSession) {
      throw new Error('No current session');
    }
  
    const sessionToken = this.currentSession.token;
  
    // Check if we already have session key locally
    if (await this._getSessionKeyOptimized(sessionToken)) {
      console.log("✅ Session key already exists");
      return;
    }
  
  // ⭐ DODAJ TO NA POCZĄTKU:
  // Try to get existing key from server FIRST
    try {
      console.log("🔍 Checking server for existing key...");
      const response = await fetch(`/api/session/${sessionToken}/key`);
      if (response.ok) {
        const data = await response.json();
        if (data.encrypted_key) {
        console.log("🔑 Found encrypted key on server, decrypting...");
        
        // Decrypt the session key with our private key
        const decryptedKeyBase64 = await window.cryptoManager.decryptSessionKey(data.encrypted_key);
        
        // Store locally
        window.cryptoManager.storeSessionKey(sessionToken, decryptedKeyBase64);
        console.log("✅ Server key decrypted and stored locally");
        return;
      }
    }
  } catch (e) {
    console.log("⚠️ No existing key on server or decrypt failed, will generate new");
  }
  
  // Generate new key only if none exists on server
  await this._performKeyExchange(sessionToken);
}
  
  async _performKeyExchange(sessionToken) {
    console.log("🔑 Generating NEW session key...");
    
    try {
      const sessionKey = await window.cryptoManager.generateSessionKey();
      const sessionKeyBase64 = await window.cryptoManager.exportSessionKey(sessionKey);
      
      // Store locally first (CRITICAL)
      window.cryptoManager.storeSessionKey(sessionToken, sessionKeyBase64);
      
      // Get recipient's public key (with cache)
      const publicKey = await this._getRecipientPublicKey(this.currentSession.other_user.user_id);
      
      // Encrypt and send session key
      const encryptedSessionKey = await window.cryptoManager.encryptSessionKey(publicKey, sessionKey);
      
      const response = await fetch(`/api/session/${sessionToken}/exchange_key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_key: encryptedSessionKey })
      });
      
      if (!response.ok) {
        window.cryptoManager.removeSessionKey(sessionToken);
        throw new Error(`Key exchange failed: ${response.status}`);
      }
      
      // Clear cache for this session key
      this.apiCache.delete(`session_key_${sessionToken}`);
      
    } catch (error) {
      window.cryptoManager.removeSessionKey(sessionToken);
      throw new Error(`Session key setup failed: ${error.message}`);
    }
  }

  // === CACHE DLA KLUCZY PUBLICZNYCH ===
  async _getRecipientPublicKey(userId) {
    const cacheKey = `public_key_${userId}`;
    
    if (this.apiCache.has(cacheKey)) {
      const cached = this.apiCache.get(cacheKey);
      if (Date.now() - cached.timestamp < 3600000) { // 1 hour cache
        return cached.key;
      }
    }
    
    const response = await fetch(`/api/user/${userId}/public_key`);
    if (!response.ok) {
      throw new Error(`Failed to get public key: ${response.status}`);
    }
    
    const keyData = await response.json();
    const publicKey = await window.cryptoManager.importPublicKeyFromPEM(keyData.public_key);
    
    // Cache result
    this.apiCache.set(cacheKey, {
      key: publicKey,
      timestamp: Date.now()
    });
    
    return publicKey;
  }

  // === ZOPTYMALIZOWANE ŁADOWANIE WIADOMOŚCI ===
  async _loadMessages(sessionToken) {
    if (!this.elements.messagesContainer) return;
    
    this.elements.messagesContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-muted);">Loading messages...</div>';
    
    try {
      console.log(`📥 Loading messages for session: ${sessionToken.slice(0, 8)}...`);
      
      // Check local cache first
      const localMessages = this.messages.get(sessionToken) || [];
      if (localMessages.length > 0) {
        console.log(`📱 Found ${localMessages.length} cached messages`);
        this._displayMessages(localMessages);
        return;
      }
      
      // Fetch from server
      const response = await fetch(`/api/messages/${sessionToken}`);
      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        console.log(`📥 Processing ${data.messages.length} messages from server`);
        
        // Process all messages through unified pipeline
        for (const message of data.messages) {
          await this._processMessage(sessionToken, message, 'import');
        }
        
        // Display processed messages
        const processedMessages = this.messages.get(sessionToken) || [];
        this._displayMessages(processedMessages);
      }
      
    } catch (error) {
      console.error("Message loading error:", error);
      this._showNotification('Failed to load messages', 'error');
      
      if (this.elements.messagesContainer) {
        this.elements.messagesContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--danger);">Failed to load messages</div>';
      }
    }
  }

  _displayMessages(messages) {
    if (!this.elements.messagesContainer) return;
    
    this.elements.messagesContainer.innerHTML = '';
    
    // Sort and display
    const sortedMessages = [...messages].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    
    sortedMessages.forEach(message => {
      this._addMessageToUI(message);
    });
    
    this._scrollToBottom();
  }

  _refreshCurrentChat() {
    if (this.currentSession) {
      const messages = this.messages.get(this.currentSession.token) || [];
      this._displayMessages(messages);
    }
  }

  _addMessageToUI(message) {
    if (!this.elements.messagesContainer) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${message.sender_id == this.user.id || message.is_mine ? 'sent' : 'received'}`;
    
    messageDiv.innerHTML = `
      <div class="message-content">${message.content}</div>
      <div class="message-info">
        <span class="message-time">${this._formatTime(message.timestamp)}</span>
      </div>
    `;
    
    this.elements.messagesContainer.appendChild(messageDiv);
    this._scrollToBottom();
  }

  // === ZOPTYMALIZOWANE WYSYŁANIE WIADOMOŚCI ===
  async sendMessage() {
    const content = this.elements.messageInput?.value.trim();
    if (!content || !this.currentSession) return;
    
    console.log('🚀 Sending message to session:', this.currentSession.token);
    
    // Disable input
    this.elements.messageInput.disabled = true;
    this.elements.sendButton.disabled = true;
    
    try {
      // Ensure session key exists
      await this._ensureSessionKey();
      
      // Get session key
      const sessionKey = await this._getSessionKeyOptimized(this.currentSession.token);
      if (!sessionKey) {
        throw new Error('No session key available');
      }
      
      // Encrypt message
      const encrypted = await window.cryptoManager.encryptMessage(sessionKey, content);
      
      console.log('🔐 Message encrypted, sending to server...');
      
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
      
      console.log('📡 Server response status:', response.status);
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ Server error:', response.status, errorText);
        throw new Error(`Server error: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('✅ Server response:', data);
      
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

  // === ZOPTYMALIZOWANE STORAGE ===
  async _storeMessage(sessionToken, message) {
    if (!this.db) return;
    
    try {
      // Add to memory cache
      if (!this.messages.has(sessionToken)) {
        this.messages.set(sessionToken, []);
      }
      
      const messages = this.messages.get(sessionToken);
      
      // Check for duplicates (optimized)
      const messageKey = `${message.id}-${message.timestamp}`;
      const exists = messages.find(m => 
        m.id === message.id || 
        `${m.id}-${m.timestamp}` === messageKey ||
        (Math.abs(new Date(m.timestamp) - new Date(message.timestamp)) < 1000 && m.content === message.content)
      );
      
      if (!exists) {
        messages.push(message);
        
        // Store in IndexedDB (async, non-blocking)
        this._storeInIndexedDB(message, sessionToken).catch(error => {
          console.error("IndexedDB storage error:", error);
        });
        
        // Limit memory cache size (keep last 100 messages per session)
        if (messages.length > 100) {
          messages.splice(0, messages.length - 100);
        }
      }
    } catch (error) {
      console.error("Message storage error:", error);
    }
  }

  async _storeInIndexedDB(message, sessionToken) {
    const tx = this.db.transaction(['messages'], 'readwrite');
    const store = tx.objectStore('messages');
    
    await new Promise((resolve, reject) => {
      const request = store.add({ ...message, sessionToken });
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  // === DODANA FUNKCJA: FORCE REFRESH MESSAGES ===
  async refreshMessages() {
    if (!this.currentSession) return;
    
    try {
      // Clear current messages from memory cache
      this.messages.delete(this.currentSession.token);
      
      // Clear API cache for this session
      this.apiCache.delete(`session_key_${this.currentSession.token}`);
      
      // Clear UI
      if (this.elements.messagesContainer) {
        this.elements.messagesContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-muted);">Refreshing messages...</div>';
      }
      
      // Reload from server
      await this._loadMessages(this.currentSession.token);
      
      this._showNotification('Messages refreshed', 'success', 2000);
      
    } catch (error) {
      console.error("Refresh messages error:", error);
      this._showNotification('Failed to refresh messages', 'error');
    }
  }

  // === SPRAWDZENIE REAL-TIME STATUS ===
  checkRealTimeStatus() {
    if (this.socket && this.socket.connected) {
      return {
        status: 'real-time',
        transport: this.socket.io.engine.transport.name,
        connected: true
      };
    } else if (this.pollingInterval) {
      return {
        status: 'polling',
        transport: 'fallback',
        connected: true
      };
    } else {
      return {
        status: 'disconnected',
        transport: 'none',
        connected: false
      };
    }
  }

  // === FRIEND MANAGEMENT ===
  _showAddFriendModal() {
    const modal = document.getElementById('add-friend-modal');
    if (modal) modal.style.display = 'block';
  }

  async _sendFriendRequest() {
    const input = document.getElementById('friend-username-input');
    const username = input?.value.trim();
    
    if (!username) {
      this._showNotification('Enter username', 'warning');
      return;
    }
    
    try {
      const response = await fetch('/api/friend_requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      
      const data = await response.json();
      
      if (data.status === 'success') {
        this._showNotification('Friend request sent!', 'success');
        input.value = '';
        document.getElementById('add-friend-modal').style.display = 'none';
      } else {
        this._showNotification(data.message || 'Request failed', 'error');
      }
    } catch (error) {
      this._showNotification('Connection error', 'error');
    }
  }

  _showFriendRequestsModal() {
    // Create or show friend requests modal
    let modal = document.getElementById('friend-requests-modal');
    if (!modal) {
      modal = this._createFriendRequestsModal();
      document.body.appendChild(modal);
    }
    
    this._updateFriendRequestsModal(modal);
    modal.style.display = 'block';
  }

  _createFriendRequestsModal() {
    const modal = document.createElement('div');
    modal.id = 'friend-requests-modal';
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h3>Friend Requests</h3>
          <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
          <div id="friend-requests-list"></div>
        </div>
      </div>
    `;
    
    // Add event listeners
    modal.querySelector('.modal-close').addEventListener('click', () => {
      modal.style.display = 'none';
    });
    
    return modal;
  }

  async _updateFriendRequestsModal(modal) {
    const listContainer = modal.querySelector('#friend-requests-list');
    
    try {
      const response = await fetch('/api/friend_requests/pending');
      const data = await response.json();
      
      if (data.status === 'success' && data.requests.length > 0) {
        listContainer.innerHTML = data.requests.map(request => `
          <div class="friend-request-item" style="display: flex; justify-content: space-between; align-items: center; padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.1);">
            <div>
              <strong>${request.username}</strong>
              <small style="display: block; color: var(--text-secondary);">${this._formatTime(request.created_at)}</small>
            </div>
            <div>
              <button class="btn btn-success btn-sm" onclick="chatManager.acceptFriendRequest(${request.id})">Accept</button>
              <button class="btn btn-danger btn-sm" onclick="chatManager.rejectFriendRequest(${request.id})" style="margin-left: 8px;">Reject</button>
            </div>
          </div>
        `).join('');
      } else {
        listContainer.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">No pending requests</p>';
      }
    } catch (error) {
      listContainer.innerHTML = '<p style="color: var(--danger);">Error loading requests</p>';
    }
  }

  async acceptFriendRequest(requestId) {
    try {
      const response = await fetch(`/api/friend_requests/${requestId}/accept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      const data = await response.json();
      
      if (data.status === 'success') {
        this._showNotification('Friend request accepted!', 'success');
        await this._loadFriends();
        this._updateFriendRequestsModal(document.getElementById('friend-requests-modal'));
        this._loadPendingRequests();
      } else {
        this._showNotification(data.message || 'Accept failed', 'error');
      }
    } catch (error) {
      this._showNotification('Connection error', 'error');
    }
  }

  async rejectFriendRequest(requestId) {
    try {
      const response = await fetch(`/api/friend_requests/${requestId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      const data = await response.json();
      
      if (data.status === 'success') {
        this._showNotification('Friend request rejected', 'info');
        this._updateFriendRequestsModal(document.getElementById('friend-requests-modal'));
        this._loadPendingRequests();
      } else {
        this._showNotification(data.message || 'Reject failed', 'error');
      }
    } catch (error) {
      this._showNotification('Connection error', 'error');
    }
  }

  // === CLEAR CONVERSATION ===
  async clearConversation(sessionToken = null) {
    const token = sessionToken || this.currentSession?.token;
    if (!token) return;
    
    // Get current friend name for better UX
    const currentFriend = this.currentSession?.other_user?.username || 'this contact';
    
    if (!confirm(`Delete all messages with ${currentFriend}?\n\nThis will permanently delete the conversation from both devices and cannot be undone.`)) {
      return;
    }
    
    // Show loading state
    const clearBtn = document.getElementById('clear-conversation-btn');
    const originalText = clearBtn?.innerHTML;
    if (clearBtn) {
      clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
      clearBtn.disabled = true;
    }
    
    try {
      // 1. Clear from server
      const response = await fetch(`/api/messages/${token}/clear`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Server error: ${response.status}`);
      }
      
      const result = await response.json();
      
      // 2. Clear from local storage
      this.messages.delete(token);
      
      // 3. Clear from IndexedDB
      if (this.db) {
        const tx = this.db.transaction(['messages'], 'readwrite');
        const store = tx.objectStore('messages');
        
        await new Promise((resolve, reject) => {
          const request = store.openCursor();
          request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
              if (cursor.value.sessionToken === token) {
                cursor.delete();
              }
              cursor.continue();
            } else {
              resolve();
            }
          };
          request.onerror = () => reject(request.error);
        });
      }
      
      // 4. Clear API cache for this session
      this.apiCache.delete(`session_key_${token}`);
      
      // 5. Clear UI if it's current session
      if (token === this.currentSession?.token && this.elements.messagesContainer) {
        this.elements.messagesContainer.innerHTML = `
          <div style="text-align: center; padding: 40px; color: var(--text-muted);">
            <i class="fas fa-comments" style="font-size: 48px; margin-bottom: 16px; opacity: 0.3;"></i>
            <p>Conversation cleared</p>
            <p style="font-size: 0.9em;">Start a new conversation by sending a message</p>
          </div>
        `;
      }
      
      this._showNotification(`✅ Deleted ${result.deleted_count || 0} messages`, 'success');
      
    } catch (error) {
      console.error("Clear conversation error:", error);
      this._showNotification(`❌ Failed to clear conversation: ${error.message}`, 'error');
    } finally {
      // Restore button state
      if (clearBtn) {
        clearBtn.innerHTML = originalText || '<i class="fas fa-trash"></i> Clear';
        clearBtn.disabled = false;
      }
    }
  }

  // === LOGOUT ===
  async logout() {
    try {
      console.log('🚪 Optimized logout process...');
      
      // Clear all caches and processing queues
      this.apiCache.clear();
      this.keyExchangePromises.clear();
      this.messageProcessingQueue = [];
      console.log('✅ All caches cleared');
      
      // Close sessions (with timeout)
      if (this.sessions?.length > 0) {
        const closePromises = this.sessions.map(session => 
          Promise.race([
            fetch(`/api/session/${session.token}/close`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' }
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000))
          ]).catch(() => {}) // Non-critical
        );
        
        await Promise.allSettled(closePromises);
        console.log(`✅ Closed ${this.sessions.length} sessions`);
      }
      
      // Clear crypto + disconnect socket
      if (window.cryptoManager) {
        window.cryptoManager.clearAllKeys();
        console.log('✅ Crypto keys cleared');
      }
      
      if (this.socket) {
        this.socket.disconnect();
        console.log('✅ Socket disconnected');
      }
      
      // Clear polling interval
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
        this.pollingInterval = null;
      }
      
      // Clear sessionStorage only (preserve messages in IndexedDB for next login)
      sessionStorage.clear();
      console.log('✅ Session storage cleared');
      
      // Clear memory
      Object.assign(this, {
        currentSession: null,
        friends: [],
        sessions: [],
        messages: new Map()
      });
      
      // Close database connection
      if (this.db) {
        this.db.close();
        console.log('✅ Database connection closed');
      }
      
      // Redirect
      window.location.href = '/logout';
      
    } catch (error) {
      console.error("Logout error:", error);
      // Force redirect even on error
      window.location.href = '/logout';
    }
  }

  // === CLEANUP ON DESTROY ===
  destroy() {
    // Clear polling interval
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
    
    // Clear all caches
    this.apiCache.clear();
    this.keyExchangePromises.clear();
    this.messageProcessingQueue = [];
    
    // Disconnect socket
    if (this.socket) {
      this.socket.disconnect();
    }
    
    // Close database
    if (this.db) {
      this.db.close();
    }
    
    console.log("🧹 Optimized ChatManager destroyed");
  }

  // === UTILITIES ===
  _updateRequestBadge(count) {
    if (!this.elements.requestBadge) return;
    
    if (count > 0) {
      this.elements.requestBadge.textContent = count;
      this.elements.requestBadge.style.display = 'inline';
    } else {
      this.elements.requestBadge.style.display = 'none';
    }
  }

  _updateUnreadCount(sessionToken) {
    const session = this.sessions.find(s => s.token === sessionToken);
    if (session) {
      session.unread_count = (session.unread_count || 0) + 1;
      this._renderFriendsList();
    }
  }

  _updateUserStatus(userId, isOnline) {
    const friend = this.friends.find(f => f.user_id === userId);
    if (friend) {
      friend.is_online = isOnline;
      this._renderFriendsList();
    }
  }

  _playNotificationSound() {
    try {
      const audio = new Audio('/static/sounds/notification.mp3');
      audio.volume = 0.3;
      audio.play().catch(() => {}); // Ignore errors
    } catch (e) {}
  }

  _scrollToBottom() {
    if (this.elements.messagesContainer) {
      this.elements.messagesContainer.scrollTop = this.elements.messagesContainer.scrollHeight;
    }
  }

  _formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    
    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    if (date >= today) {
      return timeStr;
    } else if (date >= new Date(today - 86400000)) {
      return `Yesterday, ${timeStr}`;
    } else {
      return `${date.toLocaleDateString()} ${timeStr}`;
    }
  }

  _showNotification(message, type = 'info', duration = 5000) {
    // Prevent notification spam
    const existingNotifications = document.querySelectorAll('.notification');
    if (existingNotifications.length > 3) {
      existingNotifications[0].remove();
    }
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, duration);
  }

  // === PERFORMANCE MONITORING ===
  getPerformanceStats() {
    return {
      cacheSize: this.apiCache.size,
      messagesCached: Array.from(this.messages.values()).reduce((total, msgs) => total + msgs.length, 0),
      activeKeyExchanges: this.keyExchangePromises.size,
      processingQueue: this.messageProcessingQueue.length,
      realTimeStatus: this.checkRealTimeStatus(),
      memoryUsage: {
        friends: this.friends.length,
        sessions: this.sessions.length,
        messageSessions: this.messages.size
      }
    };
  }

  // === DEBUG HELPER ===
  debugInfo() {
    console.log("=== CHAT MANAGER DEBUG INFO ===");
    console.log("Performance Stats:", this.getPerformanceStats());
    console.log("Current Session:", this.currentSession?.token?.slice(0, 8) + "...");
    console.log("API Cache Keys:", Array.from(this.apiCache.keys()));
    console.log("Message Cache:", Array.from(this.messages.keys()).map(k => k.slice(0, 8) + "..."));
    console.log("Active Key Exchanges:", Array.from(this.keyExchangePromises.keys()).map(k => k.slice(0, 8) + "..."));
  }
}

// === GLOBAL ERROR HANDLER ===
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  
  // Don't show UI notifications for crypto errors during logout
  if (event.reason?.message?.includes('session key') || 
      event.reason?.message?.includes('crypto') ||
      window.location.href.includes('logout')) {
    return;
  }
  
  // Show notification for other errors
  if (window.chatManager) {
    window.chatManager._showNotification('⚠️ Connection error occurred', 'warning', 3000);
  }
});

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
