/**
 * chat.js - Complete Chat Manager with Socket.IO Auto-join Fix
 * Fixed version - ensuring all code is included
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
    
    // Optimization properties
    this.keyExchangePromises = new Map();
    this.apiCache = new Map();
    this.messageProcessingQueue = [];
    
    // UI elements
    this.elements = {};
    
    // Initialize all components
    this._initDatabase();
    this._initDOM();
    this._initSocket();
    this._initEvents();
    this._initClearButton();
    this._loadInitialData();
    
    console.log("✅ ChatManager initialized:", this.user.username);
  }

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

  async _initSocket() {
    try {
      const config = await this._getSocketConfig();
      
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
    
    if (this.apiCache.has(cacheKey)) {
      const cached = this.apiCache.get(cacheKey);
      if (Date.now() - cached.timestamp < 600000) {
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
    
    this.apiCache.set(cacheKey, {
      config: defaultConfig,
      timestamp: Date.now()
    });
    
    return defaultConfig;
  }

  _setupSocketEvents() {
    // 🚀 FIXED: Connect handler with auto-rejoin
    this.socket.on('connect', () => {
      console.log("✅ Socket.IO connected");
      this.socket.emit('register_user', { user_id: this.user.id });
      
      // Auto-rejoin current session if exists
      if (this.currentSession?.token) {
        console.log('🔄 Rejoining session room after reconnect...');
        this._joinSessionRoom(this.currentSession.token);
      }
    });

    this.socket.on('disconnect', (reason) => {
      console.log(`🔌 Socket.IO disconnected: ${reason}`);
    });

    // 🚀 NEW: joined_session event handler
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
      this._enablePollingFallback();
    });
  }

  // 🚀 NEW: Auto-join session room function
  async _joinSessionRoom(sessionToken) {
    if (!this.socket || !this.socket.connected) {
      console.warn('Socket not connected, cannot join room');
      return false;
    }
    
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        console.error('❌ Join session timeout');
        resolve(false);
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
          resolve(false);
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

  async _handleNewMessage(data) {
    console.log("📨 Real-time message received:", data.type);
    console.log("🔍 Full message data:", data);
  
    // 🚀 BULLETPROOF ECHO PREVENTION - Multiple checks
    const senderId = data.message.sender_id;
    const currentUserId = this.user.id;
  
    // Convert both to strings for reliable comparison
    const senderIdStr = String(senderId);
    const currentUserIdStr = String(currentUserId);
  
    console.log("🔍 DETAILED Echo check:", {
      senderId: senderId,
      senderIdType: typeof senderId,
      currentUserId: currentUserId,
      currentUserIdType: typeof currentUserId,
      senderIdStr: senderIdStr,
      currentUserIdStr: currentUserIdStr,
      strictEqual: senderId === currentUserId,
      looseEqual: senderId == currentUserId,
      stringEqual: senderIdStr === currentUserIdStr,
      parseIntEqual: parseInt(senderId) === parseInt(currentUserId)
    });
  
  // 🚫 MULTI-LAYER ECHO PREVENTION
  if (senderIdStr === currentUserIdStr || 
      senderId === currentUserId ||
      senderId == currentUserId ||
      parseInt(senderId) === parseInt(currentUserId)) {
    console.log("🚫 ECHO BLOCKED: Own message detected - IGNORING COMPLETELY");
    console.log("🛑 STOPPING PROCESSING - This is sender's own message");
    return; // CRITICAL: Stop processing entirely
  }
  
  console.log("✅ Message from different user - proceeding with processing...");
  console.log("👤 Sender:", senderId, "| Current user:", currentUserId);
  
  // Additional session validation
  if (!this.currentSession) {
    console.warn("⚠️ No current session - storing message for later");
  }
  
  // Process message through unified pipeline
  try {
    await this._processMessage(data.session_token, data.message, 'realtime');
    console.log("✅ Message processed successfully");
  } catch (error) {
    console.error("❌ Error processing message:", error);
  }
  
  // Update UI if current session
  if (data.session_token === this.currentSession?.token) {
    console.log("📱 Updating current chat UI");
    this._refreshCurrentChat();
  } else {
    console.log("📬 Message for different session - updating unread count");
    this._updateUnreadCount(data.session_token);
  }
  
  // Play notification sound (only for messages from others)
  this._playNotificationSound();
  console.log("🔔 Notification played for incoming message");
}

  async _processMessage(sessionToken, message, source = 'unknown') {
    try {
      console.log(`📨 Processing ${source} message for session: ${sessionToken.slice(0, 8)}`);
      
      const messageKey = `${sessionToken}-${message.id || message.timestamp}`;
      if (this.messageProcessingQueue.includes(messageKey)) {
        console.log("⚠️ Message already being processed, skipping");
        return;
      }
      this.messageProcessingQueue.push(messageKey);
      
      let processedMessage = { ...message };
      
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
            processedMessage.content = '[Decryption failed: ' + decryptError.message + ']';
          }
        } else {
          console.log("⚠️ No session key available");
          processedMessage.content = '[Encrypted - key not available]';
        }
      } else {
        console.log("📝 Message is plain text, no decryption needed");
      }
      
      await this._storeMessage(sessionToken, processedMessage);
      
      const queueIndex = this.messageProcessingQueue.indexOf(messageKey);
      if (queueIndex > -1) {
        this.messageProcessingQueue.splice(queueIndex, 1);
      }
      
    } catch (error) {
      console.error("❌ Message processing error:", error);
      const errorMessage = { ...message, content: '[Processing failed: ' + error.message + ']' };
      await this._storeMessage(sessionToken, errorMessage);
    }
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

  _enablePollingFallback() {
    if (this.pollingInterval) return;
    
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
    }, 3000);
  }

  _initEvents() {
    if (!this.elements.sendButton || !this.elements.messageInput) return;
    
    this.elements.sendButton.addEventListener('click', () => this.sendMessage());
    
    this.elements.messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });
    
    this.elements.addFriendBtn?.addEventListener('click', () => {
      this._showAddFriendModal();
    });
    
    this.elements.logoutBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      this.logout();
    });
    
    this.elements.requestBadge?.parentElement?.addEventListener('click', () => {
      this._showFriendRequestsModal();
    });
    
    this._initModalEvents();
    
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
    const sendRequestBtn = document.getElementById('send-friend-request-btn');
    sendRequestBtn?.addEventListener('click', () => this._sendFriendRequest());
    
    document.querySelectorAll('.modal .close, .modal-close').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.target.closest('.modal').style.display = 'none';
      });
    });
    
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal')) {
        e.target.style.display = 'none';
      }
    });
  }

  async _loadInitialData() {
    try {
      await Promise.all([
        this._loadFriends(),
        this._loadSessions(),
        this._loadPendingRequests()
      ]);
      
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

  async _selectFriend(friend) {
    document.querySelectorAll('.friend-item').forEach(item => {
      item.classList.remove('active');
    });
    
    const friendElement = document.querySelector(`[data-user-id="${friend.user_id}"]`);
    friendElement?.classList.add('active');
    
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
      
      this._initClearButton();
    }
    
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

  // 🚀 FIXED: _initSession with auto-join
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
        
        // 🔥 CRITICAL FIX: AUTO-JOIN SOCKET.IO ROOM
        if (this.socket && this.socket.connected) {
          await this._joinSessionRoom(data.session.token);
        }
        
        await this._ensureSessionKey();
        this._updateSessionStatus('ready');
        
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

  async _getSessionKeyOptimized(sessionToken) {
    const cacheKey = `session_key_${sessionToken}`;
    if (this.apiCache.has(cacheKey)) {
      const cached = this.apiCache.get(cacheKey);
      if (Date.now() - cached.timestamp < 300000) {
        return cached.key;
      }
    }
    
    const sessionKeyBase64 = window.cryptoManager.getSessionKey(sessionToken);
    if (sessionKeyBase64) {
      try {
        const sessionKey = await window.cryptoManager.importSessionKey(sessionKeyBase64);
        
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

  async _ensureSessionKey() {
    if (!this.currentSession) {
      throw new Error('No current session');
    }

    const sessionToken = this.currentSession.token;

    if (await this._getSessionKeyOptimized(sessionToken)) {
      console.log("✅ Session key already exists locally");
      return;
    }

    await this._performKeyExchange(sessionToken);
  }
  
  async _performKeyExchange(sessionToken) {
    try {
      console.log("🔍 Checking if key already exists before generating new...");
      const response = await fetch(`/api/session/${sessionToken}/key`);
      if (response.ok) {
        const data = await response.json();
        if (data.encrypted_key) {
          console.log("🔑 Key already exists on server, using it instead of generating new");
          
          const decryptedKeyBase64 = await window.cryptoManager.decryptSessionKey(data.encrypted_key);
          
          window.cryptoManager.storeSessionKey(sessionToken, decryptedKeyBase64);
          console.log("✅ Existing server key decrypted and stored locally");
          return;
        }
      }
    } catch (e) {
      console.log("⚠️ No existing key found, will generate new");
    }

    console.log("🔑 Generating NEW session key...");
    
    try {
      const sessionKey = await window.cryptoManager.generateSessionKey();
      const sessionKeyBase64 = await window.cryptoManager.exportSessionKey(sessionKey);
      
      window.cryptoManager.storeSessionKey(sessionToken, sessionKeyBase64);
      
      console.log("🔍 Current user:", this.user.id, this.user.username);
      console.log("🔍 Other user:", this.currentSession.other_user.user_id, this.currentSession.other_user.username);  
      console.log("🔍 Encrypting session key FOR:", this.currentSession.other_user.user_id);
      
      const publicKey = await this._getRecipientPublicKey(this.currentSession.other_user.user_id);
      
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
      
      console.log("✅ New session key generated and sent to server");
      
      this.apiCache.delete(`session_key_${sessionToken}`);
      
    } catch (error) {
      window.cryptoManager.removeSessionKey(sessionToken);
      throw new Error(`Session key setup failed: ${error.message}`);
    }
  }

  async _getRecipientPublicKey(userId) {
    const cacheKey = `public_key_${userId}`;
    
    if (this.apiCache.has(cacheKey)) {
      const cached = this.apiCache.get(cacheKey);
      if (Date.now() - cached.timestamp < 3600000) {
        return cached.key;
      }
    }
    
    const response = await fetch(`/api/user/${userId}/public_key`);
    if (!response.ok) {
      throw new Error(`Failed to get public key: ${response.status}`);
    }
    
    const keyData = await response.json();
    const publicKey = await window.cryptoManager.importPublicKeyFromPEM(keyData.public_key);
    
    this.apiCache.set(cacheKey, {
      key: publicKey,
      timestamp: Date.now()
    });
    
    return publicKey;
  }

  async _loadMessages(sessionToken) {
    if (!this.elements.messagesContainer) return;
    
    this.elements.messagesContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-muted);">Loading messages...</div>';
    
    try {
      console.log(`📥 Loading messages for session: ${sessionToken.slice(0, 8)}...`);
      
      const localMessages = this.messages.get(sessionToken) || [];
      if (localMessages.length > 0) {
        console.log(`📱 Found ${localMessages.length} cached messages`);
        this._displayMessages(localMessages);
        return;
      }
      
      const response = await fetch(`/api/messages/${sessionToken}`);
      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        console.log(`📥 Processing ${data.messages.length} messages from server`);
        
        for (const message of data.messages) {
          await this._processMessage(sessionToken, message, 'import');
        }
        
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

  async sendMessage() {
    const content = this.elements.messageInput?.value.trim();
    if (!content || !this.currentSession) return;
    
    console.log('🚀 Sending message to session:', this.currentSession.token);
    
    this.elements.messageInput.disabled = true;
    this.elements.sendButton.disabled = true;
    
    try {
      await this._ensureSessionKey();
      
      const sessionKey = await this._getSessionKeyOptimized(this.currentSession.token);
      if (!sessionKey) {
        throw new Error('No session key available');
      }
      
      const encrypted = await window.cryptoManager.encryptMessage(sessionKey, content);
      
      console.log('🔐 Message encrypted, sending to server...');
      
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
        this.elements.messageInput.value = '';
        
        const newMessage = {
          id: data.message.id,
          sender_id: parseInt(this.user.id),
          content: content,
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
      this.elements.messageInput.disabled = false;
      this.elements.sendButton.disabled = false;
      this.elements.messageInput.focus();
    }
  }

  async _storeMessage(sessionToken, message) {
    if (!this.db) return;
    
    try {
      if (!this.messages.has(sessionToken)) {
        this.messages.set(sessionToken, []);
      }
      
      const messages = this.messages.get(sessionToken);
      
      const messageKey = `${message.id}-${message.timestamp}`;
      const exists = messages.find(m => 
        m.id === message.id || 
        `${m.id}-${m.timestamp}` === messageKey ||
        (Math.abs(new Date(m.timestamp) - new Date(message.timestamp)) < 1000 && m.content === message.content)
      );
      
      if (!exists) {
        messages.push(message);
        
        this._storeInIndexedDB(message, sessionToken).catch(error => {
          console.error("IndexedDB storage error:", error);
        });
        
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

  async refreshMessages() {
    if (!this.currentSession) return;
    
    try {
      this.messages.delete(this.currentSession.token);
      
      this.apiCache.delete(`session_key_${this.currentSession.token}`);
      
      if (this.elements.messagesContainer) {
        this.elements.messagesContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-muted);">Refreshing messages...</div>';
      }
      
      await this._loadMessages(this.currentSession.token);
      
      this._showNotification('Messages refreshed', 'success', 2000);
      
    } catch (error) {
      console.error("Refresh messages error:", error);
      this._showNotification('Failed to refresh messages', 'error');
    }
  }

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

  async clearConversation(sessionToken = null) {
    const token = sessionToken || this.currentSession?.token;
    if (!token) return;
    
    const currentFriend = this.currentSession?.other_user?.username || 'this contact';
    
    if (!confirm(`Delete all messages with ${currentFriend}?\n\nThis will permanently delete the conversation from both devices and cannot be undone.`)) {
      return;
    }
    
    const clearBtn = document.getElementById('clear-conversation-btn');
    const originalText = clearBtn?.innerHTML;
    if (clearBtn) {
      clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
      clearBtn.disabled = true;
    }
    
    try {
      const response = await fetch(`/api/messages/${token}/clear`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Server error: ${response.status}`);
      }
      
      const result = await response.json();
      
      this.messages.delete(token);
      
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
      
      this.apiCache.delete(`session_key_${token}`);
      
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
      if (clearBtn) {
        clearBtn.innerHTML = originalText || '<i class="fas fa-trash"></i> Clear';
        clearBtn.disabled = false;
      }
    }
  }

  async logout() {
    try {
      console.log('🚪 Logout process...');
      
      // 🚀 FIXED: Leave current session room
      if (this.currentSession?.token && this.socket && this.socket.connected) {
        this.socket.emit('leave_session', { 
          session_token: this.currentSession.token 
        });
      }
      
      this.apiCache.clear();
      this.keyExchangePromises.clear();
      this.messageProcessingQueue = [];
      console.log('✅ All caches cleared');
      
      if (this.sessions?.length > 0) {
        const closePromises = this.sessions.map(session => 
          Promise.race([
            fetch(`/api/session/${session.token}/close`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' }
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000))
          ]).catch(() => {})
        );
        
        await Promise.allSettled(closePromises);
        console.log(`✅ Closed ${this.sessions.length} sessions`);
      }
      
      if (window.cryptoManager) {
        window.cryptoManager.clearAllKeys();
        console.log('✅ Crypto keys cleared');
      }
      
      if (this.socket) {
        this.socket.disconnect();
        console.log('✅ Socket disconnected');
      }
      
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
        this.pollingInterval = null;
      }
      
      sessionStorage.clear();
      console.log('✅ Session storage cleared');
      
      Object.assign(this, {
        currentSession: null,
        friends: [],
        sessions: [],
        messages: new Map()
      });
      
      if (this.db) {
        this.db.close();
        console.log('✅ Database connection closed');
      }
      
      window.location.href = '/logout';
      
    } catch (error) {
      console.error("Logout error:", error);
      window.location.href = '/logout';
    }
  }

  destroy() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
    
    this.apiCache.clear();
    this.keyExchangePromises.clear();
    this.messageProcessingQueue = [];
    
    if (this.socket) {
      this.socket.disconnect();
    }
    
    if (this.db) {
      this.db.close();
    }
    
    console.log("🧹 ChatManager destroyed");
  }

  // Utility functions
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
      audio.play().catch(() => {});
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

  debugInfo() {
    console.log("=== CHAT MANAGER DEBUG INFO ===");
    console.log("Performance Stats:", this.getPerformanceStats());
    console.log("Current Session:", this.currentSession?.token?.slice(0, 8) + "...");
    console.log("API Cache Keys:", Array.from(this.apiCache.keys()));
    console.log("Message Cache:", Array.from(this.messages.keys()).map(k => k.slice(0, 8) + "..."));
    console.log("Active Key Exchanges:", Array.from(this.keyExchangePromises.keys()).map(k => k.slice(0, 8) + "..."));
  }
}

// Global error handler
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  
  if (event.reason?.message?.includes('session key') || 
      event.reason?.message?.includes('crypto') ||
      window.location.href.includes('logout')) {
    return;
  }
  
  if (window.chatManager) {
    window.chatManager._showNotification('⚠️ Connection error occurred', 'warning', 3000);
  }
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey && e.key === 'r') || e.key === 'F5') {
    if (window.chatManager && window.chatManager.currentSession) {
      e.preventDefault();
      window.chatManager.refreshMessages();
    }
  }
  
  if (e.ctrlKey && e.shiftKey && e.key === 'Delete') {
    if (window.chatManager && window.chatManager.currentSession) {
      e.preventDefault();
      window.chatManager.clearConversation();
    }
  }
  
  if (e.ctrlKey && e.shiftKey && e.key === 'D') {
    if (window.chatManager) {
      e.preventDefault();
      window.chatManager.debugInfo();
    }
  }
});

// Performance monitoring
if (typeof PerformanceObserver !== 'undefined') {
  const observer = new PerformanceObserver((list) => {
    const entries = list.getEntries();
    entries.forEach((entry) => {
      if (entry.duration > 100) {
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

// Validation check
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
  
  if (chatManager.socket) {
    console.log('✅ Socket.IO initialized');
    console.log('📡 Socket connected:', chatManager.socket.connected);
  } else {
    console.warn('⚠️ Socket.IO not initialized');
  }
}, 1000);
