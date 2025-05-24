/**
 * chat.js - Zunifikowany Chat Manager
 * Scalenie: ChatInterface.js + SecureSessionManager.js + SocketIOHandler.js
 * Redukcja: 1400 → 800 linii kodu
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
    
    // UI elements
    this.elements = {};
    
    // Callbacks
    this.onMessageReceived = null;
    this.onFriendsUpdated = null;
    this.onSessionsUpdated = null;
    
    // Initialize
    this._initDatabase();
    this._initDOM();
    this._initSocket();
    this._initEvents();
    this._loadInitialData();
    
    console.log("✅ ChatManager initialized:", this.user.username);
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
      // Get Socket.IO config
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
    try {
      const response = await fetch('/api/websocket/config');
      if (response.ok) {
        const config = await response.json();
        if (window.location.protocol === 'https:' && config.socketUrl?.startsWith('http:')) {
          config.socketUrl = config.socketUrl.replace('http:', 'https:');
        }
        return config;
      }
    } catch (e) {
      console.warn("Using default Socket.IO config");
    }
    
    return {
      socketUrl: `${window.location.protocol}//${window.location.host}`,
      path: '/socket.io/'
    };
  }

  _setupSocketEvents() {
    this.socket.on('connect', () => {
      console.log("✅ Socket.IO connected");
      this.socket.emit('register_user', { user_id: this.user.id });
    });

    this.socket.on('disconnect', (reason) => {
      console.log(`🔌 Socket.IO disconnected: ${reason}`);
    });

    this.socket.on('message', (data) => {
      this._handleSocketMessage(data);
    });

    this.socket.on('connect_error', (error) => {
      console.error("❌ Socket.IO error:", error);
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

  _handleNewMessage(data) {
    // Avoid echo
    if (data.message.sender_id == this.user.id) return;
    
    this._storeMessage(data.session_token, data.message);
    
    if (data.session_token === this.currentSession?.token) {
      this._addMessageToUI(data.message);
    } else {
      this._updateUnreadCount(data.session_token);
    }
    
    this._playNotificationSound();
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

  async _selectFriend(friend) {
    // Update UI
    document.querySelectorAll('.friend-item').forEach(item => {
      item.classList.remove('active');
    });
    
    const friendElement = document.querySelector(`[data-user-id="${friend.user_id}"]`);
    friendElement?.classList.add('active');
    
    // Update header with status
    if (this.elements.chatHeader) {
      this.elements.chatHeader.innerHTML = `
        <h2>${friend.username}</h2>
        <span class="chat-status ${friend.is_online ? 'online' : 'offline'}">
          ${friend.is_online ? 'Online' : 'Offline'}
        </span>
        <span id="session-status" class="session-status">Connecting...</span>
      `;
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
        
        // 🔑 AUTOMATYCZNA WYMIANA KLUCZY przy kliknięciu na nick
        try {
          await this._ensureSessionKey();
          this._updateSessionStatus('ready');
        } catch (keyError) {
          console.log("Key exchange will happen on first message");
          this._updateSessionStatus('pending');
        }
        
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
      this._selectFriend(friend);
    }
  }

  // === MESSAGE HANDLING ===
  async _loadMessages(sessionToken) {
    if (!this.elements.messagesContainer) return;
    
    this.elements.messagesContainer.innerHTML = '';
    
    try {
      // Load from local storage first
      const localMessages = this.messages.get(sessionToken) || [];
      
      if (localMessages.length === 0) {
        // Fetch from server if no local messages
        const response = await fetch(`/api/messages/${sessionToken}`);
        const data = await response.json();
        
        if (data.status === 'success') {
          for (const message of data.messages) {
            if (message.content && message.iv && window.cryptoManager) {
              try {
                const sessionKey = window.cryptoManager.getSessionKey(sessionToken);
                if (sessionKey) {
                  const key = await window.cryptoManager.importSessionKey(sessionKey);
                  message.content = await window.cryptoManager.decryptMessage(key, {
                    data: message.content,
                    iv: message.iv
                  });
                }
              } catch (decryptError) {
                message.content = '[Decryption failed]';
              }
            }
            
            this._storeMessage(sessionToken, message);
          }
        }
      }
      
      // Display messages
      const messages = this.messages.get(sessionToken) || [];
      messages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      
      messages.forEach(message => {
        this._addMessageToUI(message);
      });
      
      this._scrollToBottom();
    } catch (error) {
      console.error("Message loading error:", error);
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
    
    // Disable input
    this.elements.messageInput.disabled = true;
    this.elements.sendButton.disabled = true;
    
    try {
      // Ensure session key exists
      await this._ensureSessionKey();
      
      // Get session key
      const sessionKeyBase64 = window.cryptoManager.getSessionKey(this.currentSession.token);
      if (!sessionKeyBase64) {
        throw new Error('No session key available');
      }
      
      // Encrypt message
      const sessionKey = await window.cryptoManager.importSessionKey(sessionKeyBase64);
      const encrypted = await window.cryptoManager.encryptMessage(sessionKey, content);
      
      // Send to server
      const response = await fetch('/api/message/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_token: this.currentSession.token,
          content: encrypted.data,
          iv: encrypted.iv
        })
      });
      
      const data = await response.json();
      
      if (data.status === 'success') {
        // Clear input
        this.elements.messageInput.value = '';
        
        // Add to UI optimistically
        const newMessage = {
          id: data.message.id,
          sender_id: parseInt(this.user.id),
          content: content,
          timestamp: data.message.timestamp,
          is_mine: true
        };
        
        this._addMessageToUI(newMessage);
        this._storeMessage(this.currentSession.token, newMessage);
      } else {
        this._showNotification(data.message || 'Send failed', 'error');
      }
    } catch (error) {
      console.error("Send message error:", error);
      this._showNotification('Failed to send message', 'error');
    } finally {
      // Re-enable input
      this.elements.messageInput.disabled = false;
      this.elements.sendButton.disabled = false;
      this.elements.messageInput.focus();
    }
  }

  async _ensureSessionKey() {
    if (!this.currentSession) return;
    
    const sessionToken = this.currentSession.token;
    
    // Check if we have the session key
    if (window.cryptoManager.hasSessionKey(sessionToken)) return;
    
    try {
      if (!this.currentSession.has_key) {
        // Generate new session key
        const sessionKey = await window.cryptoManager.generateSessionKey();
        const sessionKeyBase64 = await window.cryptoManager.exportSessionKey(sessionKey);
        
        // Store locally first
        window.cryptoManager.storeSessionKey(sessionToken, sessionKeyBase64);
        
        // Get recipient's public key
        const response = await fetch(`/api/user/${this.currentSession.other_user.user_id}/public_key`);
        const keyData = await response.json();
        const recipientPublicKey = await window.cryptoManager.importPublicKeyFromPEM(keyData.public_key);
        
        // Encrypt and send session key
        const encryptedSessionKey = await window.cryptoManager.encryptSessionKey(recipientPublicKey, sessionKey);
        
        const keyResponse = await fetch(`/api/session/${sessionToken}/exchange_key`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ encrypted_key: encryptedSessionKey })
        });
        
        if (!keyResponse.ok) {
          throw new Error('Failed to exchange session key');
        }
        
        console.log("✅ Session key generated and sent");
      } else {
        // Retrieve existing session key
        const response = await fetch(`/api/session/${sessionToken}/key`);
        const data = await response.json();
        
        if (data.status === 'success') {
          const sessionKeyBase64 = await window.cryptoManager.decryptSessionKey(data.encrypted_key);
          window.cryptoManager.storeSessionKey(sessionToken, sessionKeyBase64);
          
          // Acknowledge key receipt
          await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          
          console.log("✅ Session key retrieved and acknowledged");
        }
      }
    } catch (error) {
      console.error("Session key error:", error);
      throw error;
    }
  } window.cryptoManager.encryptSessionKey(recipientPublicKey, sessionKey);
        
        const keyResponse = await fetch(`/api/session/${sessionToken}/exchange_key`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ encrypted_key: encryptedSessionKey })
        });
        
        if (!keyResponse.ok) {
          throw new Error('Failed to exchange session key');
        }
        
        console.log("✅ Session key generated and sent");
      } else {
        // Retrieve existing session key
        const response = await fetch(`/api/session/${sessionToken}/key`);
        const data = await response.json();
        
        if (data.status === 'success') {
          const sessionKeyBase64 = await window.cryptoManager.decryptSessionKey(data.encrypted_key);
          window.cryptoManager.storeSessionKey(sessionToken, sessionKeyBase64);
          
          // Acknowledge key receipt
          await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          
          console.log("✅ Session key retrieved and acknowledged");
        }
      }
    } catch (error) {
      console.error("Session key error:", error);
      throw error;
    }
  }

  // === STORAGE ===
  async _storeMessage(sessionToken, message) {
    if (!this.db) return;
    
    try {
      // Add to memory
      if (!this.messages.has(sessionToken)) {
        this.messages.set(sessionToken, []);
      }
      
      const messages = this.messages.get(sessionToken);
      
      // Check for duplicates
      const exists = messages.find(m => 
        m.id === message.id || (m.timestamp === message.timestamp && m.content === message.content)
      );
      
      if (!exists) {
        messages.push(message);
        
        // Store in IndexedDB
        const tx = this.db.transaction(['messages'], 'readwrite');
        const store = tx.objectStore('messages');
        
        await new Promise((resolve, reject) => {
          const request = store.add({ ...message, sessionToken });
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        });
      }
    } catch (error) {
      console.error("Message storage error:", error);
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

  // === LOGOUT ===
  async logout() {
    try {
      console.log('🚪 Starting logout process...');
      
      // 1. Kończymy aktywne sesje
      if (this.currentSession) {
        try {
          await fetch(`/api/session/${this.currentSession.token}/close`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          console.log('✅ Current session closed');
        } catch (e) {
          console.log('Session close error (non-critical):', e);
        }
      }
      
      // 2. Clear crypto keys (CRITICAL for security)
      if (window.cryptoManager) {
        window.cryptoManager.clearAllKeys();
        console.log('✅ Crypto keys cleared');
      }
      
      // 3. Disconnect socket
      if (this.socket) {
        this.socket.disconnect();
        console.log('✅ Socket disconnected');
      }
      
      // 4. Clear all storage
      localStorage.clear();
      sessionStorage.clear();
      console.log('✅ Storage cleared');
      
      // 5. Close database
      if (this.db) {
        this.db.close();
        console.log('✅ Database closed');
      }
      
      // 6. Clear memory
      this.currentSession = null;
      this.friends = [];
      this.sessions = [];
      this.messages.clear();
      
      // Small delay then redirect
      await new Promise(resolve => setTimeout(resolve, 500));
      window.location.href = '/logout';
    } catch (error) {
      console.error("Logout error:", error);
      // Force redirect even on error
      window.location.href = '/logout';
    }
  }
}

// Initialize ChatManager
window.chatManager = new ChatManager();

// Backward compatibility
window.ChatInterface = ChatManager;
window.chatInterface = window.chatManager;
