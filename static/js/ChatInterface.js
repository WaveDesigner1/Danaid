/**
 * ChatInterface - POPRAWIONA wersja z automatyczną wymianą kluczy
 * Używa UnifiedCrypto i SocketIOHandler z real-time messaging
 */

// ZABEZPIECZENIA PRZECIWKO PĘTLI
let messageLoadingInProgress = new Set();
let lastLoadTime = {};
let switchSessionTimeout = null;
let lastSwitchTime = {};

class ChatInterface {
  constructor(sessionManager) {
    // Inicjalizacja menedżera sesji
    this.sessionManager = sessionManager || window.sessionManager;
    this.initializeDOMElements();
    
    // Stan aplikacji
    this.currentSessionToken = null;
    this.currentUser = null;
    this.friends = [];
    this.sessions = [];
    this.pendingRequests = [];
    
    // Sprawdź czy UnifiedCrypto jest dostępny
    if (!window.unifiedCrypto) {
      console.error("❌ UnifiedCrypto nie jest dostępny!");
      this.showNotification("Błąd ładowania modułu kryptograficznego", "error");
      return;
    }
    
    // Załaduj konfigurację Socket.IO, a następnie zainicjuj interfejs
    this.loadSocketIOConfig().then(() => {
      // Inicjalizacja 
      this.initializeEvents();
      this.loadUserData();
      this.initializeFriendRequestNotifications();
      this.loadFriends();
      this.loadSessions();
    });
    
    // Regularne aktualizacje
    setInterval(() => this.loadPendingRequests(), 30000);
    
    console.log("✅ ChatInterface zainicjalizowany z automatyczną wymianą kluczy");
  }

  /**
   * Ładuje konfigurację Socket.IO
   */
  async loadSocketIOConfig() {
    try {
      const response = await fetch('/api/websocket/config');
      if (response.ok) {
        const config = await response.json();
        if (config && config.socketUrl) {
          window._socketConfig = window._socketConfig || {};
          window._socketConfig.socketUrl = config.socketUrl;
          window._socketConfig.path = config.path;
          console.log('✅ Pobrano konfigurację Socket.IO:', config.socketUrl);
        }
      }
    } catch (e) {
      console.warn('⚠️ Nie udało się pobrać konfiguracji Socket.IO:', e);
    }
  }
  
  /**
   * Inicjalizacja elementów DOM
   */
  initializeDOMElements() {
    this.friendsList = document.getElementById('friend-list');
    this.messagesContainer = document.getElementById('messages');
    this.messageInput = document.getElementById('message-input');
    this.sendButton = document.getElementById('send-button');
    this.addFriendBtn = document.getElementById('add-friend-btn');
    this.chatHeader = document.getElementById('chat-header');
    this.requestBadge = document.getElementById('friend-request-count');
    
    // Utwórz link do panelu admin jeśli potrzeba
    this.adminLink = document.createElement('a');
    this.adminLink.id = 'admin-panel-link';
    this.adminLink.innerHTML = '<i class="fas fa-cog"></i> Admin Panel';
    this.adminLink.style.marginLeft = '15px';
    this.adminLink.classList.add('admin-btn');
    this.adminLink.href = '/admin_dashboard';
    
    console.log('🔧 Elementy DOM zainicjalizowane:', {
      friendsList: !!this.friendsList,
      messagesContainer: !!this.messagesContainer,
      messageInput: !!this.messageInput,
      sendButton: !!this.sendButton
    });
  }

  /**
   * Ładuje dane użytkownika
   */
  loadUserData() {
    this.currentUser = {
      id: sessionStorage.getItem('user_id'),
      username: sessionStorage.getItem('username'),
      isAdmin: sessionStorage.getItem('is_admin') === 'true'
    };
    
    if (!this.currentUser.id) {
      console.error('❌ Brak ID użytkownika');
      this.showNotification('Błąd ładowania danych użytkownika', 'error');
      return;
    }
    
    // Ustaw nazwę użytkownika w UI
    const usernameElement = document.getElementById('username');
    if (usernameElement) {
      usernameElement.textContent = this.currentUser.username;
      
      // Dodaj przycisk panelu administratora, jeśli użytkownik jest adminem
      if (this.currentUser.isAdmin) {
        const userControls = document.querySelector('.user-controls');
        if (userControls && !document.getElementById('admin-panel-link')) {
          userControls.insertBefore(this.adminLink, userControls.firstChild);
        }
      }
    }
    
    console.log(`✅ Dane użytkownika załadowane: ${this.currentUser.username}`);
  }

  /**
   * Ładuje listę znajomych z serwera
   */
  async loadFriends() {
    try {
      if (!this.sessionManager) return;
      
      const result = await this.sessionManager.fetchFriends();
      if (result.status === 'success') {
        this.friends = result.friends;
        this.renderFriendsList();
        console.log(`✅ Załadowano ${this.friends.length} znajomych`);
      } else {
        this.showNotification('Błąd ładowania znajomych', 'error');
      }
    } catch (error) {
      console.error('❌ Błąd ładowania znajomych:', error);
      this.showNotification('Błąd ładowania znajomych', 'error');
    }
  }

  /**
   * POPRAWIONA: Ładuje aktywne sesje z automatyczną wymianą kluczy
   */
  async loadSessions() {
    try {
      if (!this.sessionManager) return;
      
      const result = await this.sessionManager.getActiveSessions();
      if (result.status === 'success') {
        this.updateSessionsList(result.sessions);
        
        // NOWE: Automatycznie uruchom wymianę kluczy dla sesji które jej potrzebują
        result.sessions.forEach(session => {
          if (session.needs_key_exchange && session.is_initiator) {
            console.log('🔑 Auto-start wymiany kluczy dla sesji:', session.token?.substring(0, 10) + '...');
            this.sessionManager.startAutomaticKeyExchange(session.token, session);
          }
        });
        
        // Wybierz pierwszą gotową sesję, jeśli jest dostępna
        if (result.sessions.length > 0 && !this.currentSessionToken) {
          const readySession = result.sessions.find(s => !s.needs_key_exchange);
          if (readySession) {
            this.switchToSession(readySession.token); // ZMIENIONE NA switchToSession
          } else if (result.sessions.length > 0) {
            // Jeśli żadna nie jest gotowa, wybierz pierwszą
            this.switchToSession(result.sessions[0].token); // ZMIENIONE NA switchToSession
          }
        }
        
        console.log(`✅ Załadowano ${result.sessions.length} aktywnych sesji`);
      } else {
        this.showNotification('Błąd ładowania sesji czatu', 'error');
      }
    } catch (error) {
      console.error('❌ Błąd ładowania sesji:', error);
      this.showNotification('Błąd ładowania sesji czatu', 'error');
    }
  }

/**
   * Inicjalizacja nasłuchiwania zdarzeń
   */
  initializeEvents() {
    // Sprawdź, czy wszystkie elementy DOM istnieją
    if (!this.friendsList || !this.messagesContainer || !this.messageInput || 
        !this.sendButton || !this.addFriendBtn || !this.chatHeader) {
      console.error('❌ Brak wymaganych elementów DOM');
      return;
    }

    // Przycisk wysyłania wiadomości
    this.sendButton.addEventListener('click', () => this.sendMessage());
    
    // Obsługa Enter do wysyłania wiadomości
    this.messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });
    
    // Obsługa modalu dodawania znajomych
    this.addFriendBtn.addEventListener('click', () => {
      const modal = document.getElementById('add-friend-modal');
      if (modal) modal.style.display = 'block';
    });
    
    // Zamykanie modalu dodawania znajomego
    const closeBtn = document.querySelector('.search-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        const modal = document.getElementById('add-friend-modal');
        if (modal) modal.style.display = 'none';
      });
    }
    
    // Przycisk wysyłania zaproszenia
    const sendFriendRequestBtn = document.getElementById('send-friend-request-btn');
    if (sendFriendRequestBtn) {
      sendFriendRequestBtn.addEventListener('click', () => this.sendFriendRequest());
    }
    
    // Obsługa kliknięcia w powiadomienie o zaproszeniach
    const notificationIcon = document.getElementById('friend-request-notification');
    if (notificationIcon) {
      notificationIcon.addEventListener('click', () => this.showFriendRequestsModal());
    }

    // Obsługa przycisku wylogowania
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        
        console.log('🚪 Rozpoczynam wylogowanie...');
        
        if (this.sessionManager && typeof this.sessionManager.logout === 'function') {
          this.sessionManager.logout();
        } else {
          // Fallback - bezpośrednie przekierowanie
          console.log('🚪 Wylogowanie fallback...');
          localStorage.clear();
          sessionStorage.clear();
          window.location.href = '/logout';
        }
      });
      
      console.log('✅ Przycisk wylogowania skonfigurowany');
    } else {
      console.warn('⚠️ Przycisk #logout-btn nie znaleziony');
    }

    // POPRAWIONE: Nasłuchiwanie na zdarzenia z menedżera sesji - real-time
    if (this.sessionManager) {
      this.sessionManager.onMessageReceived = (sessionToken, message) => 
        this.displayNewMessage(sessionToken, message);
      this.sessionManager.onSessionsUpdated = (sessions) => 
        this.updateSessionsList(sessions);
      this.sessionManager.onFriendsUpdated = (friends) => 
        this.updateFriendsList(friends);
      this.sessionManager.onOnlineStatusChanged = (onlineUsers) => 
        this.updateOnlineStatus(onlineUsers);
      this.sessionManager.onFriendRequestReceived = () => {
        this.loadPendingRequests();
      };
    }
    
    console.log('✅ Wydarzenia zainicjalizowane z real-time messaging');
  }

  /**
   * NOWA: Wysyłanie wiadomości
   */
  async sendMessage() {
    if (!this.messageInput || !this.currentSessionToken) {
      console.error('❌ Brak wymaganych elementów do wysłania wiadomości');
      return;
    }
    
    const content = this.messageInput.value.trim();
    if (!content) {
      console.log('⚠️ Pusta wiadomość - ignoruję');
      return;
    }
    
    try {
      console.log('📤 Wysyłanie wiadomości...');
      
      // Wyczyść pole input od razu
      this.messageInput.value = '';
      
      // Wyślij przez SessionManager
      const result = await this.sessionManager.sendMessage(this.currentSessionToken, content);
      
      if (result.status === 'success') {
        console.log('✅ Wiadomość wysłana pomyślnie');
        
        // Dodaj wiadomość do UI od razu (optimistic update)
        if (result.messageData) {
          this.addMessageToUI(result.messageData);
        }
      } else {
        console.error('❌ Błąd wysyłania:', result.message);
        this.showNotification(result.message || 'Błąd wysyłania wiadomości', 'error');
        
        // Przywróć tekst w input przy błędzie
        this.messageInput.value = content;
      }
    } catch (error) {
      console.error('❌ Błąd sendMessage:', error);
      this.showNotification('Błąd wysyłania wiadomości', 'error');
      
      // Przywróć tekst w input przy błędzie
      this.messageInput.value = content;
    }
  }

  /**
   * POPRAWIONA: Wybiera znajomego i automatycznie uruchamia wymianę kluczy
   */
  async selectFriend(friend) {
    console.log('👤 Wybrano znajomego:', friend.username);
    
    // Usuń aktywny stan z innych elementów
    document.querySelectorAll('.friend-item').forEach(item => {
      item.classList.remove('active');
    });
    
    // Dodaj aktywny stan do wybranego elementu
    const friendElement = document.querySelector(`[data-user-id="${friend.user_id}"]`);
    if (friendElement) {
      friendElement.classList.add('active');
    }
    
    // Zaktualizuj nagłówek czatu
    if (this.chatHeader) {
      this.chatHeader.innerHTML = `
        <h3>${friend.username}</h3>
        <span class="status ${friend.is_online ? 'online' : 'offline'}">
          ${friend.is_online ? 'Online' : 'Offline'}
        </span>
      `;
    }
    
    try {
      // NOWE: Automatyczne initSession z auto-wymianą kluczy
      await this.initSession(friend.user_id);
    } catch (error) {
      console.error('❌ Błąd wyboru znajomego:', error);
      this.showNotification('Błąd inicjalizacji czatu', 'error');
    }
  }

  /**
   * POPRAWIONA: Inicjuje sesję - używa istniejącej lub tworzy nową z auto-kluczami
   */
  async initSession(userId) {
    try {
      console.log('🚀 Inicjalizacja sesji z użytkownikiem:', userId);
      
      // NOWE: SessionManager automatycznie sprawdzi czy sesja istnieje
      const result = await this.sessionManager.initSession(userId);
      
      if (result.status === 'success') {
        this.currentSessionToken = result.session_token;
        
        if (result.isExisting) {
          console.log('♻️ Używam istniejącej sesji:', this.currentSessionToken?.substring(0, 10) + '...');
        } else {
          console.log('🆕 Utworzono nową sesję:', this.currentSessionToken?.substring(0, 10) + '...');
        }
        
        // Załaduj wiadomości dla tej sesji
        await this.loadMessages(this.currentSessionToken);
        
        // Wyczyść licznik nieprzeczytanych dla tej sesji
        const session = this.sessions.find(s => s.token === this.currentSessionToken);
        if (session) {
          session.unread_count = 0;
          this.renderFriendsList();
        }
        
        // NOWE: Jeśli sesja potrzebuje wymiany kluczy - pokaż status
        if (result.session?.needs_key_exchange) {
          this.showNotification("🔑 Konfigurowanie szyfrowania...", "info", 3000);
        }
        
      } else {
        console.error('❌ Błąd inicjalizacji sesji:', result.message);
        this.showNotification(result.message || 'Błąd inicjalizacji sesji', 'error');
      }
    } catch (error) {
      console.error('❌ Błąd initSession:', error);
      this.showNotification('Błąd połączenia z serwerem', 'error');
    }
  }

  /**
   * Przełącza na wybraną sesję (ISTNIEJĄCA - bez zabezpieczeń)
   */
  async switchSession(sessionToken) {
    console.log('🔄 Przełączanie na sesję:', sessionToken?.substring(0, 10) + '...');
    
    this.currentSessionToken = sessionToken;
    await this.loadMessages(sessionToken);
    
    // Znajdź użytkownika tej sesji i zaktualizuj UI
    const session = this.sessions.find(s => s.token === sessionToken);
    if (session) {
      const friend = this.friends.find(f => f.user_id === session.other_user.user_id);
      if (friend) {
        // Zaktualizuj UI bez ponownej inicjalizacji sesji
        document.querySelectorAll('.friend-item').forEach(item => {
          item.classList.remove('active');
        });
        
        const friendElement = document.querySelector(`[data-user-id="${friend.user_id}"]`);
        if (friendElement) {
          friendElement.classList.add('active');
        }
        
        if (this.chatHeader) {
          this.chatHeader.innerHTML = `
            <h3>${friend.username}</h3>
            <span class="status ${friend.is_online ? 'online' : 'offline'}">
              ${friend.is_online ? 'Online' : 'Offline'}
            </span>
          `;
        }
      }
    }
  }

  /**
   * NOWA: Przełączanie na sesję - ZABEZPIECZONE PRZED PĘTLĄ
   */
  switchToSession(sessionToken) {
    console.log('🔄 [PROTECTED] Przełączanie na sesję:', sessionToken?.substring(0, 10) + '...');
    
    // ZABEZPIECZENIE 1: Sprawdź czy to nie ta sama sesja
    if (this.currentSessionToken === sessionToken) {
      console.log('⚠️ Już jesteś w tej sesji - ignoruję');
      return;
    }
    
    // ZABEZPIECZENIE 2: Debouncing - anuluj poprzednie wywołanie
    if (switchSessionTimeout) {
      clearTimeout(switchSessionTimeout);
    }
    
    // ZABEZPIECZENIE 3: Sprawdź czy nie przełączaliśmy niedawno
    const now = Date.now();
    const lastSwitch = lastSwitchTime[sessionToken] || 0;
    if (now - lastSwitch < 500) { // 500ms debounce
      console.log('⏳ Zbyt częste przełączanie - ignoruję');
      return;
    }
    
    // Opóźnij przełączanie o 100ms
    switchSessionTimeout = setTimeout(async () => {
      lastSwitchTime[sessionToken] = Date.now();
      await this.switchSession(sessionToken); // Wywołaj istniejącą metodę
    }, 100);
  }

/**
   * POPRAWIONA: Ładowanie wiadomości - ZABEZPIECZONE PRZED PĘTLĄ
   */
  async loadMessages(sessionToken) {
    try {
      console.log('📥 Ładowanie wiadomości dla sesji:', sessionToken?.substring(0, 10) + '...');
      
      // ZABEZPIECZENIE 1: Sprawdź czy już ładujemy dla tej sesji
      if (messageLoadingInProgress.has(sessionToken)) {
        console.log('⚠️ Ładowanie wiadomości już w toku dla:', sessionToken?.substring(0, 10) + '...');
        return;
      }
      
      // ZABEZPIECZENIE 2: Sprawdź czy nie ładowaliśmy niedawno (debouncing)
      const now = Date.now();
      const lastLoad = lastLoadTime[sessionToken] || 0;
      if (now - lastLoad < 1000) { // 1 sekunda debounce
        console.log('⏳ Zbyt częste ładowanie - ignoruję');
        return;
      }
      
      // Dodaj do listy w toku
      messageLoadingInProgress.add(sessionToken);
      lastLoadTime[sessionToken] = now;
      
      if (!sessionToken) {
        console.error('❌ Brak tokenu sesji');
        return;
      }
      
      // 1. Najpierw załaduj lokalne wiadomości
      const localResult = window.sessionManager.getLocalMessages(sessionToken);
      const localMessages = localResult.messages || [];
      
      console.log(`📝 Ładuję ${localMessages.length} wiadomości`);
      
      // Wyświetl lokalne wiadomości natychmiast
      if (localMessages.length > 0) {
        this.displayMessages(localMessages);
      }
      
      // 2. Następnie pobierz z serwera (z zabezpieczeniem)
      const serverResult = await window.sessionManager.fetchMessagesFromServer(sessionToken);
      
      if (serverResult.status === 'success' && serverResult.messages.length > 0) {
        console.log(`📥 Pobrano ${serverResult.messages.length} nowych wiadomości z serwera`);
        
        // Wyświetl wszystkie wiadomości (lokalne + nowe z serwera)
        const allLocalMessages = window.sessionManager.getLocalMessages(sessionToken);
        this.displayMessages(allLocalMessages.messages || []);
      }
      
    } catch (error) {
      console.error('❌ Błąd ładowania wiadomości:', error);
    } finally {
      // ZAWSZE usuń z listy w toku
      messageLoadingInProgress.delete(sessionToken);
    }
  }

  /**
   * NOWA: Wyświetla listę wiadomości
   */
  displayMessages(messages) {
    if (!this.messagesContainer) {
      console.error('❌ messagesContainer nie istnieje!');
      return;
    }
    
    try {
      // Wyczyść kontener
      this.messagesContainer.innerHTML = '';
      
      if (!messages || messages.length === 0) {
        this.messagesContainer.innerHTML = '<div class="system-message">Brak wiadomości</div>';
        return;
      }
      
      // Wyświetl wszystkie wiadomości
      messages.forEach(message => {
        const messageElement = this.createMessageElement(message);
        this.messagesContainer.appendChild(messageElement);
      });
      
      this.scrollToBottom();
      
    } catch (error) {
      console.error('❌ Błąd wyświetlania wiadomości:', error);
    }
  }

  /**
   * POPRAWIONA: Real-time wyświetlanie nowych wiadomości
   */
  displayNewMessage(sessionToken, message) {
    console.log('🆕 REAL-TIME: Otrzymano nową wiadomość:', {
      sessionToken: sessionToken?.substring(0, 10) + '...',
      message: {
        id: message.id,
        content: message.content?.substring(0, 50) + "...",
        sender_id: message.sender_id
      },
      currentSession: this.currentSessionToken?.substring(0, 10) + '...',
      isCurrentSession: sessionToken === this.currentSessionToken
    });
    
    // Jeśli to aktualna sesja, wyświetl od razu
    if (sessionToken === this.currentSessionToken) {
      console.log('📺 REAL-TIME: Wyświetlam wiadomość w aktualnej sesji');
      this.addMessageToUI(message);
      this.playNotificationSound();
    } else {
      // NOWE: Jeśli to inna sesja, ale nie mamy aktywnej - automatycznie przełącz
      if (!this.currentSessionToken) {
        console.log('🔄 REAL-TIME: Brak aktywnej sesji - automatyczne przełączenie');
        
        // Znajdź sesję i przełącz na nią
        const session = this.sessions.find(s => s.token === sessionToken);
        if (session && session.other_user) {
          const friend = this.friends.find(f => f.user_id === session.other_user.user_id);
          if (friend) {
            this.switchToSession(sessionToken);
            
            // Po przełączeniu, wyświetl wiadomość
            setTimeout(() => {
              this.addMessageToUI(message);
              this.playNotificationSound();
            }, 500);
          }
        }
      } else {
        // Jeśli to inna sesja, zaktualizuj wskaźnik nieprzeczytanych wiadomości
        console.log('📊 REAL-TIME: Wiadomość w innej sesji - aktualizuję wskaźniki');
        this.updateUnreadCount(sessionToken);
        this.playNotificationSound();
        
        // Pokaż powiadomienie o nowej wiadomości z innej sesji
        const session = this.sessions.find(s => s.token === sessionToken);
        if (session && session.other_user) {
          this.showNotification(
            `Nowa wiadomość od ${session.other_user.username}`, 
            "info", 
            5000
          );
        }
      }
    }
  }

  /**
   * Dodaje wiadomość do UI
   */
  addMessageToUI(message) {
    if (!this.messagesContainer) {
      console.error('❌ messagesContainer nie istnieje!');
      this.messagesContainer = document.getElementById('messages');
      if (!this.messagesContainer) {
        console.error('❌ Nie można znaleźć elementu #messages w DOM');
        return;
      }
    }
    
    if (!message) {
      console.error('❌ Brak wiadomości do wyświetlenia');
      return;
    }
    
    try {
      // Usuń komunikat systemowy jeśli istnieje
      const systemMessage = this.messagesContainer.querySelector('.system-message');
      if (systemMessage) {
        systemMessage.remove();
      }
      
      const messageElement = this.createMessageElement(message);
      this.messagesContainer.appendChild(messageElement);
      this.scrollToBottom();
      
    } catch (error) {
      console.error('❌ Błąd w addMessageToUI:', error);
    }
  }
  
  /**
   * Tworzy element wiadomości
   */
  createMessageElement(message) {
    const messageDiv = document.createElement('div');
    
    // Sprawdź czy to nasza wiadomość
    const isSent = message.sender_id === parseInt(this.currentUser.id) || message.is_mine;
    
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = message.content || '[Pusta wiadomość]';
    
    const infoDiv = document.createElement('div');
    infoDiv.className = 'message-info';
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = this.formatTime(message.timestamp);
    
    infoDiv.appendChild(timeSpan);
    messageDiv.appendChild(contentDiv);
    messageDiv.appendChild(infoDiv);
    
    // Dodaj style inline
    messageDiv.style.cssText = `
      margin-bottom: 10px;
      padding: 10px;
      border-radius: 8px;
      max-width: 70%;
      word-wrap: break-word;
      ${isSent ? 
        'background: #007bff; color: white; margin-left: auto; text-align: right;' : 
        'background: #f1f1f1; color: black; margin-right: auto; text-align: left;'
      }
    `;
    
    contentDiv.style.cssText = 'margin-bottom: 5px; font-size: 14px;';
    infoDiv.style.cssText = 'font-size: 12px; opacity: 0.7;';
    
    return messageDiv;
  }

  /**
   * Formatuje czas wiadomości
   */
  formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    if (date >= today) {
      return timeStr;
    } else if (date >= yesterday) {
      return `Wczoraj, ${timeStr}`;
    } else {
      return `${date.toLocaleDateString()} ${timeStr}`;
    }
  }
  
  /**
   * Przewija do końca kontener wiadomości
   */
  scrollToBottom() {
    if (this.messagesContainer) {
      this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }
  }

  /**
   * Aktualizuje liczbę nieprzeczytanych wiadomości
   */
  updateUnreadCount(sessionToken) {
    const session = this.sessions.find(s => s.token === sessionToken);
    if (session) {
      session.unread_count = (session.unread_count || 0) + 1;
      this.renderFriendsList();
    }
  }

  /**
   * Odtwarza dźwięk powiadomienia
   */
  playNotificationSound() {
    const soundEnabled = localStorage.getItem('notification_sound') !== 'false';
    if (soundEnabled) {
      try {
        const audio = new Audio('/static/sounds/notification.mp3');
        audio.volume = 0.3;
        audio.play().catch(e => console.log('Nie można odtworzyć dźwięku:', e));
      } catch (e) {
        console.log('Błąd odtwarzania dźwięku:', e);
      }
    }
  }

  /**
   * Aktualizuje listę sesji
   */
  updateSessionsList(sessions) {
    this.sessions = sessions || [];
    console.log(`📋 Zaktualizowano listę sesji: ${this.sessions.length} sesji`);
  }

  /**
   * Renderuje listę znajomych
   */
  renderFriendsList() {
    if (!this.friendsList) return;
    
    this.friendsList.innerHTML = '';
    
    this.friends.forEach(friend => {
      const friendElement = this.createFriendElement(friend);
      this.friendsList.appendChild(friendElement);
    });
  }

  /**
   * Tworzy element znajomego na liście
   */
  createFriendElement(friend) {
    const li = document.createElement('li');
    li.className = 'friend-item';
    li.dataset.userId = friend.user_id;
    
    // Znajdź sesję dla tego znajomego
    const session = this.sessions.find(s => s.other_user && s.other_user.user_id === friend.user_id);
    const unreadCount = session?.unread_count || 0;
    
    li.innerHTML = `
      <div class="friend-avatar">
        <i class="fas fa-user"></i>
      </div>
      <div class="friend-info">
        <div class="friend-name">${friend.username}</div>
        <div class="friend-status ${friend.is_online ? 'online' : 'offline'}">
          ${friend.is_online ? 'Online' : 'Offline'}
        </div>
      </div>
      ${unreadCount > 0 ? `<div class="unread-count">${unreadCount}</div>` : ''}
    `;
    
    li.addEventListener('click', () => this.selectFriend(friend));
    
    return li;
  }

  /**
   * Aktualizuje status online użytkowników
   */
  updateOnlineStatus(onlineUsers) {
    console.log('🟢 Aktualizacja statusu online:', onlineUsers);
    
    this.friends.forEach(friend => {
      friend.is_online = onlineUsers.includes(friend.user_id);
    });
    
    this.renderFriendsList();
  }

  /**
   * Aktualizuje listę znajomych
   */
  updateFriendsList(friends) {
    this.friends = friends || [];
    this.renderFriendsList();
    console.log(`👥 Zaktualizowano listę znajomych: ${this.friends.length} znajomych`);
  }

  /**
   * Inicjalizuje powiadomienia o zaproszeniach do znajomych
   */
  initializeFriendRequestNotifications() {
    this.loadPendingRequests();
  }

  /**
   * Ładuje oczekujące zaproszenia do znajomych
   */
  async loadPendingRequests() {
    try {
      const response = await fetch('/api/friend_requests/pending', {
        credentials: 'same-origin'
      });
      
      if (response.ok) {
        const data = await response.json();
        this.pendingRequests = data.requests || [];
        this.updateRequestBadge();
      }
    } catch (error) {
      console.error('❌ Błąd ładowania zaproszeń:', error);
    }
  }

  /**
   * Aktualizuje wskaźnik liczby zaproszeń
   */
  updateRequestBadge() {
    if (this.requestBadge) {
      const count = this.pendingRequests.length;
      if (count > 0) {
        this.requestBadge.textContent = count;
        this.requestBadge.style.display = 'inline';
      } else {
        this.requestBadge.style.display = 'none';
      }
    }
  }

  /**
   * Wysyła zaproszenie do znajomego
   */
  async sendFriendRequest() {
    const usernameInput = document.getElementById('friend-username-input');
    if (!usernameInput) return;
    
    const username = usernameInput.value.trim();
    if (!username) {
      this.showNotification('Wprowadź nazwę użytkownika', 'warning');
      return;
    }
    
    try {
      const response = await fetch('/api/friend_requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({ username })
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        this.showNotification('Zaproszenie wysłane!', 'success');
        usernameInput.value = '';
        
        // Zamknij modal
        const modal = document.getElementById('add-friend-modal');
        if (modal) modal.style.display = 'none';
      } else {
        this.showNotification(result.message || 'Błąd wysyłania zaproszenia', 'error');
      }
    } catch (error) {
      console.error('❌ Błąd wysyłania zaproszenia:', error);
      this.showNotification('Błąd połączenia z serwerem', 'error');
    }
  }

  /**
   * Pokazuje modal z zaproszeniami do znajomych
   */
  showFriendRequestsModal() {
    console.log('📨 Pokazuję modal z zaproszeniami');
    
    let modal = document.getElementById('friend-requests-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'friend-requests-modal';
      modal.className = 'modal';
      modal.innerHTML = `
        <div class="modal-content">
          <div class="modal-header">
            <h3>Zaproszenia do znajomych</h3>
            <span class="modal-close">&times;</span>
          </div>
          <div class="modal-body">
            <div id="friend-requests-list"></div>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
      
      modal.querySelector('.modal-close').addEventListener('click', () => {
        modal.style.display = 'none';
      });
      
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.style.display = 'none';
        }
      });
    }
    
    const requestsList = modal.querySelector('#friend-requests-list');
    if (requestsList) {
      if (this.pendingRequests.length === 0) {
        requestsList.innerHTML = '<p>Brak nowych zaproszeń</p>';
      } else {
        requestsList.innerHTML = this.pendingRequests.map(request => `
          <div class="friend-request-item">
            <div class="request-info">
              <strong>${request.sender_username}</strong>
              <small>${this.formatTime(request.created_at)}</small>
            </div>
            <div class="request-actions">
              <button class="btn btn-accept" onclick="chatInterface.acceptFriendRequest(${request.id})">
                Akceptuj
              </button>
              <button class="btn btn-decline" onclick="chatInterface.declineFriendRequest(${request.id})">
                Odrzuć
              </button>
            </div>
          </div>
        `).join('');
      }
    }
    
    modal.style.display = 'block';
  }

  /**
   * Akceptuje zaproszenie do znajomych
   */
  async acceptFriendRequest(requestId) {
    try {
      const response = await fetch(`/api/friend_requests/${requestId}/accept`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        this.showNotification('Zaproszenie zaakceptowane!', 'success');
        this.loadPendingRequests();
        this.loadFriends();
        
        if (this.pendingRequests.length <= 1) {
          const modal = document.getElementById('friend-requests-modal');
          if (modal) modal.style.display = 'none';
        }
      } else {
        this.showNotification(result.message || 'Błąd akceptacji zaproszenia', 'error');
      }
    } catch (error) {
      console.error('❌ Błąd akceptacji zaproszenia:', error);
      this.showNotification('Błąd połączenia z serwerem', 'error');
    }
  }

  /**
   * Odrzuca zaproszenie do znajomych
   */
  async declineFriendRequest(requestId) {
    try {
      const response = await fetch(`/api/friend_requests/${requestId}/decline`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        this.showNotification('Zaproszenie odrzucone', 'info');
        this.loadPendingRequests();
        
        if (this.pendingRequests.length <= 1) {
          const modal = document.getElementById('friend-requests-modal');
          if (modal) modal.style.display = 'none';
        }
      } else {
        this.showNotification(result.message || 'Błąd odrzucenia zaproszenia', 'error');
      }
    } catch (error) {
      console.error('❌ Błąd odrzucenia zaproszenia:', error);
      this.showNotification('Błąd połączenia z serwerem', 'error');
    }
  }

  /**
   * Pokazuje powiadomienie
   */
  showNotification(message, type = 'info', duration = 5000) {
    console.log(`📢 Powiadomienie [${type}]:`, message);
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 20px;
      border-radius: 6px;
      color: white;
      font-weight: 500;
      z-index: 10000;
      max-width: 300px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2);
      background: ${type === 'success' ? '#28a745' : 
                   type === 'error' ? '#dc3545' : 
                   type === 'warning' ? '#ffc107' : '#007bff'};
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, duration);
  }
}

// Eksportuj klasę lub ustaw jako globalną
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ChatInterface;
} else {
  window.ChatInterface = ChatInterface;
}

// Inicjalizacja globalnego ChatInterface po załadowaniu DOM
document.addEventListener('DOMContentLoaded', () => {
  // Poczekaj na załadowanie SessionManager
  const initChatInterface = () => {
    if (window.sessionManager) {
      window.chatInterface = new ChatInterface(window.sessionManager);
      console.log('✅ ChatInterface zainicjalizowany globalnie');
    } else {
      console.log('⏳ Czekam na SessionManager...');
      setTimeout(initChatInterface, 500);
    }
  };
  
  initChatInterface();
});

console.log("✅ ChatInterface załadowany z automatyczną wymianą kluczy i real-time messaging");
