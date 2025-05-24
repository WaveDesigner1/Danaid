/**
 * ChatInterface - POPRAWIONA wersja z automatyczną wymianą kluczy i real-time messaging
 * Używa UnifiedCrypto i SocketIOHandler z automatyczną obsługą stanów sesji
 */
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
    this.sessionStates = {}; // NOWE: Śledzenie stanów sesji
    
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
      
      // NOWE: Ustaw callback dla zakończenia wymiany kluczy
      if (this.sessionManager) {
        this.sessionManager.onKeyExchangeCompleted = (sessionToken) => {
          this.handleKeyExchangeCompleted(sessionToken);
        };
      }
    });
    
    // Regularne aktualizacje
    setInterval(() => this.loadPendingRequests(), 30000);
    setInterval(() => this.refreshActiveSessions(), 60000); // NOWE: Odświeżanie sesji
    
    console.log("✅ ChatInterface zainicjalizowany z automatyczną wymianą kluczy");
  }

  /**
   * NOWA: Obsługuje zakończenie wymiany kluczy
   */
  handleKeyExchangeCompleted(sessionToken) {
    console.log('🎉 Wymiana kluczy zakończona dla sesji:', sessionToken?.substring(0, 10) + '...');
    
    // Zaktualizuj stan sesji
    if (this.sessionStates[sessionToken]) {
      this.sessionStates[sessionToken].keyExchangeCompleted = true;
      this.sessionStates[sessionToken].isReady = true;
    }
    
    // Jeśli to aktywna sesja, pokaż powiadomienie
    if (sessionToken === this.currentSessionToken) {
      this.showNotification("🔐 Szyfrowanie końcowo-końcowe aktywne", "success", 3000);
      
      // Włącz pole wprowadzania wiadomości
      if (this.messageInput) {
        this.messageInput.disabled = false;
        this.messageInput.placeholder = "Napisz wiadomość...";
      }
      
      if (this.sendButton) {
        this.sendButton.disabled = false;
      }
    }
    
    // Odśwież listę sesji
    this.loadSessions();
  }

  /**
   * NOWA: Odświeża aktywne sesje
   */
  async refreshActiveSessions() {
    if (this.sessionManager) {
      await this.sessionManager.getActiveSessions();
    }
  }

  /**
   * Ładuje konfigurację Socket.IO - BEZ ZMIAN
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
   * Inicjalizacja elementów DOM - BEZ ZMIAN
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
   * POPRAWIONA: Inicjalizacja nasłuchiwania zdarzeń z obsługą stanów sesji
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
    
    // Obsługa Enter do wysyłania wiadomości + Shift+Enter dla nowej linii
    this.messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });
    
    // NOWE: Obsługa pisania (typing indicators w przyszłości)
    this.messageInput.addEventListener('input', () => {
      // Można dodać typing indicators
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

    // POPRAWIONE: Nasłuchiwanie na zdarzenia z menedżera sesji
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
    
    console.log('✅ Wydarzenia zainicjalizowane z obsługą stanów sesji');
  }

/**
 * ChatInterface - POPRAWIONA wersja z automatyczną wymianą kluczy i real-time messaging
 * Używa UnifiedCrypto i SocketIOHandler z automatyczną obsługą stanów sesji
 */
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
    this.sessionStates = {}; // NOWE: Śledzenie stanów sesji
    
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
      
      // NOWE: Ustaw callback dla zakończenia wymiany kluczy
      if (this.sessionManager) {
        this.sessionManager.onKeyExchangeCompleted = (sessionToken) => {
          this.handleKeyExchangeCompleted(sessionToken);
        };
      }
    });
    
    // Regularne aktualizacje
    setInterval(() => this.loadPendingRequests(), 30000);
    setInterval(() => this.refreshActiveSessions(), 60000); // NOWE: Odświeżanie sesji
    
    console.log("✅ ChatInterface zainicjalizowany z automatyczną wymianą kluczy");
  }

  /**
   * NOWA: Obsługuje zakończenie wymiany kluczy
   */
  handleKeyExchangeCompleted(sessionToken) {
    console.log('🎉 Wymiana kluczy zakończona dla sesji:', sessionToken?.substring(0, 10) + '...');
    
    // Zaktualizuj stan sesji
    if (this.sessionStates[sessionToken]) {
      this.sessionStates[sessionToken].keyExchangeCompleted = true;
      this.sessionStates[sessionToken].isReady = true;
    }
    
    // Jeśli to aktywna sesja, pokaż powiadomienie
    if (sessionToken === this.currentSessionToken) {
      this.showNotification("🔐 Szyfrowanie końcowo-końcowe aktywne", "success", 3000);
      
      // Włącz pole wprowadzania wiadomości
      if (this.messageInput) {
        this.messageInput.disabled = false;
        this.messageInput.placeholder = "Napisz wiadomość...";
      }
      
      if (this.sendButton) {
        this.sendButton.disabled = false;
      }
    }
    
    // Odśwież listę sesji
    this.loadSessions();
  }

  /**
   * NOWA: Odświeża aktywne sesje
   */
  async refreshActiveSessions() {
    if (this.sessionManager) {
      await this.sessionManager.getActiveSessions();
    }
  }

  /**
   * Ładuje konfigurację Socket.IO - BEZ ZMIAN
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
   * Inicjalizacja elementów DOM - BEZ ZMIAN
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
   * POPRAWIONA: Inicjalizacja nasłuchiwania zdarzeń z obsługą stanów sesji
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
    
    // Obsługa Enter do wysyłania wiadomości + Shift+Enter dla nowej linii
    this.messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });
    
    // NOWE: Obsługa pisania (typing indicators w przyszłości)
    this.messageInput.addEventListener('input', () => {
      // Można dodać typing indicators
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

    // POPRAWIONE: Nasłuchiwanie na zdarzenia z menedżera sesji
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
    
    console.log('✅ Wydarzenia zainicjalizowane z obsługą stanów sesji');
  }

/**
   * POPRAWIONA: Wyświetla nową wiadomość z automatycznym przełączaniem sesji
   */
  displayNewMessage(sessionToken, message) {
    console.log('🆕 Otrzymano nową wiadomość:', {
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
      console.log('📺 Wyświetlam wiadomość w aktualnej sesji');
      this.addMessageToUI(message);
      this.playNotificationSound();
    } else {
      // NOWE: Jeśli to inna sesja, ale nie mamy aktywnej - automatycznie przełącz
      if (!this.currentSessionToken) {
        console.log('🔄 Brak aktywnej sesji - automatyczne przełączenie');
        
        // Znajdź sesję i przełącz na nią
        const session = this.sessions.find(s => s.token === sessionToken);
        if (session && session.other_user) {
          const friend = this.friends.find(f => f.user_id === session.other_user.user_id);
          if (friend) {
            this.selectFriend(friend);
            
            // Po przełączeniu, wyświetl wiadomość
            setTimeout(() => {
              this.addMessageToUI(message);
              this.playNotificationSound();
            }, 1000);
          }
        }
      } else {
        // Jeśli to inna sesja, zaktualizuj wskaźnik nieprzeczytanych wiadomości
        console.log('📊 Wiadomość w innej sesji - aktualizuję wskaźniki');
        this.updateUnreadCount(sessionToken);
        this.playNotificationSound();
        
        // NOWE: Pokaż powiadomienie o nowej wiadomości z innej sesji
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
   * Ładuje dane użytkownika - BEZ ZMIAN
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
   * Ładuje listę znajomych - BEZ ZMIAN
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
   * POPRAWIONA: Ładuje aktywne sesje z obsługą stanów
   */
  async loadSessions() {
    try {
      if (!this.sessionManager) return;
      
      const result = await this.sessionManager.getActiveSessions();
      if (result.status === 'success') {
        this.updateSessionsList(result.sessions);
        
        // NOWE: Aktualizuj stany sesji
        result.sessions.forEach(session => {
          this.sessionStates[session.token] = {
            friendId: session.other_user?.user_id,
            friendUsername: session.other_user?.username,
            isReady: session.is_ready || false,
            needsKeyExchange: session.needs_key_exchange || false,
            keyExchangeCompleted: session.is_ready || false
          };
        });
        
        // Jeśli nie mamy aktywnej sesji, ale są dostępne sesje, wybierz pierwszą gotową
        if (!this.currentSessionToken && result.sessions.length > 0) {
          const readySession = result.sessions.find(s => s.is_ready);
          if (readySession) {
            const friend = this.friends.find(f => f.user_id === readySession.other_user.user_id);
            if (friend) {
              console.log('🔄 Automatyczne przełączenie na gotową sesję:', readySession.token?.substring(0, 10) + '...');
              this.selectFriend(friend);
            }
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
   * POPRAWIONA: Ładuje wiadomości z kontrolą gotowości sesji
   */
  async loadMessages(sessionToken) {
    if (!this.sessionManager) {
      console.error('❌ SessionManager nie jest dostępny');
      return;
    }
    
    if (this.messagesContainer) {
      this.messagesContainer.innerHTML = '';
    }
    
    try {
      console.log('📥 Ładowanie wiadomości dla sesji:', sessionToken?.substring(0, 10) + '...');
      
      // Sprawdź stan sesji
      const sessionState = this.sessionStates[sessionToken];
      if (sessionState && !sessionState.keyExchangeCompleted) {
        console.log('⏳ Sesja nie jest jeszcze gotowa, czekam...');
        
        // Pokaż komunikat o oczekiwaniu
        if (this.messagesContainer) {
          this.messagesContainer.innerHTML = `
            <div class="system-message">
              <div class="loading-indicator">
                <div class="spinner"></div>
                <p>Przygotowywanie bezpiecznego połączenia...</p>
              </div>
            </div>
          `;
        }
        
        return;
      }
      
      // Załaduj lokalne wiadomości
      const result = this.sessionManager.getLocalMessages(sessionToken);
      
      console.log('📨 Wynik ładowania wiadomości:', result);
      
      if (result && result.status === 'success') {
        const messages = result.messages || [];
        console.log(`📝 Ładuję ${messages.length} wiadomości`);
        
        if (messages.length === 0) {
          // Pokaż komunikat o braku wiadomości
          if (this.messagesContainer) {
            this.messagesContainer.innerHTML = `
              <div class="system-message">
                <p>🔐 Bezpieczna rozmowa została rozpoczęta</p>
                <p>Wiadomości są szyfrowane końcowo-końcowo</p>
              </div>
            `;
          }
        } else {
          messages.forEach(message => {
            this.addMessageToUI(message);
          });
        }
        
        this.scrollToBottom();
        
        // Spróbuj pobrać nowsze wiadomości z serwera
        try {
          const serverResult = await this.sessionManager.fetchMessagesFromServer(sessionToken);
          if (serverResult.status === 'success' && serverResult.messages.length > messages.length) {
            console.log(`📥 Pobrano ${serverResult.messages.length - messages.length} nowych wiadomości z serwera`);
            // Przeładuj po pobraniu z serwera
            setTimeout(() => this.loadMessages(sessionToken), 100);
          }
        } catch (serverError) {
          console.warn('⚠️ Nie można pobrać z serwera:', serverError);
        }
      } else {
        console.warn('⚠️ Brak wiadomości lub błąd:', result);
      }
    } catch (error) {
      console.error('❌ Błąd ładowania wiadomości:', error);
      this.showNotification('Błąd ładowania wiadomości', 'error');
    }
  }

  /**
   * POPRAWIONA: Dodaje wiadomość do UI z lepszym formatowaniem
   */
  addMessageToUI(message) {
    console.log('🎨 addMessageToUI wywołane z:', {
      message: message,
      hasContainer: !!this.messagesContainer
    });
    
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
      console.log('✅ Element wiadomości utworzony:', messageElement);
      
      this.messagesContainer.appendChild(messageElement);
      this.scrollToBottom();
      
      console.log('✅ Element dodany do kontenera');
      
    } catch (error) {
      console.error('❌ Błąd w addMessageToUI:', error);
    }
  }
  
  /**
   * POPRAWIONA: Tworzy element wiadomości z lepszym stylem
   */
  createMessageElement(message) {
    const messageDiv = document.createElement('div');
    
    // Sprawdź czy to nasza wiadomość
    const isSent = message.sender_id === parseInt(this.currentUser.id) || message.is_mine;
    
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    
    // NOWE: Lepsze formatowanie treści wiadomości
    let content = message.content || '[Pusta wiadomość]';
    
    // Sprawdź czy są błędy deszyfrowania
    if (message.decryption_error) {
      content = '🔒 ' + content;
      contentDiv.classList.add('decryption-error');
    }
    
    // Formatuj tekst (podstawowe formatowanie)
    content = this.formatMessageContent(content);
    contentDiv.innerHTML = content;
    
    const infoDiv = document.createElement('div');
    infoDiv.className = 'message-info';
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = this.formatTime(message.timestamp);
    
    // NOWE: Dodaj status dostarczenia dla wysłanych wiadomości
    if (isSent && !message.decryption_error) {
      const statusSpan = document.createElement('span');
      statusSpan.className = 'message-status';
      statusSpan.innerHTML = '✓'; // Podstawowy status
      infoDiv.appendChild(statusSpan);
    }
    
    infoDiv.appendChild(timeSpan);
    messageDiv.appendChild(contentDiv);
    messageDiv.appendChild(infoDiv);
    
    // POPRAWIONE: Lepsze style CSS
    messageDiv.style.cssText = `
      margin-bottom: 12px;
      padding: 12px 16px;
      border-radius: 12px;
      max-width: 70%;
      word-wrap: break-word;
      position: relative;
      ${isSent ? 
        'background: linear-gradient(135deg, #007bff, #0056b3); color: white; margin-left: auto; text-align: right;' : 
        'background: #f8f9fa; color: #333; margin-right: auto; text-align: left; border: 1px solid #e9ecef;'
      }
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      animation: messageSlideIn 0.3s ease-out;
    `;
    
    contentDiv.style.cssText = 'margin-bottom: 6px; font-size: 14px; line-height: 1.4;';
    infoDiv.style.cssText = 'font-size: 11px; opacity: 0.7; display: flex; justify-content: space-between; align-items: center;';
    
    // Dodaj animację CSS jeśli nie istnieje
    if (!document.getElementById('message-animations')) {
      const style = document.createElement('style');
      style.id = 'message-animations';
      style.textContent = `
        @keyframes messageSlideIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        
        .message.sent .message-status {
          margin-left: 8px;
          color: rgba(255,255,255,0.8);
        }
        
        .message.received.decryption-error {
          background: #fff3cd;
          border-color: #ffeaa7;
          color: #856404;
        }
        
        .message.sent.decryption-error {
          background: #f8d7da;
          color: #721c24;
        }
        
        .system-message {
          text-align: center;
          padding: 20px;
          color: #666;
          font-style: italic;
        }
        
        .loading-indicator {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 10px;
        }
        
        .spinner {
          width: 32px;
          height: 32px;
          border: 3px solid #f3f3f3;
          border-top: 3px solid #007bff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }
    
    return messageDiv;
  }

  /**
   * NOWA: Formatuje treść wiadomości (podstawowe formatowanie)
   */
  formatMessageContent(content) {
    // Escapuj HTML
    const div = document.createElement('div');
    div.textContent = content;
    let formatted = div.innerHTML;
    
    // Podstawowe formatowanie
    formatted = formatted.replace(/\n/g, '<br>'); // Nowe linie
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>'); // Pogrubienie
    formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>'); // Kursywa
    
    // Linki (proste wykrywanie)
    formatted = formatted.replace(
      /(https?:\/\/[^\s]+)/g,
      '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>'
    );
    
    return formatted;
  }

  /**
   * Formatuje czas wiadomości - BEZ ZMIAN
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
   * Przewija do końca kontener wiadomości - BEZ ZMIAN
   */
  scrollToBottom() {
    if (this.messagesContainer) {
      this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }
  }

  /**
   * Aktualizuje liczbę nieprzeczytanych wiadomości - BEZ ZMIAN
   */
  updateUnreadCount(sessionToken) {
    const session = this.sessions.find(s => s.token === sessionToken);
    if (session) {
      session.unread_count = (session.unread_count || 0) + 1;
      this.renderFriendsList();
    }
  }

  /**
   * Odtwarza dźwięk powiadomienia - BEZ ZMIAN
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
   * Aktualizuje listę sesji - BEZ ZMIAN
   */
  updateSessionsList(sessions) {
    this.sessions = sessions || [];
    console.log(`📋 Zaktualizowano listę sesji: ${this.sessions.length} sesji`);
  }

  /**
   * POPRAWIONA: Renderuje listę znajomych z wskaźnikami sesji
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
   * POPRAWIONA: Tworzy element znajomego z wskaźnikami stanu sesji
   */
  createFriendElement(friend) {
    const li = document.createElement('li');
    li.className = 'friend-item';
    li.dataset.userId = friend.user_id;
    
    // Znajdź sesję dla tego znajomego
    const session = this.sessions.find(s => s.other_user.user_id === friend.user_id);
    const unreadCount = session?.unread_count || 0;
    
    // NOWE: Sprawdź stan sesji
    let sessionStatus = '';
    if (session) {
      if (session.is_ready) {
        sessionStatus = '<span class="session-ready">🔐</span>';
      } else if (session.needs_key_exchange) {
        sessionStatus = '<span class="session-pending">🔑</span>';
      }
    }
    
    li.innerHTML = `
      <div class="friend-avatar">
        <i class="fas fa-user"></i>
      </div>
      <div class="friend-info">
        <div class="friend-name">
          ${friend.username}
          ${sessionStatus}
        </div>
        <div class="friend-status ${friend.is_online ? 'online' : 'offline'}">
          ${friend.is_online ? 'Online' : 'Offline'}
        </div>
      </div>
      ${unreadCount > 0 ? `<div class="unread-count">${unreadCount}</div>` : ''}
    `;
    
    li.addEventListener('click', () => this.selectFriend(friend));
    
    return li;
  }
