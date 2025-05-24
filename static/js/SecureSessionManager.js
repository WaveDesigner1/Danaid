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
    setInterval(() => this.refreshActiveSessions(), 60000);
    
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
   * Ładuje listę znajomych
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
   * POPRAWIONA: Wybiera znajomego i automatycznie inicjuje sesję z wymianą kluczy
   */
  async selectFriend(friend) {
    console.log('👤 Wybrano znajomego:', friend.username);
    
    try {
      // Pokaż wskaźnik ładowania
      this.showSessionStatus("Łączenie z " + friend.username + "...", "loading");
      
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
          <div class="chat-header-info">
            <h3>${friend.username}</h3>
            <span class="status ${friend.is_online ? 'online' : 'offline'}">
              ${friend.is_online ? 'Online' : 'Offline'}
            </span>
          </div>
          <div class="session-status" id="session-status">
            <span class="status-text">Inicjalizacja...</span>
          </div>
        `;
      }
      
      // NOWE: Wyłącz pole wprowadzania do czasu zakończenia wymiany kluczy
      if (this.messageInput) {
        this.messageInput.disabled = true;
        this.messageInput.placeholder = "Przygotowywanie szyfrowania...";
      }
      
      if (this.sendButton) {
        this.sendButton.disabled = true;
      }
      
      // Inicjuj sesję z automatyczną wymianą kluczy
      const result = await this.sessionManager.initSession(friend.user_id);
      
      if (result.status === 'success') {
        this.currentSessionToken = result.session_token;
        console.log('✅ Sesja zainicjalizowana:', this.currentSessionToken?.substring(0, 10) + '...');
        
        // Zapisz stan sesji
        this.sessionStates[this.currentSessionToken] = {
          friendId: friend.user_id,
          friendUsername: friend.username,
          isReady: result.session?.is_ready || false,
          needsKeyExchange: result.session?.needs_key_exchange || false,
          keyExchangeCompleted: result.session?.is_ready || false
        };
        
        // Załaduj wiadomości dla tej sesji
        await this.loadMessages(this.currentSessionToken);
        
        // Sprawdź stan wymiany kluczy
        await this.checkSessionReadiness();
        
        // Wyczyść licznik nieprzeczytanych dla tej sesji
        const session = this.sessions.find(s => s.token === this.currentSessionToken);
        if (session) {
          session.unread_count = 0;
          this.renderFriendsList();
        }
        
      } else {
        console.error('❌ Błąd inicjalizacji sesji:', result.message);
        this.showNotification(result.message || 'Błąd inicjalizacji sesji', 'error');
        this.showSessionStatus("Błąd połączenia", "error");
        
        // Przywróć pole wprowadzania
        if (this.messageInput) {
          this.messageInput.disabled = false;
          this.messageInput.placeholder = "Napisz wiadomość...";
        }
        
        if (this.sendButton) {
          this.sendButton.disabled = false;
        }
      }
    } catch (error) {
      console.error('❌ Błąd wyboru znajomego:', error);
      this.showNotification('Błąd inicjalizacji czatu', 'error');
      this.showSessionStatus("Błąd", "error");
    }
  }

  /**
   * NOWA: Sprawdza gotowość sesji i aktualizuje UI
   */
  async checkSessionReadiness() {
    if (!this.currentSessionToken) return;
    
    try {
      const response = await fetch(`/api/session/${this.currentSessionToken}/validate`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (response.ok) {
        const data = await response.json();
        
        if (data.status === 'success' && data.session) {
          const session = data.session;
          
          // Aktualizuj stan sesji
          if (this.sessionStates[this.currentSessionToken]) {
            this.sessionStates[this.currentSessionToken].isReady = session.is_ready || false;
            this.sessionStates[this.currentSessionToken].needsKeyExchange = session.needs_key_exchange || false;
            this.sessionStates[this.currentSessionToken].keyExchangeCompleted = !session.needs_key_exchange;
          }
          
          // Pokaż odpowiedni status
          if (session.is_ready) {
            this.showSessionStatus("🔐 Bezpieczne połączenie", "ready");
            
            // Włącz pole wprowadzania
            if (this.messageInput) {
              this.messageInput.disabled = false;
              this.messageInput.placeholder = "Napisz wiadomość...";
              this.messageInput.focus();
            }
            
            if (this.sendButton) {
              this.sendButton.disabled = false;
            }
          } else if (session.needs_key_exchange) {
            if (session.is_initiator) {
              this.showSessionStatus("🔑 Generowanie kluczy...", "loading");
            } else {
              this.showSessionStatus("🔑 Oczekiwanie na klucze...", "waiting");
            }
          }
        }
      }
    } catch (error) {
      console.error('❌ Błąd sprawdzania gotowości sesji:', error);
    }
  }

  /**
   * NOWA: Pokazuje status sesji w nagłówku
   */
  showSessionStatus(message, type = "info") {
    const statusElement = document.getElementById('session-status');
    if (statusElement) {
      const statusText = statusElement.querySelector('.status-text');
      if (statusText) {
        statusText.textContent = message;
        
        // Usuń poprzednie klasy statusu
        statusElement.classList.remove('loading', 'waiting', 'ready', 'error');
        
        // Dodaj nową klasę
        if (type) {
          statusElement.classList.add(type);
        }
      }
    }
  }

/**
   * POPRAWIONA: Wysyłanie wiadomości z kontrolą gotowości sesji
   */
  async sendMessage() {
    const content = this.messageInput.value.trim();
    if (!content) return;
    
    // Sprawdź czy UnifiedCrypto jest dostępny
    if (!window.unifiedCrypto) {
      this.showNotification("Moduł kryptograficzny nie jest dostępny", "error");
      return;
    }
    
    // Sprawdź czy mamy aktywną sesję
    if (!this.currentSessionToken) {
      this.showNotification("Brak aktywnej sesji czatu", "error");
      return;
    }
    
    // NOWE: Sprawdź czy sesja jest gotowa
    const sessionState = this.sessionStates[this.currentSessionToken];
    if (sessionState && !sessionState.keyExchangeCompleted) {
      this.showNotification("Poczekaj na zakończenie wymiany kluczy", "warning");
      return;
    }
    
    // Zablokuj pole wprowadzania na czas wysyłania
    this.messageInput.disabled = true;
    this.sendButton.disabled = true;
    
    try {
      // Zapamiętaj treść na wypadek błędu
      const messageContent = content;
      
      // Wyczyść pole wprowadzania od razu
      this.messageInput.value = '';
      
      // Wyślij wiadomość przez menedżer sesji
      const result = await this.sessionManager.sendMessage(this.currentSessionToken, messageContent);
      
      if (result.status === 'success') {
        console.log("✅ Wiadomość wysłana pomyślnie");
        
        // Dodaj wiadomość do UI od razu (optymistyczne UI)
        const newMessage = {
          id: result.messageData?.id || Date.now().toString(),
          sender_id: parseInt(this.currentUser.id),
          content: messageContent,
          timestamp: result.messageData?.timestamp || new Date().toISOString(),
          is_mine: true
        };
        
        this.addMessageToUI(newMessage);
        
      } else {
        // Przywróć treść w przypadku błędu
        this.messageInput.value = messageContent;
        this.showNotification(result.message || 'Błąd wysyłania wiadomości', "error");
      }
      
    } catch (error) {
      console.error('❌ Błąd wysyłania wiadomości:', error);
      this.showNotification('Nie udało się wysłać wiadomości: ' + error.message, "error");
      
      // Przywróć treść w przypadku błędu
      this.messageInput.value = content;
      
    } finally {
      // Odblokuj pole wprowadzania
      this.messageInput.disabled = false;
      this.sendButton.disabled = false;
      this.messageInput.focus();
    }
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
        
        .session-status.loading .status-text::after {
          content: '...';
          animation: dots 1.5s infinite;
        }
        
        .session-status.ready {
          color: #28a745;
        }
        
        .session-status.waiting {
          color: #ffc107;
        }
        
        .session-status.error {
          color: #dc3545;
        }
        
        @keyframes dots {
          0%, 33% { content: '...'; }
          34%, 66% { content: '....'; }
          67%, 100% { content: '.....'; }
        }
        
        .chat-header-info {
          display: flex;
          align-items: center;
          gap: 15px;
        }
        
        .chat-header-info h3 {
          margin: 0;
          font-size: 1.2em;
        }
        
        .chat-header-info .status {
          font-size: 0.9em;
          font-weight: 500;
        }
        
        .chat-header-info .status.online {
          color: #28a745;
        }
        
        .chat-header-info .status.offline {
          color: #6c757d;
        }
        
        .session-ready {
          color: #28a745;
          margin-left: 5px;
        }
        
        .session-pending {
          color: #ffc107;
          margin-left: 5px;
          animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
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
      session.unread_count = (session.unread_count || 0) + 1erenFriendsList();
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

  /**
   * Przełącza na wybraną sesję
   */
  async switchSession(sessionToken) {
    console.log('🔄 Przełączanie na sesję:', sessionToken);
    
    this.currentSessionToken = sessionToken;
    await this.loadMessages(sessionToken);
    
    // Znajdź użytkownika tej sesji i zaktualizuj UI
    const session = this.sessions.find(s => s.token === sessionToken);
    if (session) {
      const friend = this.friends.find(f => f.user_id === session.other_user.user_id);
      if (friend) {
        this.selectFriend(friend);
      }
    }
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
   * Inicjalizuje powiadomienia o zaproszeniach
   */
  initializeFriendRequestNotifications() {
    this.loadPendingRequests();
  }

  /**
   * Ładuje oczekujące zaproszenia
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
   * Aktualizuje wskaźnik zaproszeń
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
   * Pokazuje modal z zaproszeniami
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
              <strong>${request.username}</strong>
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
   * Akceptuje zaproszenie
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
   * Odrzuca zaproszenie
   */
  async declineFriendRequest(requestId) {
    try {
      const response = await fetch(`/api/friend_requests/${requestId}/reject`, {
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
      animation: slideInRight 0.3s ease-out;
    `;
    
    // Dodaj animację slideInRight jeśli nie istnieje
    if (!document.getElementById('notification-animations')) {
      const style = document.createElement('style');
      style.id = 'notification-animations';
      style.textContent = `
        @keyframes slideInRight {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        
        @keyframes slideOutRight {
          from {
            transform: translateX(0);
            opacity: 1;
          }
          to {
            transform: translateX(100%);
            opacity: 0;
          }
        }
        
        .notification.slide-out {
          animation: slideOutRight 0.3s ease-in;
        }
      `;
      document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Usuń po określonym czasie z animacją
    setTimeout(() => {
      notification.classList.add('slide-out');
      setTimeout(() => {
        if (notification.parentNode) {
          notification.parentNode.removeChild(notification);
        }
      }, 300);
    }, duration);
  }
}

// Eksportuj klasę
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ChatInterface;
} else {
  window.ChatInterface = ChatInterface;
}

console.log("✅ ChatInterface załadowany - gotowy do użycia z automatyczną wymianą kluczy i real-time messaging");

/**
   * POPRAWIONA: Wysyłanie wiadomości z obsługą szyfrowania
   */
  async sendMessage(sessionToken, content) {
    try {
      if (!sessionToken || !content) {
        throw new Error('Sessional token i treść wiadomości są wymagane');
      }

      console.log('📤 Wysyłanie wiadomości:', {
        sessionToken: sessionToken?.substring(0, 10) + '...',
        contentLength: content.length
      });

      // Sprawdź czy mamy klucz sesji
      if (!window.unifiedCrypto.hasSessionKey(sessionToken)) {
        throw new Error('Brak klucza sesji - wymiana kluczy nie została zakończona');
      }

      // Pobierz klucz sesji
      const sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
      const sessionKey = await window.unifiedCrypto.importSessionKey(sessionKeyBase64);

      // Zaszyfruj wiadomość
      const encryptedData = await window.unifiedCrypto.encryptMessage(sessionKey, content);

      // Wyślij zaszyfrowaną wiadomość
      const response = await fetch('/api/message/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          session_token: sessionToken,
          encrypted_content: encryptedData.data,
          iv: encryptedData.iv
        })
      });

      if (!response.ok) {
        throw new Error(`Błąd wysyłania wiadomości: ${response.status}`);
      }

      const result = await response.json();

      if (result.status === 'success') {
        // Zapisz wiadomość lokalnie
        const messageToStore = {
          id: result.message_id,
          sender_id: parseInt(this.user.id),
          content: content, // Niezaszyfrowana treść lokalnie
          timestamp: result.timestamp || new Date().toISOString(),
          is_mine: true
        };

        await this.storeMessage(sessionToken, messageToStore);

        console.log('✅ Wiadomość wysłana i lokalnie zapisana');

        return {
          status: 'success',
          messageData: messageToStore
        };
      } else {
        throw new Error(result.message || 'Błąd wysyłania wiadomości');
      }

    } catch (error) {
      console.error('❌ Błąd wysyłania wiadomości:', error);
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  /**
   * NOWA: Pobieranie wiadomości z serwera z deszyfrowaniem
   */
  async fetchMessagesFromServer(sessionToken) {
    try {
      console.log('📥 Pobieranie wiadomości z serwera dla:', sessionToken?.substring(0, 10) + '...');

      const response = await fetch(`/api/session/${sessionToken}/messages`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });

      if (!response.ok) {
        throw new Error(`Błąd pobierania wiadomości: ${response.status}`);
      }

      const data = await response.json();

      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania wiadomości');
      }

      const messages = data.messages || [];
      const decryptedMessages = [];

      // Pobierz klucz sesji
      const sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
      const sessionKey = sessionKeyBase64 ? 
        await window.unifiedCrypto.importSessionKey(sessionKeyBase64) : null;

      // Odszyfruj każdą wiadomość
      for (const message of messages) {
        try {
          if (message.content && message.iv && sessionKey) {
            const decryptedContent = await window.unifiedCrypto.decryptMessage(sessionKey, {
              data: message.content,
              iv: message.iv
            });
            
            message.content = decryptedContent;
            console.log('✅ Wiadomość odszyfrowana z serwera');
          } else if (message.content && !message.iv) {
            // Stara wiadomość bez szyfrowania lub błąd
            message.content = '[Nie można odszyfrować - brak IV]';
            message.decryption_error = true;
          }
          
          decryptedMessages.push(message);
          
          // Zapisz wiadomość lokalnie
          await this.storeMessage(sessionToken, message);
          
        } catch (decryptError) {
          console.error('❌ Błąd deszyfrowania wiadomości:', decryptError);
          message.content = '[Błąd deszyfrowania]';
          message.decryption_error = true;
          decryptedMessages.push(message);
        }
      }

      console.log(`📨 Pobrano i odszyfrowano ${decryptedMessages.length} wiadomości z serwera`);

      return {
        status: 'success',
        messages: decryptedMessages
      };

    } catch (error) {
      console.error('❌ Błąd pobierania wiadomości z serwera:', error);
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  /**
   * Pobieranie znajomych
   */
  async fetchFriends() {
    try {
      const response = await fetch('/api/friends', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });

      if (!response.ok) {
        throw new Error(`Błąd pobierania znajomych: ${response.status}`);
      }

      const data = await response.json();

      if (data.status === 'success') {
        this.friends = data.friends || [];
        
        if (this.onFriendsUpdated) {
          this.onFriendsUpdated(this.friends);
        }

        return {
          status: 'success',
          friends: this.friends
        };
      } else {
        throw new Error(data.message || 'Błąd pobierania znajomych');
      }

    } catch (error) {
      console.error('❌ Błąd pobierania znajomych:', error);
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  /**
   * Aktualizacja statusu online pojedynczego użytkownika
   */
  updateOnlineStatus(userId, isOnline) {
    if (isOnline) {
      if (!this.onlineUsers.includes(userId)) {
        this.onlineUsers.push(userId);
      }
    } else {
      this.onlineUsers = this.onlineUsers.filter(id => id !== userId);
    }

    // Aktualizuj status w liście znajomych
    const friend = this.friends.find(f => f.user_id === userId);
    if (friend) {
      friend.is_online = isOnline;
    }

    if (this.onOnlineStatusChanged) {
      this.onOnlineStatusChanged(this.onlineUsers);
    }
  }

  /**
   * Wylogowanie użytkownika
   */
  async logout() {
    try {
      console.log('🚪 SecureSessionManager: Rozpoczynam wylogowanie...');
      
      // Wyczyść lokalne dane
      this.activeSessions = [];
      this.friends = [];
      this.onlineUsers = [];
      this.messages = {};
      this.currentSessionId = null;
      this.keyExchangeInProgress.clear();

      // Wyczyść klucze kryptograficzne
      if (window.unifiedCrypto) {
        window.unifiedCrypto.clearAllKeys();
      }

      // Rozłącz Socket.IO
      if (window.wsHandler) {
        window.wsHandler.disconnect();
      }

      // Wyczyść pamięć przeglądarki
      localStorage.clear();
      sessionStorage.clear();

      // Wyloguj na serwerze
      const response = await fetch('/logout', {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });

      console.log('✅ Wylogowanie zakończone - przekierowanie...');
      
      // Przekieruj do strony logowania
      window.location.href = '/login';

    } catch (error) {
      console.error('❌ Błąd podczas wylogowania:', error);
      
      // Wymuś przekierowanie nawet w przypadku błędu
      window.location.href = '/logout';
    }
  }

  /**
   * Sprawdź czy użytkownik jest zalogowany
   */
  isLoggedIn() {
    return this.user.isLoggedIn && this.user.id;
  }

  /**
   * Pobierz informacje o aktualnym użytkowniku
   */
  getCurrentUser() {
    return this.user;
  }

  /**
   * Sprawdź czy sesja jest gotowa do messaging
   */
  isSessionReady(sessionToken) {
    const session = this.activeSessions.find(s => s.token === sessionToken);
    return session ? session.is_ready : false;
  }

  /**
   * Pobierz aktywną sesję po tokenie
   */
  getActiveSession(sessionToken) {
    return this.activeSessions.find(s => s.token === sessionToken);
  }

  /**
   * Pobierz wszystkie wiadomości dla sesji
   */
  getAllMessages(sessionToken) {
    return this.messages[sessionToken] || [];
  }

  /**
   * Wyczyść wiadomości dla sesji
   */
  clearMessages(sessionToken) {
    if (this.messages[sessionToken]) {
      delete this.messages[sessionToken];
    }
  }

  /**
   * Sprawdź czy wymiana kluczy jest w toku
   */
  isKeyExchangeInProgress(sessionToken) {
    return this.keyExchangeInProgress.has(sessionToken);
  }
}

// Globalna inicjalizacja
document.addEventListener('DOMContentLoaded', () => {
  console.log('🚀 Inicjalizacja SecureSessionManager...');
  
  // Utwórz globalną instancję menedżera sesji
  window.sessionManager = new SecureSessionManager();
  
  // Poczekaj na pełne załadowanie wszystkich modułów
  const initializationCheck = setInterval(() => {
    if (window.unifiedCrypto && window.wsHandler) {
      console.log('✅ Wszystkie moduły załadowane - SecureSessionManager gotowy');
      clearInterval(initializationCheck);
      
      // Można dodać dodatkową inicjalizację tutaj
      if (window.sessionManager.isLoggedIn()) {
        console.log('👤 Użytkownik zalogowany - pobieranie danych...');
        window.sessionManager.fetchFriends();
        window.sessionManager.getActiveSessions();
      }
    }
  }, 100);
  
  // Timeout po 10 sekundach
  setTimeout(() => {
    clearInterval(initializationCheck);
    if (!window.unifiedCrypto || !window.wsHandler) {
      console.error('❌ Nie udało się załadować wszystkich modułów w czasie 10 sekund');
    }
  }, 10000);
});

// Eksportuj klasę
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecureSessionManager;
} else {
  window.SecureSessionManager = SecureSessionManager;
}

console.log("✅ SecureSessionManager załadowany z automatyczną wymianą kluczy i real-time messaging");

