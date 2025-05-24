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
   * POPRAWIONA: Inicjuje sesję czatu (używana wewnętrznie)
   */
  async initSession(userId) {
    try {
      console.log('🚀 Inicjalizacja sesji z użytkownikiem:', userId);
      
      const result = await this.sessionManager.initSession(userId);
      
      if (result.status === 'success') {
        this.currentSessionToken = result.session_token;
        console.log('✅ Sesja zainicjalizowana:', this.currentSessionToken);
        
        // Załaduj wiadomości dla tej sesji
        await this.loadMessages(this.currentSessionToken);
        
        // Sprawdź gotowość sesji
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
      }
    } catch (error) {
      console.error('❌ Błąd initSession:', error);
      this.showNotification('Błąd połączenia z serwerem', 'error');
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
          sender_id: parseInt(this.currentuser.id),
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
    contentDiv.textContent = message.content || '[Pusta wiadomość]';
    
    const infoDiv = document.createElement('div');
    infoDiv.className = 'message-info';
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = this.formatTime(message.timestamp);
    
    infoDiv.appendChild(timeSpan);
    messageDiv.appendChild(contentDiv);
    messageDiv.appendChild(infoDiv);
    
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
   * Przełącza na wybraną sesję - BEZ ZMIAN
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
   * Aktualizuje status online użytkowników - BEZ ZMIAN
   */
  updateOnlineStatus(onlineUsers) {
    console.log('🟢 Aktualizacja statusu online:', onlineUsers);
    
    this.friends.forEach(friend => {
      friend.is_online = onlineUsers.includes(friend.user_id);
    });
    
    this.renderFriendsList();
  }

  /**
   * Aktualizuje listę znajomych - BEZ ZMIAN
   */
  updateFriendsList(friends) {
    this.friends = friends || [];
    this.renderFriendsList();
    console.log(`👥 Zaktualizowano listę znajomych: ${this.friends.length} znajomych`);
  }

  /**
   * Inicjalizuje powiadomienia o zaproszeniach - BEZ ZMIAN
   */
  initializeFriendRequestNotifications() {
    this.loadPendingRequests();
  }

  /**
   * Ładuje oczekujące zaproszenia - BEZ ZMIAN
   */
  async loadPendingRequests() {
    try {
      const response = await fetch('/api/friends/requests/pending', {
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
   * Aktualizuje wskaźnik zaproszeń - BEZ ZMIAN
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
   * Wysyła zaproszenie do znajomego - BEZ ZMIAN
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
      const response = await fetch('/api/friends/request', {
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
   * Pokazuje modal z zaproszeniami - BEZ ZMIAN
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
   * Akceptuje zaproszenie - BEZ ZMIAN
   */
  async acceptFriendRequest(requestId) {
    try {
      const response = await fetch(`/api/friends/request/${requestId}/accept`, {
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
   * Odrzuca zaproszenie - BEZ ZMIAN
   */
  async declineFriendRequest(requestId) {
    try {
      const response = await fetch(`/api/friends/request/${requestId}/decline`, {
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
   * Pokazuje powiadomienie - BEZ ZMIAN
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

// Eksportuj klasę
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ChatInterface;
} else {
  window.ChatInterface = ChatInterface;
}
