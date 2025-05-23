/**
 * ChatInterface - ZAKTUALIZOWANA wersja interfejsu użytkownika czatu
 * Używa UnifiedCrypto i SocketIOHandler zamiast WebSocketHandler
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
    
    // Regularne aktualizacje i sprawdzanie zaproszeń
    setInterval(() => this.loadPendingRequests(), 30000);
    
    console.log("✅ ChatInterface zainicjalizowany z Socket.IO");
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

    // Nasłuchiwanie na zdarzenia z menedżera sesji - ZAKTUALIZOWANE dla Socket.IO
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
    
    console.log('✅ Wydarzenia zainicjalizowane');
  }

  /**
   * Ładuje dane użytkownika i dodaje przycisk panelu administratora jeśli potrzeba
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
   * Ładuje aktywne sesje czatu z serwera
   */
  async loadSessions() {
    try {
      if (!this.sessionManager) return;
      
      const result = await this.sessionManager.getActiveSessions();
      if (result.status === 'success') {
        this.updateSessionsList(result.sessions);
        
        // Wybierz pierwszą sesję, jeśli jest dostępna
        if (result.sessions.length > 0 && !this.currentSessionToken) {
          this.switchSession(result.sessions[0].token);
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
   * POPRAWIONA: Ładuje wiadomości dla sesji
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
      console.log('📥 Ładowanie wiadomości dla sesji:', sessionToken);
      
      // NAPRAWIONE: Użyj poprawionej metody getLocalMessages
      const result = this.sessionManager.getLocalMessages(sessionToken);
      
      console.log('📨 Wynik ładowania wiadomości:', result);
      
      if (result && result.status === 'success') {
        const messages = result.messages || [];
        console.log(`📝 Ładuję ${messages.length} wiadomości`);
        
        messages.forEach(message => {
          console.log('💬 Dodaję wiadomość:', {
            id: message.id,
            content: message.content?.substring(0, 50) + "...",
            sender_id: message.sender_id,
            is_mine: message.is_mine
          });
          this.addMessageToUI(message);
        });
        
        this.scrollToBottom();
        
        // Opcjonalnie: spróbuj pobrać nowsze wiadomości z serwera
        if (messages.length === 0) {
          console.log('📡 Brak lokalnych wiadomości, próbuję pobrać z serwera...');
          try {
            const serverResult = await this.sessionManager.fetchMessagesFromServer(sessionToken);
            if (serverResult.status === 'success' && serverResult.messages.length > 0) {
              console.log(`📥 Pobrano ${serverResult.messages.length} wiadomości z serwera`);
              // Przeładuj po pobraniu z serwera
              setTimeout(() => this.loadMessages(sessionToken), 100);
            }
          } catch (serverError) {
            console.warn('⚠️ Nie można pobrać z serwera:', serverError);
          }
        }
      } else {
        console.warn('⚠️ Brak wiadomości lub błąd:', result);
      }
    } catch (error) {
      console.error('❌ Błąd ładowania wiadomości:', error);
      console.error('❌ Stack trace:', error.stack);
      this.showNotification('Błąd ładowania wiadomości', 'error');
    }
  }

/**
   * ZAKTUALIZOWANE: Funkcja obsługująca wysyłanie wiadomości z UnifiedCrypto
   */
  async sendMessage() {
    const content = this.messageInput.value.trim();
    if (!content) return;
    
    // Sprawdź czy UnifiedCrypto jest dostępny
    if (!window.unifiedCrypto) {
      this.showNotification("Moduł kryptograficzny nie jest dostępny", "error");
      return;
    }
    
    // Zablokuj pole wprowadzania i przycisk wysyłania na czas wysyłania
    this.messageInput.disabled = true;
    this.sendButton.disabled = true;
    
    try {
      // Sprawdź, czy mamy token sesji
      if (!this.currentSessionToken) {
        console.error("❌ Brak aktywnej sesji");
        
        // Sprawdź, czy mamy wybrane jakieś okno czatu
        const activeItem = document.querySelector('.friend-item.active');
        if (activeItem) {
          this.showNotification("Błąd sesji czatu. Spróbuj odświeżyć stronę.", "error");
        } else {
          this.showNotification("Wybierz znajomego z listy, aby rozpocząć rozmowę", "info");
          
          // Automatycznie wybierz pierwszego znajomego
          if (this.friends && this.friends.length > 0) {
            try {
              await this.initSession(this.friends[0].user_id);
              setTimeout(() => this.sendMessage(), 500);
            } catch (e) {
              console.error("❌ Błąd automatycznego wyboru znajomego:", e);
            }
          }
        }
        return;
      }
      
      // Sprawdź gotowość sesji przed wysłaniem
      const isSessionReady = await this.ensureSessionReady();
      if (!isSessionReady) {
        return;
      }
      
      // Zapamiętaj treść na wypadek błędu
      const messageContent = content;
      
      // Wyczyść pole wprowadzania od razu
      this.messageInput.value = '';
      
      // ZAKTUALIZOWANE: Wyślij wiadomość przez menedżer sesji z UnifiedCrypto
      const result = await this.sessionManager.sendMessage(this.currentSessionToken, messageContent);
      
      if (result.status === 'success') {
        // Wiadomość została wysłana pomyślnie
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
    } finally {
      // Odblokuj pole wprowadzania i przycisk
      this.messageInput.disabled = false;
      this.sendButton.disabled = false;
      this.messageInput.focus();
    }
  }

  /**
   * ZAKTUALIZOWANE: Sprawdza, czy sesja jest gotowa do wysyłania wiadomości
   */
  async ensureSessionReady() {
    if (!this.currentSessionToken) {
      this.showNotification("Brak aktywnej sesji", "error");
      return false;
    }
    
    // NAPRAWIONE: Sprawdź, czy klucz sesji istnieje używając UnifiedCrypto
    if (!window.unifiedCrypto.hasSessionKey(this.currentSessionToken)) {
      try {
        // Znajdź sesję w liście
        const session = this.sessions.find(s => s.token === this.currentSessionToken);
        
        if (!session) {
          this.showNotification("Sesja nie istnieje", "error");
          return false;
        }
        
        // DODANO: Automatyczne generowanie klucza jeśli nie istnieje
        if (!session.has_key) {
          console.log("🔑 Generowanie nowego klucza sesji...");
          this.showNotification("Generowanie klucza szyfrowania...", "info", 2000);
          
          // Wygeneruj nowy klucz sesji AES
          const sessionKey = await window.unifiedCrypto.generateSessionKey();
          const sessionKeyBase64 = await window.unifiedCrypto.exportSessionKey(sessionKey);
          
          // Zapisz klucz lokalnie
          window.unifiedCrypto.storeSessionKey(this.currentSessionToken, sessionKeyBase64);
          
          // Pobierz klucz publiczny drugiego użytkownika
          const recipientPublicKeyResponse = await fetch(`/api/user/${session.other_user.user_id}/public_key`);
          if (!recipientPublicKeyResponse.ok) {
            throw new Error('Nie można pobrać klucza publicznego odbiorcy');
          }
          
          const recipientKeyData = await recipientPublicKeyResponse.json();
          const recipientPublicKey = await window.unifiedCrypto.importPublicKeyFromPEM(recipientKeyData.public_key);
          
          // Zaszyfruj klucz sesji kluczem publicznym odbiorcy
          const encryptedSessionKey = await window.unifiedCrypto.encryptSessionKey(recipientPublicKey, sessionKey);
          
          // Wyślij zaszyfrowany klucz na serwer
          const keyExchangeResponse = await fetch(`/api/session/${this.currentSessionToken}/exchange_key`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin',
            body: JSON.stringify({
              encrypted_key: encryptedSessionKey
            })
          });
          
          if (!keyExchangeResponse.ok) {
            throw new Error('Nie można wymienić klucza sesji');
          }
          
          const keyResult = await keyExchangeResponse.json();
          if (keyResult.status !== 'success') {
            throw new Error(keyResult.message || 'Błąd wymiany klucza');
          }
          
          console.log("✅ Klucz sesji wygenerowany i wysłany");
          this.showNotification("Klucz szyfrowania wygenerowany", "success", 2000);
          
          // Odśwież listę sesji
          await this.loadSessions();
          
          return true;
        }
        
        // Jeśli sesja ma klucz, ale my go nie mamy - pobierz go
        const result = await this.sessionManager.retrieveSessionKey(this.currentSessionToken);
        
        if (!result.success) {
          this.showNotification("Nie można pobrać klucza sesji: " + result.message, "error");
          return false;
        }
        
        // Sprawdź, czy klucz został pobrany
        if (!window.unifiedCrypto.hasSessionKey(this.currentSessionToken)) {
          this.showNotification("Nie udało się odszyfrować klucza sesji", "error");
          return false;
        }
      } catch (error) {
        console.error("❌ Błąd podczas generowania/pobierania klucza sesji:", error);
        this.showNotification("Błąd podczas konfiguracji szyfrowania: " + error.message, "error");
        return false;
      }
    }
    
    return true;
  }

/**
   * POPRAWIONA: Dodaje wiadomość do UI z debugowaniem
   */
  addMessageToUI(message) {
    console.log('🎨 addMessageToUI wywołane z:', {
      message: message,
      hasContainer: !!this.messagesContainer,
      containerExists: !!document.getElementById('messages'),
      currentUser: this.currentUser
    });
    
    if (!this.messagesContainer) {
      console.error('❌ messagesContainer nie istnieje!');
      // Spróbuj znaleźć ponownie
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
      const messageElement = this.createMessageElement(message);
      console.log('✅ Element wiadomości utworzony:', messageElement);
      
      this.messagesContainer.appendChild(messageElement);
      console.log('✅ Element dodany do kontenera');
      
      this.scrollToBottom();
      console.log('✅ Przewinięto do dołu');
      
      // Debug: sprawdź ile wiadomości jest teraz w kontenerze
      console.log('📊 Liczba wiadomości w kontenerze:', this.messagesContainer.children.length);
      
    } catch (error) {
      console.error('❌ Błąd w addMessageToUI:', error);
      console.error('❌ Stack trace:', error.stack);
    }
  }
  
  /**
   * POPRAWIONA: Tworzy element wiadomości z debugowaniem
   */
  createMessageElement(message) {
    console.log('🏗️ createMessageElement dla:', {
      content: message.content,
      sender_id: message.sender_id,
      current_user_id: this.currentUser?.id,
      timestamp: message.timestamp
    });
    
    const messageDiv = document.createElement('div');
    
    // Sprawdź czy to nasza wiadomość
    const isSent = message.sender_id === parseInt(this.currentUser.id) || message.is_mine;
    console.log('📤 Czy wiadomość wysłana przez nas?', {
      isSent,
      message_sender_id: message.sender_id,
      current_user_id: parseInt(this.currentUser.id),
      is_mine: message.is_mine
    });
    
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = message.content || '[Pusta wiadomość]';
    
    const infoDiv = document.createElement('div');
    infoDiv.className = 'message-info';
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = this.formatTime(message.timestamp);
    
    // Debug: sprawdź czy elementy są tworzone
    console.log('🔧 Elementy utworzone:', {
      messageDiv: !!messageDiv,
      contentDiv: !!contentDiv,
      infoDiv: !!infoDiv,
      timeSpan: !!timeSpan,
      content: contentDiv.textContent,
      className: messageDiv.className
    });
    
    infoDiv.appendChild(timeSpan);
    messageDiv.appendChild(contentDiv);
    messageDiv.appendChild(infoDiv);
    
    // Dodaj style inline dla pewności
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
    
    console.log('✅ Element wiadomości gotowy:', messageDiv);
    
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
   * POPRAWIONA: Wyświetla nową wiadomość - obsługa przychodzących wiadomości
   */
  displayNewMessage(sessionToken, message) {
    console.log('🆕 Otrzymano nową wiadomość:', {
      sessionToken,
      message: {
        id: message.id,
        content: message.content?.substring(0, 50) + "...",
        sender_id: message.sender_id
      },
      currentSession: this.currentSessionToken
    });
    
    // Jeśli to aktualna sesja, wyświetl od razu
    if (sessionToken === this.currentSessionToken) {
      console.log('📺 Wyświetlam wiadomość w aktualnej sesji');
      this.addMessageToUI(message);
    } else {
      // Jeśli to inna sesja, pokaż powiadomienie
      const session = this.sessions?.find(s => s.token === sessionToken);
      if (session) {
        console.log('🔔 Powiadomienie o wiadomości z innej sesji');
        this.showNotification(`Nowa wiadomość od ${session.other_user.username}`, 'info');
        
        // Dodaj wskaźnik nieprzeczytanych wiadomości
        this.updateUnreadIndicator(sessionToken);
      }
    }
  }

/**
   * Aktualizuje listę sesji
   */
  updateSessionsList(sessions) {
    this.sessions = sessions;
    this.renderFriendsList();
  }
  
  /**
   * Aktualizuje listę znajomych
   */
  updateFriendsList(friends) {
    this.friends = friends;
    this.renderFriendsList();
  }
  
  /**
   * Aktualizuje status online użytkowników
   */
  updateOnlineStatus(onlineUsers) {
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
      const userId = item.dataset.userId;
      const statusIndicator = item.querySelector('.status-indicator');
      
      if (!statusIndicator) return;
      
      if (onlineUsers.includes(userId)) {
        statusIndicator.classList.add('online');
        statusIndicator.classList.remove('offline');
      } else {
        statusIndicator.classList.add('offline');
        statusIndicator.classList.remove('online');
      }
    });
  }

  /**
   * Renderuje listę znajomych
   */
  renderFriendsList() {
    if (!this.friendsList) return;
    
    this.friendsList.innerHTML = '';
    
    if (this.sessions && this.sessions.length > 0) {
      this.sessions.forEach(session => {
        const otherUser = session.other_user;
        const listItem = this.createFriendListItem(otherUser, session.token);
        this.friendsList.appendChild(listItem);
      });
    }
    
    if (this.friends && this.friends.length > 0) {
      const friendsWithoutSession = this.friends.filter(friend => 
        !this.sessions || !this.sessions.some(session => 
          session.other_user.user_id === friend.user_id
        )
      );
      
      if (friendsWithoutSession.length > 0) {
        friendsWithoutSession.forEach(friend => {
          const listItem = this.createFriendListItem(friend);
          this.friendsList.appendChild(listItem);
        });
      }
    }
    
    if (this.friendsList.childElementCount === 0) {
      const emptyMessage = document.createElement('div');
      emptyMessage.className = 'empty-list-message';
      emptyMessage.textContent = 'Brak znajomych. Dodaj kogoś, aby rozpocząć rozmowę.';
      this.friendsList.appendChild(emptyMessage);
    }
  }

  /**
   * Tworzy element listy znajomych
   */
  createFriendListItem(user, sessionToken = null) {
    const li = document.createElement('li');
    li.className = 'friend-item';
    li.dataset.userId = user.user_id;
    
    if (sessionToken) {
      li.dataset.sessionToken = sessionToken;
      if (sessionToken === this.currentSessionToken) {
        li.classList.add('active');
      }
    }
    
    const avatarDiv = document.createElement('div');
    avatarDiv.className = 'friend-avatar';
    avatarDiv.textContent = user.username.charAt(0).toUpperCase();
    
    const statusIndicator = document.createElement('div');
    statusIndicator.className = 'status-indicator';
    statusIndicator.classList.add(user.is_online ? 'online' : 'offline');
    avatarDiv.appendChild(statusIndicator);
    
    const infoDiv = document.createElement('div');
    infoDiv.className = 'friend-info';
    
    const nameDiv = document.createElement('div');
    nameDiv.className = 'friend-name';
    nameDiv.textContent = user.username;
    infoDiv.appendChild(nameDiv);
    
    li.addEventListener('click', async () => {
      if (sessionToken) {
        this.switchSession(sessionToken);
      } else {
        await this.initSession(user.user_id);
      }
    });
    
    li.appendChild(avatarDiv);
    li.appendChild(infoDiv);
    return li;
  }

  /**
   * Inicjuje sesję czatu
   */
  async initSession(userId) {
    try {
      if (!this.sessionManager) {
        throw new Error("Brak menedżera sesji");
      }
      
      this.showNotification("Inicjalizacja sesji czatu...", "info", 2000);
      
      const result = await this.sessionManager.initSession(userId);
      
      if (result.success) {
        await this.loadSessions();
        this.switchSession(result.session.token);
      } else {
        this.showNotification(result.message || 'Błąd inicjacji sesji', 'error');
      }
    } catch (error) {
      console.error('❌ Błąd inicjacji sesji:', error);
      this.showNotification('Nie udało się rozpocząć rozmowy: ' + error.message, 'error');
    }
  }

  /**
   * POPRAWIONA: Przełącza aktywną sesję z wyczyszczeniem wskaźnika
   */
  switchSession(sessionToken) {
    if (!sessionToken || sessionToken === this.currentSessionToken) return;
    
    this.currentSessionToken = sessionToken;
    
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
      if (item.dataset.sessionToken === sessionToken) {
        item.classList.add('active');
        
        // Usuń wskaźnik nieprzeczytanych wiadomości
        const badge = item.querySelector('.unread-badge');
        if (badge) {
          badge.remove();
        }
      } else {
        item.classList.remove('active');
      }
    });
    
    const session = this.sessions.find(s => s.token === sessionToken);
    if (!session) {
      console.error(`❌ Nie znaleziono sesji o tokenie ${sessionToken}`);
      this.showNotification("Błąd: nie znaleziono sesji", "error");
      return;
    }
    
    if (this.chatHeader) {
      this.chatHeader.innerHTML = `<h2>${session.other_user.username}</h2>`;
      
      const statusSpan = document.createElement('span');
      statusSpan.className = `status-indicator ${session.other_user.is_online ? 'online' : 'offline'}`;
      statusSpan.style.display = 'inline-block';
      statusSpan.style.marginLeft = '10px';
      this.chatHeader.querySelector('h2').appendChild(statusSpan);
    }
    
    this.loadMessages(sessionToken);
  }

  /**
   * DODANA: Aktualizacja wskaźnika nieprzeczytanych wiadomości
   */
  updateUnreadIndicator(sessionToken) {
    const friendItem = document.querySelector(`[data-session-token="${sessionToken}"]`);
    if (friendItem) {
      let badge = friendItem.querySelector('.unread-badge');
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'unread-badge';
        badge.style.cssText = `
          background: #ff4444;
          color: white;
          border-radius: 50%;
          width: 20px;
          height: 20px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 12px;
          margin-left: auto;
          font-weight: bold;
        `;
        friendItem.appendChild(badge);
      }
      
      const currentCount = parseInt(badge.textContent) || 0;
      badge.textContent = currentCount + 1;
      badge.style.display = 'flex';
    }
  }

/**
   * Wyświetla powiadomienie
   */
  showNotification(message, type = 'info', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Stylizacja
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.padding = '15px 20px';
    notification.style.borderRadius = '5px';
    notification.style.zIndex = '10000';
    notification.style.maxWidth = '300px';
    notification.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';
    
    // Kolory w zależności od typu
    switch(type) {
      case 'success':
        notification.style.backgroundColor = '#4CAF50';
        notification.style.color = 'white';
        break;
      case 'error':
        notification.style.backgroundColor = '#F44336';
        notification.style.color = 'white';
        break;
      case 'warning':
        notification.style.backgroundColor = '#FF9800';
        notification.style.color = 'white';
        break;
      default:
        notification.style.backgroundColor = '#2196F3';
        notification.style.color = 'white';
    }
    
    document.body.appendChild(notification);
    
    // Usuń po określonym czasie
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, duration);
  }

  /**
   * Wysyła zaproszenie do znajomych
   */
  async sendFriendRequest() {
    const usernameInput = document.getElementById('friend-user-id');
    const statusDiv = document.getElementById('friend-request-status');
    
    if (!usernameInput || !statusDiv) {
      console.error('❌ Brak elementów UI dla wysyłania zaproszeń');
      return;
    }
    
    const username = usernameInput.value.trim();
    if (!username) {
      statusDiv.textContent = 'Wprowadź nazwę użytkownika';
      statusDiv.className = 'search-status search-error';
      statusDiv.style.display = 'block';
      return;
    }
    
    try {
      statusDiv.textContent = 'Wysyłanie zaproszenia...';
      statusDiv.className = 'search-status';
      statusDiv.style.display = 'block';
      
      if (!this.sessionManager) {
        throw new Error('Menedżer sesji nie jest dostępny');
      }
      
      const result = await this.sessionManager.sendFriendRequest(username);
      
      if (result.success) {
        statusDiv.textContent = result.message;
        statusDiv.className = 'search-status search-success';
        usernameInput.value = '';
        
        // Odśwież listę znajomych
        await this.loadFriends();
        
        // Zamknij modal po chwili
        setTimeout(() => {
          const modal = document.getElementById('add-friend-modal');
          if (modal) modal.style.display = 'none';
        }, 2000);
      } else {
        statusDiv.textContent = result.message;
        statusDiv.className = 'search-status search-error';
      }
    } catch (error) {
      console.error('❌ Błąd wysyłania zaproszenia:', error);
      statusDiv.textContent = 'Błąd wysyłania zaproszenia: ' + error.message;
      statusDiv.className = 'search-status search-error';
    }
  }

  /**
   * Ładuje oczekujące zaproszenia
   */
  async loadPendingRequests() {
    if (!this.sessionManager) return;
    
    try {
      const result = await this.sessionManager.getPendingFriendRequests();
      if (result.success) {
        this.pendingRequests = result.requests;
        this.updateRequestBadge();
      }
    } catch (error) {
      console.error('❌ Błąd ładowania zaproszeń:', error);
    }
  }

  /**
   * Aktualizuje badge z liczbą zaproszeń
   */
  updateRequestBadge() {
    if (this.requestBadge) {
      const count = this.pendingRequests.length;
      if (count > 0) {
        this.requestBadge.textContent = count;
        this.requestBadge.style.display = 'inline-block';
      } else {
        this.requestBadge.style.display = 'none';
      }
    }
  }

  /**
   * Inicjalizuje powiadomienia o zaproszeniach
   */
  initializeFriendRequestNotifications() {
    this.loadPendingRequests();
  }

  /**
   * Pokazuje modal z zaproszeniami do znajomych
   */
  showFriendRequestsModal() {
    console.log('Wyświetlanie modalu zaproszeń:', this.pendingRequests);
    // Implementacja modalu zaproszeń - można rozszerzyć
    if (this.pendingRequests.length > 0) {
      const requestsList = this.pendingRequests.map(req => 
        `${req.sender_username} (${req.created_at})`
      ).join('\n');
      
      if (confirm(`Masz ${this.pendingRequests.length} oczekujących zaproszeń:\n${requestsList}\n\nCzy chcesz przejść do panelu zarządzania?`)) {
        // Można przekierować do dedykowanego panelu
        window.location.href = '/friends';
      }
    } else {
      this.showNotification('Brak oczekujących zaproszeń', 'info');
    }
  }

  /**
   * DODANA: Funkcja testowa do dodawania wiadomości
   */
  testAddMessage() {
    console.log('🧪 Test dodawania wiadomości...');
    
    const testMessage = {
      id: 'test-' + Date.now(),
      content: 'To jest wiadomość testowa',
      sender_id: parseInt(this.currentUser.id),
      timestamp: new Date().toISOString(),
      is_mine: true
    };
    
    console.log('📨 Dodaję wiadomość testową:', testMessage);
    this.addMessageToUI(testMessage);
  }
}

// Inicjalizacja globalnego interfejsu
window.chatInterface = new ChatInterface();
