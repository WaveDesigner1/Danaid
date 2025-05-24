**
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

    // DODANE: Obsługa przycisku wylogowania
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
      // Jeśli to inna sesja, zaktualizuj wskaźnik nieprzeczytanych wiadomości
      console.log('📊 Wiadomość w innej sesji - aktualizuję wskaźniki');
      this.updateUnreadCount(sessionToken);
    }
    
    // Odtwórz dźwięk powiadomienia (jeśli włączony)
    this.playNotificationSound();
  }

  /**
   * Aktualizuje liczbę nieprzeczytanych wiadomości dla sesji
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
    // Sprawdź czy użytkownik ma włączone powiadomienia dźwiękowe
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
    const session = this.sessions.find(s => s.other_user.user_id === friend.user_id);
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
   * Wybiera znajomego i inicjuje sesję czatu
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
      await this.initSession(friend.user_id);
    } catch (error) {
      console.error('❌ Błąd wyboru znajomego:', error);
      this.showNotification('Błąd inicjalizacji czatu', 'error');
    }
  }

  /**
   * Inicjuje sesję czatu z danym użytkownikiem
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
   * Pokazuje modal z zaproszeniami do znajomych
   */
  showFriendRequestsModal() {
    // Implementacja modala z zaproszeniami
    console.log('📨 Pokazuję modal z zaproszeniami');
    // Tutaj byłaby implementacja modala
  }

  /**
   * Pokazuje powiadomienie
   */
  showNotification(message, type = 'info', duration = 5000) {
    console.log(`📢 Powiadomienie [${type}]:`, message);
    
    // Utwórz element powiadomienia
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Dodaj style
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
    
    // Usuń po określonym czasie
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
