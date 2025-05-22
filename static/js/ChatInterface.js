/**
 * ChatInterface - Ujednolicony interfejs użytkownika czatu
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
  this.pendingRequests = [];
  
  // Załaduj konfigurację WebSocket, a następnie zainicjuj interfejs
  this.loadWebSocketConfig().then(() => {
    // Inicjalizacja 
    this.initializeEvents();
    this.loadUserData();
    this.initializeFriendRequestNotifications();
    this.loadFriends();
    this.loadSessions();
  });
  
  // Regularne aktualizacje i sprawdzanie zaproszeń
  setInterval(() => this.loadPendingRequests(), 30000);
}

/**
 * Ładuje konfigurację WebSocket
 */
async loadWebSocketConfig() {
  try {
    const response = await fetch('/api/websocket/config');
    if (response.ok) {
      const config = await response.json();
      if (config && config.wsUrl) {
        window._env = window._env || {};
        window._env.wsUrl = config.wsUrl;
        console.log('Pobrano konfigurację WebSocket:', config.wsUrl);
      }
    }
  } catch (e) {
    console.warn('Nie udało się pobrać konfiguracji WebSocket:', e);
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
    this.adminLink = document.createElement('a');
    this.adminLink.id = 'admin-panel-link';
    this.adminLink.innerHTML = '<i class="fas fa-cog"></i> Admin Panel';
    this.adminLink.style.marginLeft = '15px';
    this.adminLink.classList.add('admin-btn');
    this.adminLink.href = '/admin_dashboard';
  }
  
  /**
   * Inicjalizacja nasłuchiwania zdarzeń
   */
  initializeEvents() {
    // Sprawdź, czy wszystkie elementy DOM istnieją
    if (!this.friendsList || !this.messagesContainer || !this.messageInput || 
        !this.sendButton || !this.addFriendBtn || !this.chatHeader) {
      console.error('Brak wymaganych elementów DOM');
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

    // Nasłuchiwanie na zdarzenia z menedżera sesji
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
      console.error('Brak ID użytkownika');
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
      } else {
        this.showNotification('Błąd ładowania znajomych', 'error');
      }
    } catch (error) {
      console.error('Błąd ładowania znajomych:', error);
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
      } else {
        this.showNotification('Błąd ładowania sesji czatu', 'error');
      }
    } catch (error) {
      console.error('Błąd ładowania sesji:', error);
      this.showNotification('Błąd ładowania sesji czatu', 'error');
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
    // Aktualizuj wskaźniki statusu online w interfejsie
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
   * Renderuje listę znajomych i sesji czatu
   */
  renderFriendsList() {
    if (!this.friendsList) return;
    
    // Wyczyść listę
    this.friendsList.innerHTML = '';
    
    // Dodaj aktywne sesje
    if (this.sessions && this.sessions.length > 0) {
      this.sessions.forEach(session => {
        const otherUser = session.other_user;
        const listItem = this.createFriendListItem(otherUser, session.token);
        this.friendsList.appendChild(listItem);
      });
    }
    
    // Dodaj znajomych bez aktywnych sesji
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
    
    // Jeśli lista jest pusta, pokaż komunikat
    if (this.friendsList.childElementCount === 0) {
      const emptyMessage = document.createElement('div');
      emptyMessage.className = 'empty-list-message';
      emptyMessage.textContent = 'Brak znajomych. Dodaj kogoś, aby rozpocząć rozmowę.';
      this.friendsList.appendChild(emptyMessage);
    }
  }

  /**
   * Tworzy element listy dla znajomego/sesji
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
    
    // Avatar i status
    const avatarDiv = document.createElement('div');
    avatarDiv.className = 'friend-avatar';
    avatarDiv.textContent = user.username.charAt(0).toUpperCase();
    
    const statusIndicator = document.createElement('div');
    statusIndicator.className = 'status-indicator';
    statusIndicator.classList.add(user.is_online ? 'online' : 'offline');
    avatarDiv.appendChild(statusIndicator);
    
    // Informacje o użytkowniku
    const infoDiv = document.createElement('div');
    infoDiv.className = 'friend-info';
    
    const nameDiv = document.createElement('div');
    nameDiv.className = 'friend-name';
    nameDiv.textContent = user.username;
    infoDiv.appendChild(nameDiv);
    
    // Obsługa kliknięcia
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
   * Inicjuje nową sesję czatu z użytkownikiem
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
      console.error('Błąd inicjacji sesji:', error);
      this.showNotification('Nie udało się rozpocząć rozmowy: ' + error.message, 'error');
    }
  }

  /**
   * Przełącza aktywną sesję
   */
  switchSession(sessionToken) {
    if (!sessionToken || sessionToken === this.currentSessionToken) return;
    
    // Zapisz poprzedni token sesji (dla debugowania)
    const prevSessionToken = this.currentSessionToken;
    
    // Ustaw nowy token sesji
    this.currentSessionToken = sessionToken;
    
    // Aktualizuj aktywny element na liście
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
      if (item.dataset.sessionToken === sessionToken) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
    
    // Pobierz sesję
    const session = this.sessions.find(s => s.token === sessionToken);
    if (!session) {
      console.error(`Nie znaleziono sesji o tokenie ${sessionToken}`);
      this.showNotification("Błąd: nie znaleziono sesji", "error");
      return;
    }
    
    // Wyświetl nazwę użytkownika w nagłówku czatu
    if (this.chatHeader) {
      this.chatHeader.innerHTML = `<h2>${session.other_user.username}</h2>`;
      
      // Dodaj wskaźnik statusu
      const statusSpan = document.createElement('span');
      statusSpan.className = `status-indicator ${session.other_user.is_online ? 'online' : 'offline'}`;
      statusSpan.style.display = 'inline-block';
      statusSpan.style.marginLeft = '10px';
      this.chatHeader.querySelector('h2').appendChild(statusSpan);
    }
    
    // Sprawdź, czy jest klucz sesji
    const hasSessionKey = localStorage.getItem(`session_key_${sessionToken}`);
    
    // Załaduj wiadomości
    this.loadMessages(sessionToken);
    
    // Jeśli nie ma klucza sesji, spróbuj go pobrać
    if (!hasSessionKey && session.has_key) {
      setTimeout(async () => {
        try {
          await this.ensureSessionReady();
        } catch (e) {
          console.error("Błąd pobierania klucza sesji:", e);
        }
      }, 500);
    }
  }
  
  /**
   * Wyświetla nową wiadomość
   */
  displayNewMessage(sessionToken, message) {
    // Dodaj wiadomość do interfejsu, jeśli to aktywna sesja
    if (sessionToken === this.currentSessionToken) {
      this.addMessageToUI(message);
    } else {
      // Powiadomienie o nowej wiadomości w innej sesji
      const session = this.sessions.find(s => s.token === sessionToken);
      if (session) {
        this.showNotification(`Nowa wiadomość od ${session.other_user.username}`, 'info');
      }
    }
  }
  
  /**
   * Ładuje wiadomości dla sesji
   */
  async loadMessages(sessionToken) {
    if (!this.sessionManager) return;
    
    // Wyczyść kontener wiadomości
    if (this.messagesContainer) {
      this.messagesContainer.innerHTML = '';
    }
    
    try {
      // Pobierz wiadomości z lokalnego magazynu
      const result = this.sessionManager.getLocalMessages(sessionToken);
      
      if (result.status === 'success') {
        // Wyświetl wiadomości
        const messages = result.messages;
        messages.forEach(message => this.addMessageToUI(message));
        
        // Przewiń na dół
        this.scrollToBottom();
      }
    } catch (error) {
      console.error('Błąd ładowania wiadomości:', error);
      this.showNotification('Błąd ładowania wiadomości', 'error');
    }
  }

  /**
   * Dodaje nową wiadomość do interfejsu
   */
  addMessageToUI(message) {
    if (!this.messagesContainer) return;
    
    const messageElement = this.createMessageElement(message);
    this.messagesContainer.appendChild(messageElement);
    
    // Przewiń na dół
    this.scrollToBottom();
  }
  
  /**
   * Tworzy element pojedynczej wiadomości
   */
  createMessageElement(message) {
    const messageDiv = document.createElement('div');
    
    // Określ, czy wiadomość jest wysłana przez aktualnego użytkownika
    const isSent = message.sender_id === parseInt(this.currentUser.id) || message.is_mine;
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    
    // Zawartość wiadomości
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = message.content;
    
    // Informacje o wiadomości
    const infoDiv = document.createElement('div');
    infoDiv.className = 'message-info';
    
    // Czas
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
    
    // Format godziny
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
   * Przewija widok wiadomości na dół
   */
  scrollToBottom() {
    if (this.messagesContainer) {
      this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }
  }
  
  /**
   * Sprawdza, czy sesja jest gotowa do wysyłania wiadomości
   */
  async ensureSessionReady() {
    if (!this.currentSessionToken) {
      this.showNotification("Brak aktywnej sesji", "error");
      return false;
    }
    
    // Sprawdź, czy klucz sesji istnieje
    const sessionKey = localStorage.getItem(`session_key_${this.currentSessionToken}`);
    
    if (!sessionKey) {
      try {
        // Znajdź sesję w liście
        const session = this.sessions.find(s => s.token === this.currentSessionToken);
        
        if (!session) {
          this.showNotification("Sesja nie istnieje", "error");
          return false;
        }
        
        // Sprawdź, czy sesja ma klucz
        if (!session.has_key) {
          this.showNotification("Sesja nie ma ustalonego klucza szyfrowania", "error");
          return false;
        }
        
        // Pobierz klucz z serwera
        const result = await this.sessionManager.retrieveSessionKey(this.currentSessionToken);
        
        if (!result.success) {
          this.showNotification("Nie można pobrać klucza sesji: " + result.message, "error");
          return false;
        }
        
        // Sprawdź, czy klucz został pobrany
        if (!localStorage.getItem(`session_key_${this.currentSessionToken}`)) {
          this.showNotification("Nie udało się odszyfrować klucza sesji", "error");
          return false;
        }
      } catch (error) {
        console.error("Błąd podczas pobierania klucza sesji:", error);
        this.showNotification("Błąd podczas pobierania klucza sesji", "error");
        return false;
      }
    }
    
    return true;
  }

  /**
   * Funkcja obsługująca wysyłanie wiadomości
   */
  async sendMessage() {
    const content = this.messageInput.value.trim();
    if (!content) return;
    
    // Zablokuj pole wprowadzania i przycisk wysyłania na czas wysyłania
    this.messageInput.disabled = true;
    this.sendButton.disabled = true;
    
    try {
      // Sprawdź, czy mamy token sesji
      if (!this.currentSessionToken) {
        console.error("Brak aktywnej sesji");
        
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
              console.error("Błąd automatycznego wyboru znajomego:", e);
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
      
      // Wyślij wiadomość przez menedżer sesji
      const result = await this.sessionManager.sendMessage(this.currentSessionToken, messageContent);
      
      if (result.status === 'success') {
        // Dodaj wiadomość do interfejsu - już dodana przez event listener
      } else {
        // Przywróć treść w przypadku błędu
        this.messageInput.value = messageContent;
        this.showNotification(result.message || 'Błąd wysyłania wiadomości', "error");
      }
    } catch (error) {
      console.error('Błąd wysyłania wiadomości:', error);
      this.showNotification('Nie udało się wysłać wiadomości: ' + error.message, "error");
    } finally {
      // Odblokuj pole wprowadzania i przycisk
      this.messageInput.disabled = false;
      this.sendButton.disabled = false;
      this.messageInput.focus();
    }
  }

/**
   * Sprawdza połączenie WebSocket
   */
  checkWebSocketConnection() {
    if (!window.wsHandler || !window.wsHandler.isConnected) {
      this.showNotification("Problem z połączeniem - powiadomienia w czasie rzeczywistym mogą nie działać", "warning", 8000);
    }
  }
  
  /**
   * Inicjalizuje mechanizm powiadomień o zaproszeniach
   */
  initializeFriendRequestNotifications() {
    // Załaduj oczekujące zaproszenia
    this.loadPendingRequests();
  }

  /**
   * Ładuje oczekujące zaproszenia do znajomych
   */
  async loadPendingRequests() {
    try {
      if (!this.sessionManager) return;
      
      const result = await this.sessionManager.getPendingFriendRequests();
      
      if (result.success) {
        this.pendingRequests = result.requests || [];
        this.updateRequestsCounter();
      }
      
      return this.pendingRequests;
    } catch (error) {
      console.error('Błąd ładowania zaproszeń:', error);
      return [];
    }
  }

  /**
   * Aktualizuje licznik zaproszeń
   */
  updateRequestsCounter() {
    if (!this.requestBadge) return;
    
    const count = this.pendingRequests ? this.pendingRequests.length : 0;
    
    if (count > 0) {
      this.requestBadge.textContent = count;
      this.requestBadge.style.display = 'flex';
    } else {
      this.requestBadge.style.display = 'none';
    }
  }

  /**
   * Wyświetla modal z zaproszeniami do znajomych
   */
  showFriendRequestsModal() {
    // Sprawdź, czy są oczekujące zaproszenia
    if (!this.pendingRequests || this.pendingRequests.length === 0) {
      this.showNotification("Brak oczekujących zaproszeń do znajomych", "info");
      return;
    }
    
    // Stwórz modal
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'friend-requests-modal';
    modal.style.display = 'block';
    
    const modalContent = document.createElement('div');
    modalContent.className = 'modal-content';
    
    const closeButton = document.createElement('span');
    closeButton.className = 'search-close';
    closeButton.innerHTML = '&times;';
    closeButton.addEventListener('click', () => modal.remove());
    
    const title = document.createElement('h2');
    title.textContent = 'Zaproszenia do znajomych';
    
    const requestsList = document.createElement('div');
    requestsList.className = 'friend-requests-list';
    
    this.pendingRequests.forEach(request => {
      const requestItem = document.createElement('div');
      requestItem.className = 'friend-request-item';
      requestItem.style.padding = '10px';
      requestItem.style.marginBottom = '10px';
      requestItem.style.borderBottom = '1px solid #555';
      
      const username = document.createElement('div');
      username.textContent = request.username;
      username.style.fontWeight = 'bold';
      
      const actions = document.createElement('div');
      actions.style.marginTop = '10px';
      actions.style.display = 'flex';
      actions.style.gap = '10px';
      
      const acceptButton = document.createElement('button');
      acceptButton.className = 'admin-btn';
      acceptButton.textContent = 'Akceptuj';
      acceptButton.style.backgroundColor = 'var(--primary-color)';
      acceptButton.style.color = 'var(--background-dark)';
      acceptButton.style.border = 'none';
      acceptButton.style.padding = '5px 10px';
      acceptButton.style.borderRadius = '4px';
      acceptButton.style.cursor = 'pointer';
      
      acceptButton.addEventListener('click', async () => {
        acceptButton.disabled = true;
        rejectButton.disabled = true;
        
        try {
          const result = await this.sessionManager.acceptFriendRequest(request.id);
          
          if (result.success) {
            requestItem.innerHTML = `<div>Zaproszenie od ${request.username} zaakceptowane!</div>`;
            this.loadPendingRequests();
            this.loadFriends();
            
            setTimeout(() => {
              // Usuń ten element z listy
              requestItem.remove();
              
              // Jeśli lista jest pusta, zamknij modal
              if (requestsList.childElementCount === 0) {
                modal.remove();
              }
            }, 2000);
          } else {
            requestItem.innerHTML += `<div style="color: var(--error-color)">Błąd: ${result.message}</div>`;
            acceptButton.disabled = false;
            rejectButton.disabled = false;
          }
        } catch (error) {
          requestItem.innerHTML += `<div style="color: var(--error-color)">Błąd: ${error.message}</div>`;
          acceptButton.disabled = false;
          rejectButton.disabled = false;
        }
      });
      
      const rejectButton = document.createElement('button');
      rejectButton.className = 'admin-btn';
      rejectButton.textContent = 'Odrzuć';
      rejectButton.style.backgroundColor = 'var(--error-color)';
      rejectButton.style.color = 'white';
      rejectButton.style.border = 'none';
      rejectButton.style.padding = '5px 10px';
      rejectButton.style.borderRadius = '4px';
      rejectButton.style.cursor = 'pointer';
      
      actions.appendChild(acceptButton);
      actions.appendChild(rejectButton);
      
      requestItem.appendChild(username);
      requestItem.appendChild(actions);
      
      requestsList.appendChild(requestItem);
    });
    
    modalContent.appendChild(closeButton);
    modalContent.appendChild(title);
    modalContent.appendChild(requestsList);
    
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
  }

  /**
   * Wysyła zaproszenie do znajomych
   */
  async sendFriendRequest() {
    const usernameInput = document.getElementById('friend-user-id');
    const statusDiv = document.getElementById('friend-request-status');
    
    if (!usernameInput || !statusDiv) {
      console.error('Brak elementów UI dla wysyłania zaproszeń');
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
        statusDiv.textContent = result.message || 'Zaproszenie wysłane pomyślnie';
        statusDiv.className = 'search-status search-success';
        usernameInput.value = '';
        
        // Zamknij modal po 3 sekundach
        setTimeout(() => {
          const modal = document.getElementById('add-friend-modal');
          if (modal) modal.style.display = 'none';
          
          // Odśwież listę znajomych
          this.loadFriends();
        }, 3000);
      } else {
        statusDiv.textContent = result.message || 'Wystąpił błąd';
        statusDiv.className = 'search-status search-error';
      }
    } catch (error) {
      console.error('Błąd wysyłania zaproszenia:', error);
      statusDiv.textContent = 'Wystąpił błąd sieciowy: ' + error.message;
      statusDiv.className = 'search-status search-error';
    }
  }
  
  /**
   * Pokazuje powiadomienie w interfejsie
   */
  showNotification(message, type = 'info', duration = 5000) {
    // Utwórz element powiadomienia na podstawie szablonu
    const template = document.getElementById('notification-template');
    if (!template) {
      console.log(`${type}: ${message}`);
      return;
    }
    
    const notification = document.importNode(template.content, true).querySelector('.notification');
    if (!notification) return;
    
    // Ustaw typ powiadomienia
    notification.classList.add(type);
    
    // Ustaw treść
    const content = notification.querySelector('.notification-content');
    if (content) content.textContent = message;
    
    // Dodaj obsługę zamykania
    const closeButton = notification.querySelector('.notification-close');
    if (closeButton) {
      closeButton.addEventListener('click', () => {
        notification.classList.add('closing');
        setTimeout(() => notification.remove(), 300);
      });
    }
    
    // Dodaj do dokumentu
    document.body.appendChild(notification);
    
    // Automatycznie zamknij po określonym czasie
    setTimeout(() => {
      if (document.body.contains(notification)) {
        notification.classList.add('closing');
        setTimeout(() => notification.remove(), 300);
      }
    }, duration);
  }
}

// Inicjalizacja interfejsu po załadowaniu dokumentu
document.addEventListener('DOMContentLoaded', () => {
  // Sprawdź, czy użytkownik jest zalogowany
  if (sessionStorage.getItem('isLoggedIn') === 'true' || localStorage.getItem('isLoggedIn') === 'true') {
    // Inicjuj interfejs czatu
    window.chatInterface = new ChatInterface(window.sessionManager);
  }

  // Obsługa przycisku wylogowania
  const logoutButton = document.getElementById('logout-btn');
  if (logoutButton) {
    logoutButton.addEventListener('click', function(event) {
      event.preventDefault();
      // Wywołanie metody logout z SecureSessionManager
      if (window.sessionManager) {
        window.sessionManager.logout();
      } else {
        console.error("Brak dostępu do sessionManager");
        alert("Wystąpił błąd podczas wylogowywania. Odśwież stronę i spróbuj ponownie.");
      }
    });
  }
});
});

  
