/**
 * ChatInterface.js - Interfejs użytkownika dla aplikacji czatu
 */
// Sprawdź czy klasa już istnieje w kontekście globalnym
if (typeof ChatInterface === 'undefined') {
  class ChatInterface {
    // Reszta implementacji bez zmian...
  }

class ChatInterface {
  constructor(sessionManager) {
    // Inicjalizacja menedżera sesji i elementów DOM
    this.sessionManager = sessionManager || window.sessionManager;
    this.initializeDOMElements();
    
    // Stan aplikacji
    this.currentSessionToken = null;
    this.currentUser = null;
    this.friends = [];
    this.onlineUsers = [];
    this.sessions = [];
    this.lastMessageTimes = {};
    this.pendingRequests = [];
    
    // System wzmianek
    this.mentionedUsers = [];
    this.mentionSuggestions = null;
    this.currentMentionPosition = -1;
    this.selectedMentionIndex = 0;
    
    // Inicjalizacja
    this.initializeEvents();
    this.loadUserData();
    this.initializeFriendRequestNotifications();
    this.loadFriends();
    this.loadSessions();
    
    // Sprawdź połączenie WebSocket
    setTimeout(() => this.checkWebSocketConnection(), 1000);
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
      this.sessionManager.onFriendRequestReceived = (data) => {
        console.log("Odebrano zaproszenie:", data);
        this.loadPendingRequests();
      };
    }
  }

/**
   * Ładuje dane użytkownika
   */
  loadUserData() {
    this.currentUser = {
      id: sessionStorage.getItem('user_id'),
      user_id: sessionStorage.getItem('user_id'),
      username: sessionStorage.getItem('username'),
      isAdmin: sessionStorage.getItem('is_admin') === 'true'
    };
    
    if (!this.currentUser.id) {
      console.error('Brak ID użytkownika');
      this.showNotification('Błąd ładowania danych użytkownika', 'error');
    }
  }

  /**
   * Ładuje listę znajomych z serwera
   */
  async loadFriends() {
    try {
      const response = await fetch('/api/friends');
      if (!response.ok) throw new Error('Błąd pobierania znajomych');
      
      const data = await response.json();
      if (data.status === 'success') {
        this.friends = data.friends;
        this.updateFriendsList(this.friends);
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
        this.sessions = result.sessions;
        this.updateSessionsList(this.sessions);
        
        // Wybierz pierwszą sesję, jeśli jest dostępna
        if (this.sessions.length > 0 && !this.currentSessionToken) {
          this.switchSession(this.sessions[0].token);
        }
      }
    } catch (error) {
      console.error('Błąd ładowania sesji:', error);
      this.showNotification('Błąd ładowania sesji czatu', 'error');
    }
  }
  
  /**
   * Aktualizuje listę sesji i znajomych w interfejsie
   */
  updateSessionsList(sessions) {
    this.sessions = sessions;
    this.renderFriendsList();
  }
  
  updateFriendsList(friends) {
    this.friends = friends;
    this.renderFriendsList();
  }
  
  /**
   * Aktualizuje status online użytkowników
   */
  updateOnlineStatus(onlineUsers) {
    this.onlineUsers = onlineUsers;
    
    // Aktualizuj wskaźniki statusu online w interfejsie
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
      const userId = item.dataset.userId;
      const statusIndicator = item.querySelector('.status-indicator');
      
      if (!statusIndicator) return;
      
      if (this.isUserOnline(userId)) {
        statusIndicator.classList.add('online');
        statusIndicator.classList.remove('offline');
      } else {
        statusIndicator.classList.add('offline');
        statusIndicator.classList.remove('online');
      }
    });
  }
  
  /**
   * Sprawdza, czy użytkownik jest online
   */
  isUserOnline(userId) {
    return this.onlineUsers.some(u => u.user_id === userId);
  }

  /**
   * Renderuje listę znajomych i sesji czatu
   */
  renderFriendsList() {
    if (!this.friendsList) return;
    
    // Wyczyść listę
    this.friendsList.innerHTML = '';
    
    // Dodaj aktywne sesje
    if (this.sessions.length > 0) {
      this.sessions.forEach(session => {
        const otherUser = session.other_user;
        const listItem = this.createFriendListItem(otherUser, session.token);
        this.friendsList.appendChild(listItem);
      });
    }
    
    // Dodaj znajomych bez aktywnych sesji
    const friendsWithoutSession = this.friends.filter(friend => 
      !this.sessions.some(session => session.other_user.user_id === friend.user_id)
    );
    
    if (friendsWithoutSession.length > 0) {
      friendsWithoutSession.forEach(friend => {
        const listItem = this.createFriendListItem(friend);
        this.friendsList.appendChild(listItem);
      });
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
    statusIndicator.classList.add(this.isUserOnline(user.user_id) ? 'online' : 'offline');
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
    const chatHeaderTitle = this.chatHeader.querySelector('h2');
    if (chatHeaderTitle) {
      chatHeaderTitle.textContent = session.other_user.username;
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
   * Ładuje wiadomości dla sesji
   */
  async loadMessages(sessionToken) {
    if (!this.sessionManager) return;
    
    // Wyczyść kontener wiadomości
    this.messagesContainer.innerHTML = '';
    
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
    const messageElement = this.createMessageElement(message);
    this.messagesContainer.appendChild(messageElement);
    
    // Zapisz czas ostatniej wiadomości
    this.lastMessageTimes[this.currentSessionToken] = new Date(message.timestamp);
    
    // Przewiń na dół
    this.scrollToBottom();
  }
  
  /**
   * Tworzy element pojedynczej wiadomości
   */
  createMessageElement(message) {
    const messageDiv = document.createElement('div');
    
    // Określ, czy wiadomość jest wysłana przez aktualnego użytkownika
    const isSent = message.sender_id === parseInt(this.currentUser.id);
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
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
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
    
    try {
      // Wyślij wiadomość przez menedżer sesji
      const result = await this.sessionManager.sendMessage(this.currentSessionToken, content);
      
      if (result.status === 'success') {
        // Dodaj wiadomość do interfejsu
        this.addMessageToUI(result.messageData);
        
        // Wyczyść pole wejściowe
        this.messageInput.value = '';
      } else {
        this.showNotification(result.message || 'Błąd wysyłania wiadomości', "error");
      }
    } catch (error) {
      console.error('Błąd wysyłania wiadomości:', error);
      this.showNotification('Nie udało się wysłać wiadomości: ' + error.message, "error");
    }
  }

  /**
   * Sprawdza połączenie WebSocket
   */
  checkWebSocketConnection() {
    const userId = this.currentUser ? this.currentUser.id : null;
    if (!userId) {
      console.error("Brak ID użytkownika");
      return false;
    }
    
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.hostname}:8765/ws/chat/${userId}`;
      
      const ws = new WebSocket(wsUrl);
      
      const connectionTimeout = setTimeout(() => {
        if (ws.readyState !== 1) {  // 1 = OPEN
          ws.close();
          this.showNotification("Problem z połączeniem - powiadomienia w czasie rzeczywistym mogą nie działać", "warning");
        }
      }, 5000);
      
      ws.onopen = () => {
        clearTimeout(connectionTimeout);
        ws.send(JSON.stringify({
          type: 'connection_established',
          user_id: userId
        }));
      };
      
      ws.onerror = () => {
        clearTimeout(connectionTimeout);
        this.showNotification("Problem z połączeniem - powiadomienia w czasie rzeczywistym mogą nie działać", "warning");
      };
      
      ws.onclose = () => {
        clearTimeout(connectionTimeout);
      };
      
      return true;
    } catch (error) {
      console.error("Błąd podczas sprawdzania połączenia WebSocket:", error);
      return false;
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

/**
   * Inicjalizuje mechanizm powiadomień o zaproszeniach
   */
  initializeFriendRequestNotifications() {
    // Utwórz kontener dla ikony powiadomień, jeśli nie istnieje
    this.createNotificationIcon();
    
    // Załaduj oczekujące zaproszenia
    this.loadPendingRequests();
  }

  /**
   * Tworzy ikonę powiadomień w interfejsie użytkownika
   */
  createNotificationIcon() {
    // Sprawdź, czy ikona już istnieje
    if (document.getElementById('friend-request-notification')) {
      return;
    }
    
    // Dodaj style dla ikony powiadomień
    const style = document.createElement('style');
    style.textContent = `
      .notification-icon {
        position: relative;
        cursor: pointer;
        margin: 0 15px;
      }
      
      .notification-badge {
        position: absolute;
        top: -5px;
        right: -5px;
        background-color: red;
        color: white;
        border-radius: 50%;
        min-width: 18px;
        height: 18px;
        display: flex;
        justify-content: center;
        align-items: center;
        font-size: 12px;
      }
    `;
    document.head.appendChild(style);
  }
  
  /**
   * Ładuje oczekujące zaproszenia do znajomych
   */
  async loadPendingRequests() {
    try {
      const response = await fetch('/api/friend_requests/pending');
      
      if (!response.ok) {
        throw new Error(`Błąd HTTP: ${response.status}`);
      }
      
      const data = await response.json();
      
      // Zachowaj listę zaproszeń
      this.pendingRequests = data.status === 'success' ? data.requests : [];
      
      // Aktualizuj licznik i powiadomienia
      this.updateRequestsCounter();
      
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
    const badge = document.getElementById('friend-request-count');
    
    if (!badge) return;
    
    const count = this.pendingRequests ? this.pendingRequests.length : 0;
    
    if (count > 0) {
      badge.textContent = count;
      badge.style.display = 'block';
    } else {
      badge.style.display = 'none';
    }
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
    
    // Loguj wartość przed wysłaniem
    console.log("Wysyłanie zaproszenia do:", username);
    
    // Używamy menedżera sesji do wysłania zaproszenia
    if (this.sessionManager && this.sessionManager.sendFriendRequest) {
      const result = await this.sessionManager.sendFriendRequest(username);
      
      if (result.success) {
        statusDiv.textContent = result.message || 'Zaproszenie wysłane pomyślnie';
        statusDiv.className = 'search-status search-success';
        usernameInput.value = '';
        
        // Zamknij modal po 3 sekundach
        setTimeout(() => {
          const modal = document.getElementById('add-friend-modal');
          if (modal) modal.style.display = 'none';
          
          // Odśwież listę zaproszeń i znajomych
          this.loadFriends();
        }, 3000);
      } else {
        statusDiv.textContent = result.message || 'Wystąpił błąd';
        statusDiv.className = 'search-status search-error';
      }
      return;
    }

    
    // Jeśli nie ma menedżera sesji, użyj fetch API bezpośrednio
    console.log("Używanie bezpośredniego fetch API");
    const response = await fetch('/api/friend_requests', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ username: username })
    });
    
    // Loguj odpowiedź serwera
    console.log("Status odpowiedzi:", response.status);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error("Szczegóły błędu:", errorText);
      throw new Error(`Błąd HTTP: ${response.status} - ${errorText}`);
    }
    
    const data = await response.json();
    console.log("Odpowiedź serwera:", data);
    
    if (data.status === 'success') {
      statusDiv.textContent = data.message || 'Zaproszenie wysłane pomyślnie';
      statusDiv.className = 'search-status search-success';
      usernameInput.value = '';
      
      // Zamknij modal po 3 sekundach
      setTimeout(() => {
        const modal = document.getElementById('add-friend-modal');
        if (modal) modal.style.display = 'none';
        
        // Odśwież listę zaproszeń i znajomych
        this.loadFriends();
      }, 3000);
    } else {
      statusDiv.textContent = data.message || 'Wystąpił błąd';
      statusDiv.className = 'search-status search-error';
    }
  } catch (error) {
    console.error('Błąd wysyłania zaproszenia:', error);
    statusDiv.textContent = 'Wystąpił błąd sieciowy: ' + error.message;
    statusDiv.className = 'search-status search-error';
  }
}
/**
   * Obsługuje wprowadzanie tekstu z potencjalnymi wzmiankami
   */
  async handleMentionInput() {
    if (!this.messageInput) return;
    
    // Pobierz tekst i pozycję kursora
    const text = this.messageInput.value;
    const cursorPosition = this.messageInput.selectionStart;
    
    // Resetuj stan wzmianek
    this.closeMentionSuggestions();
    
    // Znajdź ostatnią wzmiankę przed kursorem
    const textBeforeCursor = text.substring(0, cursorPosition);
    const mentionMatch = textBeforeCursor.match(/@(\w*)$/);
    
    if (mentionMatch) {
      console.log("Wykryto wzmiankę:", mentionMatch[0]);
      
      // Zapamiętaj pozycję wzmianki
      this.currentMentionPosition = mentionMatch.index;
      const query = mentionMatch[1].toLowerCase();
      
      // Upewnij się, że mamy załadowaną listę znajomych
      if (!this.friends || this.friends.length === 0) {
        try {
          await this.loadFriends();
        } catch (e) {
          console.error("Błąd ładowania znajomych:", e);
        }
      }
      
      // Filtruj znajomych pasujących do zapytania
      const filteredFriends = this.friends.filter(friend => 
        friend.username.toLowerCase().includes(query)
      );
      
      if (filteredFriends.length > 0) {
        this.showMentionSuggestions(filteredFriends, query);
      }
    }
  }
  
  /**
   * Pokazuje sugestie wzmianek
   */
  showMentionSuggestions(users, query) {
    // Utwórz lub pobierz kontener sugestii
    if (!this.mentionSuggestions) {
      this.mentionSuggestions = document.createElement('div');
      this.mentionSuggestions.className = 'mention-suggestions';
      document.body.appendChild(this.mentionSuggestions);
    }
    
    // Wyczyść poprzednie sugestie
    this.mentionSuggestions.innerHTML = '';
    
    // Dodaj nowe sugestie
    users.forEach((user, index) => {
      const suggestion = document.createElement('div');
      suggestion.className = 'mention-item';
      suggestion.textContent = user.username;
      
      if (index === this.selectedMentionIndex) {
        suggestion.classList.add('selected');
      }
      
      suggestion.addEventListener('click', () => {
        this.insertMention(user.username);
      });
      
      this.mentionSuggestions.appendChild(suggestion);
    });
    
    // Ustaw pozycję kontenera sugestii pod wzmianką
    const coords = this.getCaretCoordinates();
    this.mentionSuggestions.style.top = `${coords.bottom}px`;
    this.mentionSuggestions.style.left = `${coords.left}px`;
    
    // Zapamiętaj użytkowników
    this.mentionedUsers = users;
    this.selectedMentionIndex = 0;
  }
  
  /**
   * Pobiera pozycję kursora
   */
  getCaretCoordinates() {
    const inputRect = this.messageInput.getBoundingClientRect();
    return {
      left: inputRect.left,
      bottom: inputRect.bottom + window.scrollY
    };
  }
  
  /**
   * Obsługuje nawigację po sugestiach wzmianek
   */
  handleMentionNavigation(e) {
    if (!this.mentionSuggestions || this.mentionedUsers.length === 0) return;
    
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        this.selectedMentionIndex = (this.selectedMentionIndex + 1) % this.mentionedUsers.length;
        this.updateSelectedMention();
        break;
        
      case 'ArrowUp':
        e.preventDefault();
        this.selectedMentionIndex = (this.selectedMentionIndex - 1 + this.mentionedUsers.length) % this.mentionedUsers.length;
        this.updateSelectedMention();
        break;
        
      case 'Tab':
      case 'Enter':
        if (this.mentionSuggestions) {
          e.preventDefault();
          this.insertMention(this.mentionedUsers[this.selectedMentionIndex].username);
        }
        break;
        
      case 'Escape':
        this.closeMentionSuggestions();
        break;
    }
  }
  
  /**
   * Aktualizuje zaznaczoną wzmiankę w sugestiach
   */
  updateSelectedMention() {
    const items = this.mentionSuggestions.querySelectorAll('.mention-item');
    
    items.forEach((item, index) => {
      if (index === this.selectedMentionIndex) {
        item.classList.add('selected');
      } else {
        item.classList.remove('selected');
      }
    });
  }
  
  /**
   * Wstawia wybraną wzmiankę do pola wejściowego
   */
  insertMention(username) {
    if (!this.messageInput || this.currentMentionPosition === -1) return;
    
    const text = this.messageInput.value;
    const cursorPosition = this.messageInput.selectionStart;
    
    // Znajdź początek i koniec wzmianki
    const textBeforeCursor = text.substring(0, cursorPosition);
    const mentionMatch = textBeforeCursor.match(/@(\w*)$/);
    
    if (mentionMatch) {
      const mentionStart = mentionMatch.index;
      const mentionEnd = cursorPosition;
      
      // Wstaw wzmiankę
      const newText = text.substring(0, mentionStart) + '@' + username + ' ' + text.substring(mentionEnd);
      this.messageInput.value = newText;
      
      // Ustaw kursor za wstawioną wzmianką
      const newPosition = mentionStart + username.length + 2; // +2 for @ and space
      this.messageInput.setSelectionRange(newPosition, newPosition);
      
      // Zamknij sugestie
      this.closeMentionSuggestions();
      
      // Ustaw focus z powrotem na pole wejściowe
      this.messageInput.focus();
    }
  }
  
  /**
   * Zamyka sugestie wzmianek
   */
  closeMentionSuggestions() {
    if (this.mentionSuggestions) {
      this.mentionSuggestions.remove();
      this.mentionSuggestions = null;
    }
    
    this.currentMentionPosition = -1;
    this.mentionedUsers = [];
    this.selectedMentionIndex = 0;
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
    
    // Detekcja wzmianek i nawigacja
    this.messageInput.addEventListener('input', () => this.handleMentionInput());
    this.messageInput.addEventListener('keydown', (e) => this.handleMentionNavigation(e));
    
    // Zamykanie sugestii wzmianek po kliknięciu poza nimi
    document.addEventListener('click', (e) => {
      if (this.mentionSuggestions && !this.mentionSuggestions.contains(e.target) && e.target !== this.messageInput) {
        this.closeMentionSuggestions();
      }
    });
    
    // Obsługa modalu dodawania znajomych
    this.addFriendBtn.addEventListener('click', () => {
      const modal = document.getElementById('add-friend-modal');
      if (modal) modal.style.display = 'block';
    });
    
    // Przycisk wysyłania zaproszenia
    const sendFriendRequestBtn = document.getElementById('send-friend-request-btn');
    if (sendFriendRequestBtn) {
      sendFriendRequestBtn.addEventListener('click', () => this.sendFriendRequest());
    }

    // Nasłuchiwanie na zdarzenia z menedżera sesji
    if (this.sessionManager) {
      // Inne handlery...
    }
  }
// Inicjalizacja interfejsu po załadowaniu dokumentu
document.addEventListener('DOMContentLoaded', () => {
  // Sprawdź, czy użytkownik jest zalogowany
  if (sessionStorage.getItem('isLoggedIn') === 'true' || localStorage.getItem('isLoggedIn') === 'true') {
    // Inicjuj interfejs czatu
    window.chatInterface = new ChatInterface(window.sessionManager);
  }
});

