/**
 * SecureSessionManager - Poprawiona implementacja zarządzania sesją
 */
class SecureSessionManager {
  constructor() {
    this.activeSessions = [];
    this.friends = [];
    this.onlineUsers = [];
    this.messages = {};
    this.currentSessionId = null;
    this.user = {
      id: sessionStorage.getItem('user_id'),
      username: sessionStorage.getItem('username'),
      isAdmin: sessionStorage.getItem('is_admin') === 'true',
      isLoggedIn: sessionStorage.getItem('isLoggedIn') === 'true'
    };

    // Inicjalizacja
    this.initDatabase();
    this.loadState();
    
    // Wywołane tylko raz przy starcie
    this.setupWebSocketHandlers();

    // Callbacks
    this.onMessageReceived = null;
    this.onSessionsUpdated = null;
    this.onFriendsUpdated = null;
    this.onOnlineStatusChanged = null;
    this.onFriendRequestReceived = null;
    
    console.log("SecureSessionManager zainicjalizowany", this.user);
  }

  /**
   * Konfiguruje handlery dla WebSocketHandler
   */
  setupWebSocketHandlers() {
    // Upewnij się, że globalny wsHandler istnieje
    if (!window.wsHandler) {
      console.error("WebSocketHandler nie jest dostępny globalnie");
      return;
    }
    
    console.log("Konfiguracja handlerów WebSocket...");
    
    // Obsługa nowych wiadomości
    window.wsHandler.on('new_message', (data) => {
      console.log("Otrzymano nową wiadomość:", data);
      
      if (this.onMessageReceived) {
        this.onMessageReceived(data.session_token, data.message);
      }
    });
    
    // Obsługa aktualizacji sesji
    window.wsHandler.on('session_update', (data) => {
      console.log("Aktualizacja sesji:", data);
      this.getActiveSessions();
    });
    
    // Obsługa zaproszeń do znajomych
    window.wsHandler.on('friend_request', (data) => {
      console.log("Otrzymano zaproszenie do znajomych:", data);
      
      if (this.onFriendRequestReceived) {
        this.onFriendRequestReceived(data);
      }
    });
    
    // Obsługa zmian statusu online
    window.wsHandler.on('user_status_change', (data) => {
      console.log("Zmiana statusu użytkownika:", data);
      
      const userId = data.user_id;
      const isOnline = data.is_online;
      
      // Aktualizuj lokalny stan
      this.updateOnlineStatus(userId, isOnline);
      
      if (this.onOnlineStatusChanged) {
        this.onOnlineStatusChanged(this.onlineUsers);
      }
    });
    
    // Obsługa listy użytkowników online
    window.wsHandler.on('online_users', (data) => {
      console.log("Lista użytkowników online:", data);
      
      this.onlineUsers = data.users || [];
      
      if (this.onOnlineStatusChanged) {
        this.onOnlineStatusChanged(this.onlineUsers);
      }
    });
    
    console.log("Handlery WebSocket skonfigurowane");
  }

  /**
   * Aktualizuje status online użytkownika
   */
  updateOnlineStatus(userId, isOnline) {
    // Aktualizuj listę użytkowników online
    if (isOnline) {
      if (!this.onlineUsers.includes(userId)) {
        this.onlineUsers.push(userId);
      }
    } else {
      this.onlineUsers = this.onlineUsers.filter(id => id !== userId);
    }
    
    // Zaktualizuj status znajomych
    this.friends = this.friends.map(friend => {
      if (friend.user_id === userId) {
        return { ...friend, is_online: isOnline };
      }
      return friend;
    });
  }

  // Inicjalizuje bazę danych
  async initDatabase() {
    try {
      console.log("Inicjalizacja bazy danych IndexedDB...");
      const request = indexedDB.open('SecureChatMessages', 1);
      
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('messages')) {
          db.createObjectStore('messages', { keyPath: 'sessionToken' });
        }
      };
      
      request.onsuccess = (event) => {
        this.db = event.target.result;
        console.log("Baza danych IndexedDB zainicjalizowana");
        this.loadMessagesFromStorage();
      };
      
      request.onerror = (event) => {
        console.error('Błąd inicjalizacji IndexedDB:', event.target.error);
      };
    } catch (error) {
      console.error('Nie można utworzyć bazy danych:', error);
    }
  }

  // Pobieranie wiadomości z lokalnego magazynu
  async loadMessagesFromStorage() {
    if (!this.db) {
      console.error("Baza danych nie jest dostępna");
      return;
    }
    
    try {
      console.log("Ładowanie wiadomości z IndexedDB...");
      const tx = this.db.transaction('messages', 'readonly');
      const store = tx.objectStore('messages');
      const allRecords = await new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      allRecords.forEach(record => {
        this.messages[record.sessionToken] = record.messages;
      });
      
      console.log(`Załadowano wiadomości dla ${allRecords.length} sesji`);
    } catch (error) {
      console.error('Błąd podczas ładowania wiadomości:', error);
    }
  }

  // Zapisywanie wiadomości do lokalnego magazynu
  async storeMessage(sessionToken, message) {
    if (!this.db) {
      console.error("Baza danych nie jest dostępna");
      return false;
    }
    
    try {
      console.log(`Zapisywanie wiadomości dla sesji ${sessionToken}...`);
      const tx = this.db.transaction('messages', 'readwrite');
      const store = tx.objectStore('messages');
      
      let sessionMessages = await new Promise((resolve, reject) => {
        const request = store.get(sessionToken);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      if (!sessionMessages) {
        console.log("Tworzenie nowego obiektu wiadomości dla sesji");
        sessionMessages = {
          sessionToken: sessionToken,
          messages: [],
          lastUpdated: new Date().toISOString()
        };
      }
      
      sessionMessages.messages.push(message);
      sessionMessages.lastUpdated = new Date().toISOString();
      
      await new Promise((resolve, reject) => {
        const request = store.put(sessionMessages);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      console.log("Wiadomość zapisana do IndexedDB");
      return true;
    } catch (error) {
      console.error('Błąd zapisywania wiadomości:', error);
      return false;
    }
  }

  // Inicjalizacja sesji czatu
  async initSession(recipientId) {
    try {
      console.log(`Inicjalizacja sesji czatu z użytkownikiem ${recipientId}...`);
      
      if (!this.user.id) {
        throw new Error("Użytkownik nie jest zalogowany");
      }
      
      const response = await fetch('/api/session/init', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({ recipient_id: recipientId })
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Błąd HTTP: ${response.status}`, errorText);
        throw new Error(`Błąd inicjacji sesji: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Odpowiedź serwera:", data);
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd inicjacji sesji');
      }
      
      const session = data.session;
      console.log("Sesja zainicjowana pomyślnie:", session);
      
      // Aktualizuj listy
      await this.getActiveSessions();
      
      return {
        success: true,
        session: session
      };
    } catch (error) {
      console.error('Błąd inicjacji sesji:', error);
      return {
        success: false,
        message: error.message
      };
    }
  }

  // Pobieranie aktywnych sesji
  async getActiveSessions() {
    try {
      console.log("Pobieranie aktywnych sesji...");
      
      if (!this.user.id) {
        throw new Error("Użytkownik nie jest zalogowany");
      }
      
      const response = await fetch('/api/sessions/active', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Błąd HTTP: ${response.status}`, errorText);
        throw new Error(`Błąd pobierania sesji: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Odpowiedź serwera:", data);
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania sesji');
      }
      
      this.activeSessions = data.sessions;
      console.log(`Pobrano ${this.activeSessions.length} aktywnych sesji`);
      
      if (this.onSessionsUpdated) {
        this.onSessionsUpdated(this.activeSessions);
      }
      
      return {
        status: 'success',
        sessions: this.activeSessions
      };
    } catch (error) {
      console.error('Błąd pobierania aktywnych sesji:', error);
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  // Pobieranie klucza sesji
  async retrieveSessionKey(sessionToken) {
    try {
      console.log(`Pobieranie klucza sesji dla ${sessionToken}...`);
      
      const response = await fetch(`/api/session/${sessionToken}/key`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Błąd HTTP: ${response.status}`, errorText);
        throw new Error(`Błąd pobierania klucza sesji: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Odpowiedź serwera:", data);
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania klucza sesji');
      }
      
      // Import klucza prywatnego
      const privateKeyPEM = localStorage.getItem('private_key_pem');
      if (!privateKeyPEM) {
        throw new Error('Brak klucza prywatnego w localStorage');
      }
      
      console.log("Importowanie klucza prywatnego...");
      // Spróbuj zaimportować klucz prywatny
      const privateKey = await window.e2eeProtocol.importPrivateKeyFromPEM(privateKeyPEM);
      
      // Odszyfruj klucz sesji
      console.log("Deszyfrowanie klucza sesji...");
      const sessionKey = await window.e2eeProtocol.decryptSessionKey(privateKey, data.encrypted_key);
      
      // Zapisz klucz sesji w localStorage
      localStorage.setItem(`session_key_${sessionToken}`, sessionKey);
      console.log("Klucz sesji zapisany w localStorage");
      
      // Potwierdź odebranie klucza
      console.log("Potwierdzanie odebrania klucza...");
      const ackResponse = await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
      });
      
      if (!ackResponse.ok) {
        console.warn("Nie udało się potwierdzić odebrania klucza, ale sesja powinna działać");
      } else {
        console.log("Odebranie klucza potwierdzone pomyślnie");
      }
      
      return {
        success: true,
        message: 'Klucz sesji odebrany i potwierdzony'
      };
    } catch (error) {
      console.error('Błąd pobierania klucza sesji:', error);
      return {
        success: false,
        message: error.message
      };
    }
  }

  // Wysyłanie wiadomości
  async sendMessage(sessionToken, content, mentions = []) {
    try {
      console.log(`Wysyłanie wiadomości w sesji ${sessionToken}...`);
      
      // Sprawdź czy mamy klucz sesji
      const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
      if (!sessionKeyBase64) {
        throw new Error('Brak klucza sesji');
      }
      
      // Importuj klucz
      console.log("Importowanie klucza sesji...");
      const sessionKey = await window.e2eeProtocol.importSessionKey(sessionKeyBase64);
      
      // Szyfruj wiadomość
      console.log("Szyfrowanie wiadomości...");
      const encrypted = await window.e2eeProtocol.encryptMessage(sessionKey, content);
      
      // Wyślij na serwer
      console.log("Wysyłanie zaszyfrowanej wiadomości na serwer...");
      const response = await fetch('/api/message/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          session_token: sessionToken,
          content: encrypted.data,
          iv: encrypted.iv,
          mentions: mentions
        })
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Błąd HTTP: ${response.status}`, errorText);
        throw new Error(`Błąd wysyłania wiadomości: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Odpowiedź serwera:", data);
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd wysyłania wiadomości');
      }
      
      // Dodaj wiadomość do lokalnego stanu
      const newMessage = {
        id: data.message_id || Date.now().toString(),
        sender_id: parseInt(this.user.id),
        content: content,
        timestamp: data.timestamp || new Date().toISOString()
      };
      
      if (!this.messages[sessionToken]) {
        this.messages[sessionToken] = [];
      }
      
      this.messages[sessionToken].push(newMessage);
      
      // Zapisz lokalnie
      await this.storeMessage(sessionToken, newMessage);
      
      console.log("Wiadomość wysłana pomyślnie");
      return {
        status: 'success',
        message: 'Wiadomość wysłana',
        messageData: newMessage
      };
    } catch (error) {
      console.error('Błąd wysyłania wiadomości:', error);
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  // Pobieranie lokalnych wiadomości
  getLocalMessages(sessionToken) {
    console.log(`Pobieranie lokalnych wiadomości dla sesji ${sessionToken}...`);
    
    if (!this.messages[sessionToken]) {
      console.log("Brak lokalnych wiadomości dla tej sesji");
      return {
        status: 'success',
        messages: []
      };
    }
    
    console.log(`Znaleziono ${this.messages[sessionToken].length} wiadomości`);
    return {
      status: 'success',
      messages: this.messages[sessionToken]
    };
  }

  // Pobieranie listy znajomych
  async fetchFriends() {
    try {
      console.log("Pobieranie listy znajomych...");
      
      const response = await fetch('/api/friends', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Błąd HTTP: ${response.status}`, errorText);
        throw new Error(`Błąd pobierania znajomych: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Odpowiedź serwera:", data);
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania znajomych');
      }
      
      this.friends = data.friends;
      console.log(`Pobrano ${this.friends.length} znajomych`);
      
      if (this.onFriendsUpdated) {
        this.onFriendsUpdated(this.friends);
      }
      
      return {
        status: 'success',
        friends: this.friends
      };
    } catch (error) {
      console.error('Błąd pobierania znajomych:', error);
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  /**
   * Wysyła zaproszenie do znajomych
   */
  async sendFriendRequest(username) {
    try {
      // Sprawdź dane wejściowe
      if (!username || !username.trim()) {
        throw new Error('Podaj nazwę użytkownika');
      }
      
      if (!this.user.id) {
        throw new Error('Użytkownik nie jest zalogowany');
      }
      
      console.log('Wysyłanie zaproszenia do znajomych dla:', username);
      
      const response = await fetch('/api/friend_requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({ username: username.trim() })
      });
      
      console.log("Status odpowiedzi:", response.status);
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Błąd HTTP: ${response.status}`, errorText);
        throw new Error(`Błąd wysyłania zaproszenia: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Odpowiedź serwera:", data);
      
      if (data.status === 'success') {
        console.log('Zaproszenie wysłane pomyślnie');
        // Odśwież listę znajomych
        await this.fetchFriends();
        
        return {
          success: true,
          message: data.message || 'Zaproszenie wysłane pomyślnie'
        };
      } else {
        throw new Error(data.message || 'Błąd wysyłania zaproszenia');
      }
    } catch (error) {
      console.error('Błąd wysyłania zaproszenia:', error);
      
      return {
        success: false,
        message: error.message
      };
    }
  }

  // Ładowanie stanu z localStorage
  loadState() {
    try {
      console.log("Ładowanie stanu z localStorage...");
      const stateJSON = localStorage.getItem('chat_state');
      if (stateJSON) {
        const state = JSON.parse(stateJSON);
        if (state.friends) this.friends = state.friends;
        if (state.onlineUsers) this.onlineUsers = state.onlineUsers;
        console.log("Stan załadowany z localStorage");
      } else {
        console.log("Brak zapisanego stanu w localStorage");
      }
    } catch (error) {
      console.error('Błąd ładowania stanu:', error);
    }
  }

  // Zapisywanie stanu do localStorage
  saveState() {
    try {
      console.log("Zapisywanie stanu do localStorage...");
      localStorage.setItem('chat_state', JSON.stringify({
        friends: this.friends,
        onlineUsers: this.onlineUsers
      }));
      console.log("Stan zapisany do localStorage");
    } catch (error) {
      console.error('Błąd zapisywania stanu:', error);
    }
  }
}

// Inicjalizacja
window.sessionManager = new SecureSessionManager();
