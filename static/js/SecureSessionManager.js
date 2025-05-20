/**
 * Menedżer bezpiecznych sesji czatu
 */

// Sprawdź czy klasa już istnieje w kontekście globalnym
if (typeof E2EEProtocol === 'undefined') {
  class E2EEProtocol {
    // Reszta implementacji bez zmian...
  }
  
  // Eksport globalny
  window.e2eeProtocol = window.e2eeProtocol || new E2EEProtocol();
}
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
    this.connectWebSocket();

    // Callbacks
    this.onMessageReceived = null;
    this.onSessionsUpdated = null;
    this.onFriendsUpdated = null;
    this.onOnlineStatusChanged = null;
    this.onFriendRequestReceived = null;
  }

  // Inicjalizacja połączenia WebSocket
  connectWebSocket() {
    if (!this.user.id) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.hostname}:8765/ws/chat/${this.user.id}`;
    
    try {
      this.socket = new WebSocket(wsUrl);
      
      this.socket.onopen = () => {
        console.log('WebSocket połączony');
        this.socket.send(JSON.stringify({
          type: 'connection_established',
          user_id: this.user.id
        }));
      };
      
      this.socket.onmessage = (event) => {
        this.handleWebSocketMessage(event);
      };
      
      this.socket.onclose = () => {
        console.log('WebSocket zamknięty, próba ponownego połączenia za 5s');
        setTimeout(() => this.connectWebSocket(), 5000);
      };
      
      this.socket.onerror = (error) => {
        console.error('Błąd WebSocket:', error);
      };
    } catch (error) {
      console.error('Nie można utworzyć połączenia WebSocket:', error);
    }
  }

  // Obsługa wiadomości z WebSocket
  handleWebSocketMessage(event) {
    try {
      const data = JSON.parse(event.data);
      
      switch(data.type) {
        case 'new_message':
          this.handleNewMessage(data);
          break;
        case 'session_update':
          this.handleSessionUpdate(data);
          break;
        case 'friend_request':
          this.handleFriendRequest(data);
          break;
        case 'user_status_change':
          this.handleUserStatusChange(data);
          break;
        case 'ping':
          this.socket.send(JSON.stringify({type: 'pong'}));
          break;
      }
    } catch (error) {
      console.error('Błąd przetwarzania wiadomości WebSocket:', error);
    }
  }

  // Inicjalizuje bazę danych
  async initDatabase() {
    try {
      const request = indexedDB.open('SecureChatMessages', 1);
      
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('messages')) {
          db.createObjectStore('messages', { keyPath: 'sessionToken' });
        }
      };
      
      request.onsuccess = (event) => {
        this.db = event.target.result;
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
    if (!this.db) return;
    
    try {
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
      
      console.log('Wiadomości załadowane z lokalnego magazynu');
    } catch (error) {
      console.error('Błąd podczas ładowania wiadomości:', error);
    }
  }

  // Zapisywanie wiadomości do lokalnego magazynu
  async storeMessage(sessionToken, message) {
    if (!this.db) return false;
    
    try {
      const tx = this.db.transaction('messages', 'readwrite');
      const store = tx.objectStore('messages');
      
      let sessionMessages = await new Promise((resolve, reject) => {
        const request = store.get(sessionToken);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      if (!sessionMessages) {
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
      
      return true;
    } catch (error) {
      console.error('Błąd zapisywania wiadomości:', error);
      return false;
    }
  }

  // Inicjalizacja sesji czatu
  async initSession(recipientId) {
    try {
      const response = await fetch('/api/session/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipientId })
      });
      
      if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
      
      const data = await response.json();
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd inicjacji sesji');
      }
      
      const session = data.session;
      
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
      const response = await fetch('/api/sessions/active');
      
      if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
      
      const data = await response.json();
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania sesji');
      }
      
      this.activeSessions = data.sessions;
      
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
      const response = await fetch(`/api/session/${sessionToken}/key`);
      
      if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
      
      const data = await response.json();
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania klucza sesji');
      }
      
      // Import klucza prywatnego
      const privateKeyPEM = localStorage.getItem('private_key_pem');
      if (!privateKeyPEM) {
        throw new Error('Brak klucza prywatnego w localStorage');
      }
      
      // Spróbuj zaimportować klucz prywatny
      const privateKey = await window.e2eeProtocol.importPrivateKeyFromPEM(privateKeyPEM);
      
      // Odszyfruj klucz sesji
      const sessionKey = await window.e2eeProtocol.decryptSessionKey(privateKey, data.encrypted_key);
      
      // Zapisz klucz sesji w localStorage
      localStorage.setItem(`session_key_${sessionToken}`, sessionKey);
      
      // Potwierdź odebranie klucza
      await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
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
      // Sprawdź czy mamy klucz sesji
      const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
      if (!sessionKeyBase64) {
        throw new Error('Brak klucza sesji');
      }
      
      // Importuj klucz
      const sessionKey = await window.e2eeProtocol.importSessionKey(sessionKeyBase64);
      
      // Szyfruj wiadomość
      const encrypted = await window.e2eeProtocol.encryptMessage(sessionKey, content);
      
      // Wyślij na serwer
      const response = await fetch('/api/message/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_token: sessionToken,
          content: encrypted.data,
          iv: encrypted.iv,
          mentions: mentions
        })
      });
      
      if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
      
      const data = await response.json();
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd wysyłania wiadomości');
      }
      
      // Dodaj wiadomość do lokalnego stanu
      const newMessage = {
        id: data.message_id || Date.now().toString(),
        sender_id: parseInt(sessionStorage.getItem('user_id')),
        content: content,
        timestamp: new Date().toISOString()
      };
      
      if (!this.messages[sessionToken]) {
        this.messages[sessionToken] = [];
      }
      
      this.messages[sessionToken].push(newMessage);
      
      // Zapisz lokalnie
      await this.storeMessage(sessionToken, newMessage);
      
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
    if (!this.messages[sessionToken]) {
      return {
        status: 'success',
        messages: []
      };
    }
    
    return {
      status: 'success',
      messages: this.messages[sessionToken]
    };
  }

  // Ładowanie stanu z localStorage
  loadState() {
    try {
      const stateJSON = localStorage.getItem('chat_state');
      if (stateJSON) {
        const state = JSON.parse(stateJSON);
        if (state.friends) this.friends = state.friends;
        if (state.onlineUsers) this.onlineUsers = state.onlineUsers;
      }
    } catch (error) {
      console.error('Błąd ładowania stanu:', error);
    }
  }

  // Zapisywanie stanu do localStorage
  saveState() {
    try {
      localStorage.setItem('chat_state', JSON.stringify({
        friends: this.friends,
        onlineUsers: this.onlineUsers
      }));
    } catch (error) {
      console.error('Błąd zapisywania stanu:', error);
    }
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
          'X-Requested-With': 'XMLHttpRequest' // Dodajemy to pole
        },
        credentials: 'same-origin',
        body: JSON.stringify({ 
          username: username.trim()
          // Używamy samego username zamiast recipient_id
        })
      });
      
      if (!response.ok) {
        throw new Error(`Błąd HTTP: ${response.status}`);
      }
      
      const data = await response.json();
      
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

// Inicjalizacja
window.sessionManager = new SecureSessionManager();

