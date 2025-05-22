/**
 * SecureSessionManager - Ujednolicona implementacja zarządzania sesją
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

    // Inicjalizacja bazy danych
    this.initDatabase();
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
   * Konfiguruje handlery untuk WebSocketHandler
   */
  setupWebSocketHandlers() {
    if (!window.wsHandler) {
      console.error("WebSocketHandler nie jest dostępny globalnie");
      return;
    }
    
    // Obsługa nowych wiadomości
    window.wsHandler.on('new_message', (data) => {
      console.log("Otrzymano nową wiadomość:", data);
      
      if (this.onMessageReceived) {
        this.onMessageReceived(data.session_token, data.message);
      }
      
      // Dodaj wiadomość do lokalnego magazynu
      this.storeMessage(data.session_token, data.message);
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
      const userId = data.user_id;
      const isOnline = data.is_online;
      this.updateOnlineStatus(userId, isOnline);
    });
    
    // Obsługa listy użytkowników online
    window.wsHandler.on('online_users', (data) => {
      this.onlineUsers = data.users || [];
      
      if (this.onOnlineStatusChanged) {
        this.onOnlineStatusChanged(this.onlineUsers);
      }
    });
  }

  /**
   * Aktualizuje status online użytkownika
   */
  updateOnlineStatus(userId, isOnline) {
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
    
    if (this.onOnlineStatusChanged) {
      this.onOnlineStatusChanged(this.onlineUsers);
    }
  }

  // Inicjalizuje bazę danych
  async initDatabase() {
    try {
      const request = indexedDB.open('SecureChatMessages', 1);
      
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('messages')) {
          db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
          db.createObjectStore('sessions', { keyPath: 'token' });
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
      const tx = this.db.transaction(['messages'], 'readonly');
      const store = tx.objectStore('messages');
      const messages = await new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      // Grupuj wiadomości według sesji
      messages.forEach(message => {
        const sessionToken = message.sessionToken;
        if (!this.messages[sessionToken]) {
          this.messages[sessionToken] = [];
        }
        this.messages[sessionToken].push(message);
      });
      
      console.log(`Załadowano wiadomości dla ${Object.keys(this.messages).length} sesji`);
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
      // Dodaj wiadomość do lokalnego stanu
      if (!this.messages[sessionToken]) {
        this.messages[sessionToken] = [];
      }
      this.messages[sessionToken].push(message);
      
      // Zapisz do IndexedDB
      const tx = this.db.transaction(['messages'], 'readwrite');
      const store = tx.objectStore('messages');
      
      await new Promise((resolve, reject) => {
        const request = store.add({
          ...message,
          sessionToken: sessionToken
        });
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      return true;
    } catch (error) {
      console.error('Błąd zapisywania wiadomości:', error);
      return false;
    }
  }

  /**
   * Inicjalizacja sesji czatu
   */
  async initSession(recipientId) {
    try {
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
        throw new Error(`Błąd inicjacji sesji: ${response.status}`);
      }
      
      const data = await response.json();
      
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

  /**
   * Pobieranie aktywnych sesji
   */
  async getActiveSessions() {
    try {
      if (!this.user.id) {
        throw new Error("Użytkownik nie jest zalogowany");
      }
      
      const response = await fetch('/api/sessions/active', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        throw new Error(`Błąd pobierania sesji: ${response.status}`);
      }
      
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
  /**
   * Pobieranie klucza sesji
   */
  async retrieveSessionKey(sessionToken) {
    try {
      const response = await fetch(`/api/session/${sessionToken}/key`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        throw new Error(`Błąd pobierania klucza sesji: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania klucza sesji');
      }
      
      // Import klucza prywatnego
      const privateKeyPEM = localStorage.getItem('private_key_pem');
      if (!privateKeyPEM) {
        throw new Error('Brak klucza prywatnego w localStorage');
      }
      
      // Importuj klucz prywatny
      const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        this._pemToArrayBuffer(privateKeyPEM),
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        false,
        ["decrypt"]
      );
      
      // Odszyfruj klucz sesji
      const encryptedKey = this._base64ToArrayBuffer(data.encrypted_key);
      const sessionKeyBuffer = await window.crypto.subtle.decrypt(
        {
          name: "RSA-OAEP"
        },
        privateKey,
        encryptedKey
      );
      
      // Konwertuj na base64 i zapisz
      const sessionKey = this._arrayBufferToBase64(sessionKeyBuffer);
      localStorage.setItem(`session_key_${sessionToken}`, sessionKey);
      
      // Potwierdź odebranie klucza
      await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
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

  /**
   * Wysyłanie wiadomości
   */
  async sendMessage(sessionToken, content) {
    try {
      // Sprawdź czy mamy klucz sesji
      const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
      if (!sessionKeyBase64) {
        throw new Error('Brak klucza sesji');
      }
      
      // Importuj klucz AES-GCM
      const sessionKeyBuffer = this._base64ToArrayBuffer(sessionKeyBase64);
      const sessionKey = await window.crypto.subtle.importKey(
        "raw",
        sessionKeyBuffer,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        ["encrypt"]
      );
      
      // Generuj IV
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      // Szyfruj wiadomość
      const encoder = new TextEncoder();
      const encodedContent = encoder.encode(content);
      const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        sessionKey,
        encodedContent
      );
      
      // Wyślij na serwer
      const response = await fetch('/api/message/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          session_token: sessionToken,
          content: this._arrayBufferToBase64(encryptedBuffer),
          iv: this._arrayBufferToBase64(iv)
        })
      });
      
      if (!response.ok) {
        throw new Error(`Błąd wysyłania wiadomości: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd wysyłania wiadomości');
      }
      
      // Dodaj wiadomość do lokalnego stanu
      const newMessage = {
        id: data.message.id || Date.now().toString(),
        sender_id: parseInt(this.user.id),
        content: content,
        timestamp: data.message.timestamp || new Date().toISOString(),
        is_mine: true
      };
      
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

  /**
   * Pobieranie lokalnych wiadomości
   */
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

/**
   * Pobieranie listy znajomych
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
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania znajomych');
      }
      
      this.friends = data.friends;
      
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
      if (!username || !username.trim()) {
        throw new Error('Podaj nazwę użytkownika');
      }
      
      if (!this.user.id) {
        throw new Error('Użytkownik nie jest zalogowany');
      }
      
      const response = await fetch('/api/friend_requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({ username: username.trim() })
      });
      
      if (!response.ok) {
        throw new Error(`Błąd HTTP: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
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
  
  /**
   * Pobiera oczekujące zaproszenia do znajomych
   */
  async getPendingFriendRequests() {
    try {
      const response = await fetch('/api/friend_requests/pending', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        throw new Error(`Błąd HTTP: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        return {
          success: true,
          requests: data.requests || []
        };
      } else {
        throw new Error(data.message || 'Błąd pobierania zaproszeń');
      }
    } catch (error) {
      console.error('Błąd pobierania zaproszeń:', error);
      
      return {
        success: false,
        message: error.message,
        requests: []
      };
    }
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
      
      if (!response.ok) {
        throw new Error(`Błąd HTTP: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        // Odśwież listę znajomych
        await this.fetchFriends();
        
        return {
          success: true,
          message: data.message || 'Zaproszenie zaakceptowane'
        };
      } else {
        throw new Error(data.message || 'Błąd akceptacji zaproszenia');
      }
    } catch (error) {
      console.error('Błąd akceptacji zaproszenia:', error);
      
      return {
        success: false,
        message: error.message
      };
    }
  }

// Pomocnicze funkcje konwersji
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  
  _base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  
  _pemToArrayBuffer(pem) {
    const pemContent = pem
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("-----END PRIVATE KEY-----", "")
      .replace(/\s+/g, "");
    return this._base64ToArrayBuffer(pemContent);
  }

  /**
   * Obsługuje wylogowanie użytkownika
   */
  logout() {
    // Wyślij żądanie wylogowania do serwera
    fetch('/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      credentials: 'same-origin' // To zapewnia wysłanie cookies z żądaniem
    })
    .then(response => {
      if (response.ok) {
        // Usuń dane sesji z localStorage i sessionStorage
        localStorage.removeItem('authToken');
        localStorage.removeItem('private_key_pem');
        
        // Wyczyść wszystkie klucze sesji
        Object.keys(localStorage).forEach(key => {
          if (key.startsWith('session_key_')) {
            localStorage.removeItem(key);
          }
        });
        
        // Wyczyść dane z sessionStorage
        sessionStorage.removeItem('user_id');
        sessionStorage.removeItem('username');
        sessionStorage.removeItem('is_admin');
        sessionStorage.removeItem('isLoggedIn');
        
        // Rozłącz WebSocket jeśli istnieje
        if (window.wsHandler) {
          window.wsHandler.disconnect();
        }
        
        // Wyczyść lokalne dane
        this.activeSessions = [];
        this.friends = [];
        this.messages = {};
        this.onlineUsers = [];
        
        // Zamknij bazę danych IndexedDB
        if (this.db) {
          this.db.close();
        }
        
        // Przekieruj użytkownika na stronę logowania
        window.location.href = '/';
      } else {
        throw new Error('Wylogowanie nie powiodło się');
      }
    })
    .catch(error => {
      console.error('Błąd podczas wylogowywania:', error);
      alert('Wystąpił błąd podczas wylogowywania. Spróbuj ponownie.');
    });
  }
}

// Inicjalizacja globalnego SessionManager
window.sessionManager = new SecureSessionManager();
