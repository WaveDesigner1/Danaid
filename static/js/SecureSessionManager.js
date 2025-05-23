/**
 * SecureSessionManager - ZAKTUALIZOWANA wersja dla Socket.IO
 * Używa UnifiedCrypto i SocketIOHandler zamiast WebSocketHandler
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
    this.setupSocketIOHandlers();

    // Callbacks
    this.onMessageReceived = null;
    this.onSessionsUpdated = null;
    this.onFriendsUpdated = null;
    this.onOnlineStatusChanged = null;
    this.onFriendRequestReceived = null;
    
    console.log("SecureSessionManager zainicjalizowany z Socket.IO", this.user);
  }

  /**
   * Konfiguruje handlery dla SocketIOHandler
   */
  setupSocketIOHandlers() {
    // Poczekaj na załadowanie SocketIOHandler
    const setupHandlers = () => {
      if (!window.wsHandler) {
        console.error("SocketIOHandler nie jest dostępny globalnie");
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
      
      console.log("✅ Socket.IO handlers skonfigurowane");
    };

    // Spróbuj teraz, jeśli nie to czekaj
    if (window.wsHandler) {
      setupHandlers();
    } else {
      // Poczekaj na załadowanie
      setTimeout(setupHandlers, 1000);
    }
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

  // Inicjalizuje bazę danych IndexedDB
  async initDatabase() {
    try {
      const request = indexedDB.open('SecureChatMessages', 1);
      
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('messages')) {
          db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
        }
        if (!db.objectStoreNames.contains('sessions')) {
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
   * Inicjalizacja sesji czatu - ZAKTUALIZOWANA dla Socket.IO
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
   * Pobieranie klucza sesji - ZAKTUALIZOWANA implementacja z UnifiedCrypto
   */
  async retrieveSessionKey(sessionToken) {
    try {
      // Sprawdź czy UnifiedCrypto jest dostępny
      if (!window.unifiedCrypto) {
        throw new Error('UnifiedCrypto nie jest dostępny');
      }

      // Sprawdź czy mamy klucz prywatny
      if (!window.unifiedCrypto.hasPrivateKey()) {
        throw new Error('Brak klucza prywatnego');
      }

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
      
      // ZAKTUALIZOWANE: Używamy UnifiedCrypto zamiast starych modułów
      const sessionKeyBase64 = await window.unifiedCrypto.decryptSessionKey(data.encrypted_key);
      
      // Zapisz klucz sesji
      window.unifiedCrypto.storeSessionKey(sessionToken, sessionKeyBase64);
      
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
   * Wysyłanie wiadomości - ZAKTUALIZOWANA implementacja z Socket.IO i UnifiedCrypto
   */
  async sendMessage(sessionToken, content) {
  try {
    console.log('🚀 Rozpoczynam wysyłanie wiadomości...');
    
    // Sprawdź czy UnifiedCrypto jest dostępny
    if (!window.unifiedCrypto) {
      throw new Error('UnifiedCrypto nie jest dostępny');
    }

    // Sprawdź czy mamy klucz sesji
    const sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
    if (!sessionKeyBase64) {
      throw new Error('Brak klucza sesji');
    }
    
    // KRYTYCZNE: Znajdź sesję aby pobrać recipient_id
    const session = this.activeSessions.find(s => s.token === sessionToken);
    if (!session) {
      console.error('❌ Nie znaleziono sesji o tokenie:', sessionToken);
      console.error('Dostępne sesje:', this.activeSessions.map(s => s.token));
      throw new Error('Nie znaleziono sesji');
    }
    
    if (!session.other_user || !session.other_user.user_id) {
      console.error('❌ Sesja nie ma danych other_user:', session);
      throw new Error('Brak danych odbiorcy w sesji');
    }
    
    console.log('✅ Sesja znaleziona:', {
      token: session.token,
      recipient_id: session.other_user.user_id,
      recipient_name: session.other_user.username
    });
    
    // Szyfrowanie wiadomości
    const sessionKey = await window.unifiedCrypto.importSessionKey(sessionKeyBase64);
    const encryptedData = await window.unifiedCrypto.encryptMessage(sessionKey, content);
    
    // KRYTYCZNE: Upewnij się o prawidłowym formacie danych
    let encryptedContent, ivBase64;
    
    try {
      // Sprawdź typ danych i konwertuj na Base64
      if (typeof encryptedData.data === 'string') {
        encryptedContent = encryptedData.data;
      } else if (encryptedData.data instanceof ArrayBuffer) {
        encryptedContent = btoa(String.fromCharCode(...new Uint8Array(encryptedData.data)));
      } else if (encryptedData.data instanceof Uint8Array) {
        encryptedContent = btoa(String.fromCharCode(...encryptedData.data));
      } else {
        throw new Error('Nieobsługiwany typ danych szyfrowania: ' + typeof encryptedData.data);
      }
      
      if (typeof encryptedData.iv === 'string') {
        ivBase64 = encryptedData.iv;
      } else if (encryptedData.iv instanceof ArrayBuffer) {
        ivBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedData.iv)));
      } else if (encryptedData.iv instanceof Uint8Array) {
        ivBase64 = btoa(String.fromCharCode(...encryptedData.iv));
      } else {
        throw new Error('Nieobsługiwany typ IV: ' + typeof encryptedData.iv);
      }
    } catch (conversionError) {
      console.error('❌ Błąd konwersji danych:', conversionError);
      throw new Error('Błąd przetwarzania zaszyfrowanych danych: ' + conversionError.message);
    }
    
    // Przygotuj payload - TESTUJ różne warianty
    const basePayload = {
      session_token: sessionToken,
      recipient_id: session.other_user.user_id,
      content: encryptedContent,
      iv: ivBase64
    };
    
    // Wariant 1: Podstawowy payload
    console.log('📤 Próba wysłania wiadomości - wariant podstawowy');
    console.log('Payload:', {
      session_token: sessionToken,
      recipient_id: session.other_user.user_id,
      content_length: encryptedContent.length,
      iv_length: ivBase64.length
    });
    
    let response = await fetch('/api/message/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      credentials: 'same-origin',
      body: JSON.stringify(basePayload)
    });
    
    // Jeśli podstawowy nie zadziała, próbuj inne warianty
    if (!response.ok) {
      console.log('❌ Podstawowy payload nie zadziałał, próbuję alternatywne...');
      
      // Wariant 2: Z encrypted_content zamiast content
      const altPayload2 = {
        session_token: sessionToken,
        recipient_id: session.other_user.user_id,
        encrypted_content: encryptedContent,
        iv: ivBase64
      };
      
      console.log('📤 Próba wysłania - wariant z encrypted_content');
      response = await fetch('/api/message/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify(altPayload2)
      });
      
      if (!response.ok) {
        // Wariant 3: Z message_id
        const altPayload3 = {
          session_token: sessionToken,
          recipient_id: session.other_user.user_id,
          content: encryptedContent,
          iv: ivBase64,
          message_id: Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9)
        };
        
        console.log('📤 Próba wysłania - wariant z message_id');
        response = await fetch('/api/message/send', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
          },
          credentials: 'same-origin',
          body: JSON.stringify(altPayload3)
        });
      }
    }
    
    // Szczegółowa obsługa błędów
    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}`;
      let errorDetails = null;
      
      try {
        const responseText = await response.text();
        console.error('❌ Odpowiedź serwera (tekst):', responseText);
        
        try {
          errorDetails = JSON.parse(responseText);
          errorMessage = errorDetails.message || errorDetails.error || errorMessage;
          console.error('❌ Szczegóły błędu serwera:', errorDetails);
        } catch (parseError) {
          console.error('❌ Nie można sparsować odpowiedzi jako JSON');
          errorMessage = responseText || errorMessage;
        }
      } catch (readError) {
        console.error('❌ Nie można odczytać odpowiedzi:', readError);
      }
      
      throw new Error(`Błąd wysyłania wiadomości: ${errorMessage}`);
    }
    
    const data = await response.json();
    console.log('✅ Odpowiedź serwera:', data);
    
    if (data.status !== 'success') {
      throw new Error(data.message || 'Błąd wysyłania wiadomości');
    }
    
    // Dodaj wiadomość do lokalnego stanu
    const newMessage = {
      id: data.message?.id || Date.now().toString(),
      sender_id: parseInt(this.user.id),
      content: content,
      timestamp: data.message?.timestamp || new Date().toISOString(),
      is_mine: true
    };
    
    // Zapisz lokalnie
    await this.storeMessage(sessionToken, newMessage);
    
    console.log('✅ Wiadomość wysłana pomyślnie!');
    
    return {
      status: 'success',
      message: 'Wiadomość wysłana',
      messageData: newMessage
    };
  } catch (error) {
    console.error('❌ Błąd wysyłania wiadomości:', error);
    return {
      status: 'error',
      message: error.message
    };
  }
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

  /**
   * Obsługuje wylogowanie użytkownika - ZAKTUALIZOWANA
   */
  async logout() {
    try {
      // ZAKTUALIZOWANE: Wyczyść klucze kryptograficzne
      if (window.unifiedCrypto) {
        window.unifiedCrypto.clearAllKeys();
      }
      
      // Wyczyść dane lokalne
      localStorage.clear();
      sessionStorage.clear();
      
      // Rozłącz Socket.IO
      if (window.wsHandler) {
        window.wsHandler.disconnect();
      }
      
      // Wyczyść lokalne dane
      this.activeSessions = [];
      this.friends = [];
      this.messages = {};
      
      if (this.db) {
        this.db.close();
      }
      
      // Małe opóźnienie żeby wszystko się wykonało
      await new Promise(resolve => setTimeout(resolve, 100));
      
      console.log('Przekierowuję na logout...');
      
    } catch (error) {
      console.error('Błąd podczas wylogowania:', error);
    } finally {
      // Zawsze przekieruj, nawet jak był błąd
      window.location.href = '/logout';
    }
  }
}

// Inicjalizacja globalnego SessionManager
window.sessionManager = new SecureSessionManager();

