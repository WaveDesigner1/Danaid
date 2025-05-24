/**
 * SecureSessionManager - POPRAWIONA wersja dla Socket.IO
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
   * POPRAWIONA: Konfiguruje handlery dla SocketIOHandler
   */
  setupSocketIOHandlers() {
    // Poczekaj na załadowanie SocketIOHandler
    const setupHandlers = () => {
      if (!window.wsHandler) {
        console.error("SocketIOHandler nie jest dostępny globalnie");
        return;
      }
      
      // POPRAWIONA: Obsługa nowych wiadomości z debugowaniem
      window.wsHandler.on('new_message', (data) => {
        console.log("🆕 [SOCKET] Otrzymano nową wiadomość:", data);
        console.log("🆕 [SOCKET] Struktura danych:", {
          hasSessionToken: !!data.session_token,
          hasMessage: !!data.message,
          messageContent: data.message?.content,
          messageId: data.message?.id,
          senderId: data.message?.sender_id
        });
        
        try {
          // Sprawdź czy to nie nasza własna wiadomość (echo)
          if (data.message && data.message.sender_id && 
              parseInt(data.message.sender_id) === parseInt(this.user.id)) {
            console.log("↩️ To nasza własna wiadomość, pomijam");
            return;
          }
          
          // Wywołaj callback
          if (this.onMessageReceived) {
            this.onMessageReceived(data.session_token, data.message);
          } else {
            console.warn("⚠️ Brak callbacku onMessageReceived");
          }
          
          // Dodaj do lokalnego magazynu
          this.storeMessage(data.session_token, data.message);
          
        } catch (error) {
          console.error("❌ Błąd przetwarzania wiadomości Socket.IO:", error);
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
      
      // DODANE: Obsługa błędów Socket.IO
      window.wsHandler.on('error', (error) => {
        console.error("❌ [SOCKET] Błąd Socket.IO:", error);
      });

      // DODANE: Obsługa rozłączenia
      window.wsHandler.on('disconnect', (reason) => {
        console.warn("🔌 [SOCKET] Rozłączono:", reason);
      });

      // DODANE: Test połączenia
      window.wsHandler.on('connect', () => {
        console.log("✅ [SOCKET] Połączono - testowanie...");
        
        // Wyślij ping test
        setTimeout(() => {
          if (window.wsHandler.send) {
            window.wsHandler.send('ping', { test: true });
            console.log("🏓 Wysłano ping test");
          }
        }, 1000);
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
      
      // Sprawdź czy wiadomość już nie istnieje (unikaj duplikatów)
      const exists = this.messages[sessionToken].find(m => 
        m.id === message.id || 
        (m.timestamp === message.timestamp && m.content === message.content && m.sender_id === message.sender_id)
      );
      
      if (exists) {
        console.log("📝 Wiadomość już istnieje, pomijam duplikat");
        return true;
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
      
      console.log("💾 Wiadomość zapisana:", message.content?.substring(0, 50) + "...");
      return true;
    } catch (error) {
      console.error('Błąd zapisywania wiadomości:', error);
      return false;
    }
  }

  /**
   * DODANA: Pobieranie lokalnych wiadomości z obsługą deszyfrowania
   */
  getLocalMessages(sessionToken) {
    console.log('📥 getLocalMessages wywołane dla:', sessionToken);
    console.log('💾 Dostępne wiadomości:', Object.keys(this.messages));
    
    if (!sessionToken) {
      console.error('❌ Brak sessionToken');
      return {
        status: 'error',
        message: 'Brak tokenu sesji',
        messages: []
      };
    }
    
    // Sprawdź czy mamy wiadomości dla tej sesji
    if (!this.messages[sessionToken]) {
      console.log('📭 Brak wiadomości dla sesji:', sessionToken);
      return {
        status: 'success',
        messages: []
      };
    }
    
    const messages = this.messages[sessionToken];
    console.log(`📨 Znaleziono ${messages.length} wiadomości dla sesji ${sessionToken}`);
    
    // Posortuj wiadomości według czasu
    const sortedMessages = messages.sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      return timeA - timeB;
    });
    
    return {
      status: 'success',
      messages: sortedMessages
    };
  }

  /**
   * DODANA: Pobieranie i odszyfrowanie wiadomości z serwera
   */
  async fetchMessagesFromServer(sessionToken) {
    try {
      console.log('🌐 Pobieranie wiadomości z serwera dla:', sessionToken);
      
      const response = await fetch(`/api/messages/${sessionToken}`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'Błąd pobierania wiadomości');
      }
      
      // Odszyfruj wiadomości jeśli są zaszyfrowane
      const decryptedMessages = [];
      
      for (const message of data.messages || []) {
        try {
          if (message.content && message.iv && window.unifiedCrypto) {
            // Sprawdź czy mamy klucz sesji
            const sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
            if (sessionKeyBase64) {
              const sessionKey = await window.unifiedCrypto.importSessionKey(sessionKeyBase64);
              const decryptedContent = await window.unifiedCrypto.decryptMessage(sessionKey, {
                data: message.content,
                iv: message.iv
              });
              
              message.content = decryptedContent;
            }
          }
          
          decryptedMessages.push(message);
        } catch (decryptError) {
          console.error('❌ Błąd deszyfrowania wiadomości:', decryptError);
          // Dodaj wiadomość z błędem deszyfrowania
          decryptedMessages.push({
            ...message,
            content: '[Nie można odszyfrować wiadomości]',
            decryption_error: true
          });
        }
      }
      
      // Zapisz do lokalnej pamięci
      if (!this.messages[sessionToken]) {
        this.messages[sessionToken] = [];
      }
      
      // Połącz z lokalnymi wiadomościami (unikaj duplikatów)
      for (const message of decryptedMessages) {
        const exists = this.messages[sessionToken].find(m => 
          m.id === message.id || 
          (m.timestamp === message.timestamp && m.content === message.content)
        );
        
        if (!exists) {
          this.messages[sessionToken].push(message);
          // Zapisz też do IndexedDB
          await this.storeMessage(sessionToken, message);
        }
      }
      
      console.log(`✅ Pobrano i odszyfrowano ${decryptedMessages.length} wiadomości`);
      
      return {
        status: 'success',
        messages: this.messages[sessionToken]
      };
      
    } catch (error) {
      console.error('❌ Błąd pobierania wiadomości z serwera:', error);
      return {
        status: 'error',
        message: error.message,
        messages: []
      };
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

  async sendMessage(sessionToken, content) {
    try {
      console.log('🚀 [SENDMESSAGE] Rozpoczynam wysyłanie wiadomości...');
      
      // Sprawdź UnifiedCrypto
      if (!window.unifiedCrypto) {
        throw new Error('UnifiedCrypto nie jest dostępny');
      }

      // Sprawdź klucz sesji
      const sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
      if (!sessionKeyBase64) {
        throw new Error('Brak klucza sesji');
      }
      
      // Znajdź sesję
      const session = this.activeSessions.find(s => s.token === sessionToken);
      if (!session || !session.other_user?.user_id) {
        throw new Error('Nie znaleziono sesji lub danych odbiorcy');
      }
      
      console.log('✅ Sesja OK:', {
        token: session.token,
        recipient_id: session.other_user.user_id,
        recipient_name: session.other_user.username
      });
      
      // Szyfrowanie
      const sessionKey = await window.unifiedCrypto.importSessionKey(sessionKeyBase64);
      const encryptedData = await window.unifiedCrypto.encryptMessage(sessionKey, content);
      
      // Konwersja do Base64
      let encryptedContent, ivBase64;
      
      if (typeof encryptedData.data === 'string') {
        encryptedContent = encryptedData.data;
      } else {
        const bytes = encryptedData.data instanceof ArrayBuffer 
          ? new Uint8Array(encryptedData.data)
          : encryptedData.data;
        encryptedContent = btoa(String.fromCharCode.apply(null, bytes));
      }
      
      if (typeof encryptedData.iv === 'string') {
        ivBase64 = encryptedData.iv;
      } else {
        const ivBytes = encryptedData.iv instanceof ArrayBuffer 
          ? new Uint8Array(encryptedData.iv)
          : encryptedData.iv;
        ivBase64 = btoa(String.fromCharCode.apply(null, ivBytes));
      }
      
      console.log('📊 Dane do wysłania:', {
        session_token: sessionToken,
        recipient_id: session.other_user.user_id,
        content_length: encryptedContent.length,
        iv_length: ivBase64.length
      });
      
      // Payload dla Railway
      const payload = {
        session_token: sessionToken,
        recipient_id: parseInt(session.other_user.user_id),
        content: encryptedContent,
        iv: ivBase64
      };
      
      // Headers
      const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Cache-Control': 'no-cache'
      };
      
      console.log('📤 Wysyłanie wiadomości...');
      
      const response = await fetch('/api/message/send', {
        method: 'POST',
        headers: headers,
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      });
      
      console.log('📡 Odpowiedź serwera:', response.status, response.statusText);
      
      if (!response.ok) {
        let errorMessage = `HTTP ${response.status}`;
        
        try {
          const responseText = await response.text();
          console.error('❌ Błąd response:', responseText);
          
          try {
            const errorDetails = JSON.parse(responseText);
            errorMessage = errorDetails.message || errorDetails.error || errorMessage;
          } catch (e) {
            errorMessage = responseText.length > 100 
              ? responseText.substring(0, 100) + '...' 
              : responseText;
          }
        } catch (e) {
          console.error('❌ Nie można odczytać odpowiedzi błędu');
        }
        
        throw new Error(`Błąd serwera: ${errorMessage}`);
      }
      
      const data = await response.json();
      console.log('✅ Sukces:', data);
      
      if (data.status !== 'success') {
        throw new Error(data.message || 'API zwróciło błąd');
      }
      
      // Dodaj do lokalnego stanu
      const newMessage = {
        id: data.message?.id || Date.now().toString(),
        sender_id: parseInt(this.user.id),
        content: content,
        timestamp: data.message?.timestamp || new Date().toISOString(),
        is_mine: true
      };
      
      await this.storeMessage(sessionToken, newMessage);
      
      console.log('✅ Wiadomość wysłana i zapisana lokalnie!');
      
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
   * DODANA: Odszyfrowanie i zapis przychodzących wiadomości
   */
  async decryptAndStoreMessage(sessionToken, message) {
    try {
      console.log('🔐 Próba odszyfrowania wiadomości:', {
        sessionToken,
        hasContent: !!message.content,
        hasIv: !!message.iv
      });
      
      // Jeśli wiadomość jest zaszyfrowana i mamy klucz
      if (message.content && message.iv && window.unifiedCrypto) {
        const sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
        
        if (sessionKeyBase64) {
          const sessionKey = await window.unifiedCrypto.importSessionKey(sessionKeyBase64);
          message.content = await window.unifiedCrypto.decryptMessage(sessionKey, {
            data: message.content,
            iv: message.iv
          });
          console.log('✅ Wiadomość odszyfrowana:', message.content?.substring(0, 50) + "...");
        } else {
          console.warn('⚠️ Brak klucza sesji dla:', sessionToken);
        }
      }
      
      // Zapisz do lokalnej pamięci i IndexedDB
      await this.storeMessage(sessionToken, message);
      
      console.log('✅ Wiadomość odszyfrowana i zapisana');
      
    } catch (error) {
      console.error('❌ Błąd deszyfrowania wiadomości:', error);
      
      // Zapisz z informacją o błędzie
      message.content = '[Nie można odszyfrować]';
      message.decryption_error = true;
      await this.storeMessage(sessionToken, message);
    }
  }

  /**
   * Obsługuje wylogowanie użytkownika - ZAKTUALIZOWANA
   */
  async logout() {
    try {
      console.log('🚪 Rozpoczynam wylogowanie...');
      
      // 1. Wyczyść klucze kryptograficzne
      if (window.unifiedCrypto) {
        window.unifiedCrypto.clearAllKeys();
        console.log('🔑 Klucze kryptograficzne wyczyszczone');
      }
      
      // 2. Rozłącz Socket.IO
      if (window.wsHandler) {
        window.wsHandler.disconnect();
        console.log('🔌 Socket.IO rozłączony');
      }
      
      // 3. Wyczyść dane lokalne
      localStorage.clear();
      sessionStorage.clear();
      console.log('💾 Pamięć lokalna wyczyszczona');
      
      // 4. Wyczyść lokalne dane aplikacji
      this.activeSessions = [];
      this.friends = [];
      this.messages = {};
      
      // 5. Zamknij bazę danych
      if (this.db) {
        this.db.close();
        console.log('🗄️ Baza danych zamknięta');
      }
      
      // 6. Małe opóźnienie żeby wszystko się wykonało
      await new Promise(resolve => setTimeout(resolve, 500));
      
      console.log('✅ Wylogowanie zakończone, przekierowuję...');
      
    } catch (error) {
      console.error('❌ Błąd podczas wylogowania:', error);
    } finally {
      // 7. ZAWSZE przekieruj na endpoint logout (który przekieruje na /)
      console.log('🔄 Przekierowanie na /logout...');
      window.location.href = '/logout';
    }
  }
// Inicjalizacja globalnego SessionManager
window.sessionManager = new SecureSessionManager();
