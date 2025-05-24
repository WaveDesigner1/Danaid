/**
 * SecureSessionManager - UPROSZCZONA wersja BEZ Socket.IO
 */
let messageLoadingInProgress = new Set();
let fetchingInProgress = new Set();

class SecureSessionManager {
  constructor() {
    this.activeSessions = [];
    this.friends = [];
    this.onlineUsers = [];
    this.messages = {};
    this.currentSessionId = null;
    this.keyExchangeInProgress = new Set();
    this.user = {
      id: sessionStorage.getItem('user_id'),
      username: sessionStorage.getItem('username'),
      isAdmin: sessionStorage.getItem('is_admin') === 'true',
      isLoggedIn: sessionStorage.getItem('isLoggedIn') === 'true'
    };

    // Inicjalizacja bazy danych
    this.initDatabase();
    
    // UPROSZCZONE: Bez Socket.IO na razie
    console.log("⚠️ Socket.IO wyłączony - tylko podstawowe funkcje");

    // Callbacks
    this.onMessageReceived = null;
    this.onSessionsUpdated = null;
    this.onFriendsUpdated = null;
    this.onOnlineStatusChanged = null;
    this.onFriendRequestReceived = null;
    
    console.log("SecureSessionManager zainicjalizowany (UPROSZCZONY)", this.user);
  }

  /**
   * UPROSZCZONE: Socket.IO wyłączony
   */
  setupSocketIOHandlers() {
    console.log("⚠️ Socket.IO handlers wyłączone - tylko podstawowe funkcje");
    // Metoda pusta - bez błędów
  }

  /**
   * Znajdź istniejącą sesję z użytkownikiem
   */
  findExistingSession(userId) {
    const existingSession = this.activeSessions.find(session => 
      session.other_user && session.other_user.user_id === parseInt(userId)
    );
    
    if (existingSession) {
      console.log('✅ Znaleziono istniejącą sesję:', existingSession.token?.substring(0, 10) + '...');
      return existingSession;
    }
    
    console.log('❌ Brak istniejącej sesji z użytkownikiem:', userId);
    return null;
  }

  /**
   * UPROSZCZONA: Automatyczna wymiana kluczy
   */
  async startAutomaticKeyExchange(sessionToken, sessionData) {
    try {
      console.log('🚀 Auto-start wymiany kluczy:', sessionToken?.substring(0, 10) + '...');
      
      // Sprawdź czy wymiana nie jest już w toku
      if (this.keyExchangeInProgress.has(sessionToken)) {
        console.log('⏳ Wymiana kluczy już w toku');
        return { success: false, message: 'Wymiana w toku' };
      }
      
      // Dodaj do listy w toku
      this.keyExchangeInProgress.add(sessionToken);
      
      // Sprawdź czy jesteśmy inicjatorem
      if (!sessionData.is_initiator) {
        console.log('⏳ Czekam na klucz od inicjatora...');
        return { success: true, message: 'Czekam na klucz' };
      }
      
      console.log('🔑 Jestem inicjatorem - generuję klucz...');
      
      // Wygeneruj klucz sesji AES
      const sessionKey = await window.unifiedCrypto.generateSessionKey();
      const sessionKeyBase64 = await window.unifiedCrypto.exportSessionKey(sessionKey);
      
      // Zapisz klucz lokalnie
      window.unifiedCrypto.storeSessionKey(sessionToken, sessionKeyBase64);
      
      // Pobierz klucz publiczny odbiorcy
      const recipientResponse = await fetch(`/api/user/${sessionData.other_user.user_id}/public_key`);
      if (!recipientResponse.ok) {
        throw new Error('Nie można pobrać klucza publicznego');
      }
      
      const keyData = await recipientResponse.json();
      const recipientPublicKey = await window.unifiedCrypto.importPublicKeyFromPEM(keyData.public_key);
      
      // Zaszyfruj klucz sesji
      const encryptedKey = await window.unifiedCrypto.encryptSessionKey(recipientPublicKey, sessionKey);
      
      // Wyślij na serwer
      const response = await fetch(`/api/session/${sessionToken}/exchange_key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify({ encrypted_key: encryptedKey })
      });
      
      if (!response.ok) {
        throw new Error('Błąd wymiany klucza');
      }
      
      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.message || 'Błąd API');
      }
      
      console.log('✅ Klucz sesji wysłany automatycznie');
      
      return { success: true, message: 'Klucz wysłany' };
      
    } catch (error) {
      console.error('❌ Błąd auto-wymiany kluczy:', error);
      this.keyExchangeInProgress.delete(sessionToken);
      return { success: false, message: error.message };
    }
  }

/**
   * UPROSZCZONA: Obsługa otrzymanego klucza
   */
  async handleReceivedSessionKey(sessionToken, encryptedKey) {
    try {
      console.log('🔑 Auto-obsługa otrzymanego klucza:', sessionToken?.substring(0, 10) + '...');
      
      if (!window.unifiedCrypto.hasPrivateKey()) {
        throw new Error('Brak klucza prywatnego');
      }
      
      // Odszyfruj klucz sesji
      const sessionKeyBase64 = await window.unifiedCrypto.decryptSessionKey(encryptedKey);
      window.unifiedCrypto.storeSessionKey(sessionToken, sessionKeyBase64);
      
      console.log('✅ Klucz automatycznie odszyfrowany');
      
      // Automatyczne potwierdzenie
      const ackResponse = await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
      });
      
      if (ackResponse.ok) {
        console.log('✅ Klucz automatycznie potwierdzony');
      }
      
      // Usuń z listy w toku
      this.keyExchangeInProgress.delete(sessionToken);
      
      // Odśwież sesje
      this.getActiveSessions();
      
    } catch (error) {
      console.error('❌ Błąd auto-obsługi klucza:', error);
      this.keyExchangeInProgress.delete(sessionToken);
    }
  }

  /**
   * UPROSZCZONA: Obsługa przychodzących wiadomości
   */
  async handleIncomingMessage(sessionToken, message) {
    try {
      console.log('📨 Auto-obsługa wiadomości:', sessionToken?.substring(0, 10) + '...');
      
      // Sprawdź czy mamy klucz sesji
      if (!window.unifiedCrypto.hasSessionKey(sessionToken)) {
        console.warn('⚠️ Brak klucza - próbuję pobrać...');
        
        const keyResult = await this.retrieveSessionKey(sessionToken);
        if (!keyResult.success) {
          console.error('❌ Nie można pobrać klucza');
          message.content = '[Nie można odszyfrować - brak klucza]';
          message.decryption_error = true;
        }
      }
      
      // Automatyczne deszyfrowanie
      if (message.content && message.iv && !message.decryption_error) {
        try {
          const sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
          if (sessionKeyBase64) {
            const sessionKey = await window.unifiedCrypto.importSessionKey(sessionKeyBase64);
            const decryptedContent = await window.unifiedCrypto.decryptMessage(sessionKey, {
              data: message.content,
              iv: message.iv
            });
            
            message.content = decryptedContent;
            console.log('✅ Auto-deszyfrowanie OK');
          }
        } catch (decryptError) {
          console.error('❌ Błąd deszyfrowania:', decryptError);
          message.content = '[Błąd deszyfrowania]';
          message.decryption_error = true;
        }
      }
      
      // Automatyczne zapisanie
      await this.storeMessage(sessionToken, message);
      
      // Wyświetlenie w UI
      if (this.onMessageReceived) {
        this.onMessageReceived(sessionToken, message);
      }
      
    } catch (error) {
      console.error('❌ Błąd obsługi wiadomości:', error);
    }
  }

  /**
   * UPROSZCZONA: Inicjalizacja sesji
   */
  async initSession(recipientId) {
    try {
      if (!this.user.id) {
        throw new Error("Użytkownik nie jest zalogowany");
      }
      
      console.log('🔍 Sprawdzanie sesji z użytkownikiem:', recipientId);
      
      // Sprawdź czy sesja już istnieje
      const existingSession = this.findExistingSession(recipientId);
      if (existingSession) {
        console.log('♻️ Używam istniejącej sesji:', existingSession.token);
        
        // Sprawdź czy potrzebuje wymiany kluczy
        if (existingSession.needs_key_exchange && !this.keyExchangeInProgress.has(existingSession.token)) {
          console.log('🔑 Automatyczne uruchomienie wymiany kluczy...');
          this.startAutomaticKeyExchange(existingSession.token, existingSession);
        }
        
        return {
          status: 'success',
          session_token: existingSession.token,
          session: existingSession,
          isExisting: true
        };
      }
      
      // Jeśli nie ma sesji - utwórz nową
      console.log('🆕 Tworzenie nowej sesji...');
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
      console.log("✅ Nowa sesja utworzona:", session.token?.substring(0, 10) + '...');
      
      // Automatycznie rozpocznij wymianę kluczy dla nowej sesji
      if (session.needs_key_exchange) {
        console.log('🔑 Auto-start wymiany kluczy dla nowej sesji...');
        setTimeout(() => {
          this.startAutomaticKeyExchange(session.token, session);
        }, 500);
      }
      
      // Aktualizuj listy
      await this.getActiveSessions();
      
      return {
        status: 'success',
        session_token: session.token,
        session: session,
        isExisting: false
      };
      
    } catch (error) {
      console.error('❌ Błąd inicjacji sesji:', error);
      return {
        status: 'error',
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
      
      // Auto-wymiana kluczy dla sesji które jej potrzebują
      for (const session of this.activeSessions) {
        if (session.needs_key_exchange && session.is_initiator && 
            !this.keyExchangeInProgress.has(session.token)) {
          console.log('🔑 Auto-wymiana kluczy dla sesji:', session.token?.substring(0, 10) + '...');
          setTimeout(() => {
            this.startAutomaticKeyExchange(session.token, session);
          }, 1000);
        }
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
      if (!window.unifiedCrypto) {
        throw new Error('UnifiedCrypto nie jest dostępny');
      }

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
      
      const sessionKeyBase64 = await window.unifiedCrypto.decryptSessionKey(data.encrypted_key);
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
   * UPROSZCZONA: Wysyłanie wiadomości z szyfrowaniem
   */
  async sendMessage(sessionToken, content) {
    try {
      console.log('🚀 Wysyłanie wiadomości...');
      
      if (!window.unifiedCrypto) {
        throw new Error('UnifiedCrypto nie jest dostępny');
      }

      // Sprawdź i wygeneruj klucz jeśli brak
      let sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
      if (!sessionKeyBase64) {
        console.log('⚠️ Brak klucza sesji - próbuję wygenerować...');
        
        // Znajdź sesję
        const session = this.activeSessions.find(s => s.token === sessionToken);
        if (!session) {
          throw new Error('Nie znaleziono sesji');
        }
        
        // Uruchom wymianę kluczy jeśli jesteśmy inicjatorem
        if (session.is_initiator) {
          console.log('🔑 Generuję klucz jako inicjator...');
          const keyResult = await this.startAutomaticKeyExchange(sessionToken, session);
          if (!keyResult.success) {
            throw new Error('Nie można wygenerować klucza: ' + keyResult.message);
          }
          
          // Poczekaj chwilę na wygenerowanie klucza
          await new Promise(resolve => setTimeout(resolve, 2000));
          sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
          
          if (!sessionKeyBase64) {
            throw new Error('Klucz nadal niedostępny - spróbuj ponownie za chwilę');
          }
        } else {
          throw new Error('Czekam na klucz od rozmówcy - spróbuj za chwilę');
        }
      }
      
      // Sprawdź sesję ponownie
      const session = this.activeSessions.find(s => s.token === sessionToken);
      if (!session || !session.other_user?.user_id) {
        throw new Error('Nie znaleziono sesji lub danych odbiorcy');
      }
      
      console.log('✅ Klucz sesji dostępny, rozpoczynam szyfrowanie...');
      
      // Szyfrowanie
      const sessionKey = await window.unifiedCrypto.importSessionKey(sessionKeyBase64);
      const encryptedData = await window.unifiedCrypto.encryptMessage(sessionKey, content);
      
      const payload = {
        session_token: sessionToken,
        recipient_id: parseInt(session.other_user.user_id),
        content: encryptedData.data,
        iv: encryptedData.iv
      };
      
      console.log('📤 Wysyłanie zaszyfrowanej wiadomości...');
      
      const response = await fetch('/api/message/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ Błąd HTTP:', response.status, errorText);
        throw new Error(`Błąd serwera ${response.status}: ${errorText}`);
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

  async logout() {
    try {
      console.log('🚪 Rozpoczynam wylogowanie...');
      
      // 1. Wyczyść klucze kryptograficzne
      if (window.unifiedCrypto) {
        window.unifiedCrypto.clearAllKeys();
        console.log('🔑 Klucze kryptograficzne wyczyszczone');
      }
      
      // 2. Wyczyść dane lokalne
      localStorage.clear();
      sessionStorage.clear();
      console.log('💾 Pamięć lokalna wyczyszczona');
      
      // 3. Wyczyść lokalne dane aplikacji
      this.activeSessions = [];
      this.friends = [];
      this.messages = {};
      this.keyExchangeInProgress.clear();
      
      // 4. Zamknij bazę danych
      if (this.db) {
        this.db.close();
        console.log('🗄️ Baza danych zamknięta');
      }
      
      // 5. Małe opóźnienie żeby wszystko się wykonało
      await new Promise(resolve => setTimeout(resolve, 500));
      
      console.log('✅ Wylogowanie zakończone, przekierowuję...');
      
    } catch (error) {
      console.error('❌ Błąd podczas wylogowania:', error);
    } finally {
      // 6. ZAWSZE przekieruj na endpoint logout
      console.log('🔄 Przekierowanie na /logout...');
      window.location.href = '/logout';
    }
  }
}

// Inicjalizacja globalnego SessionManager
try {
  window.sessionManager = new SecureSessionManager();
  console.log("✅ SecureSessionManager UPROSZCZONY zainicjalizowany pomyślnie");
} catch (error) {
  console.error("❌ Błąd inicjalizacji SecureSessionManager:", error);
  
  // Fallback - spróbuj ponownie po chwili
  setTimeout(() => {
    try {
      window.sessionManager = new SecureSessionManager();
      console.log("✅ SecureSessionManager zainicjalizowany (retry)");
    } catch (retryError) {
      console.error("❌ Ponowny błąd SecureSessionManager:", retryError);
    }
  }, 1000);
}
      
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

  getLocalMessages(sessionToken) {
    console.log('📥 getLocalMessages dla:', sessionToken);
    
    if (!sessionToken) {
      return {
        status: 'error',
        message: 'Brak tokenu sesji',
        messages: []
      };
    }
    
    if (!this.messages[sessionToken]) {
      return {
        status: 'success',
        messages: []
      };
    }
    
    const messages = this.messages[sessionToken];
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

  async fetchMessagesFromServer(sessionToken) {
    try {
      // ZABEZPIECZENIE: Sprawdź czy już pobieramy dla tej sesji
      if (fetchingInProgress.has(sessionToken)) {
        console.log('⚠️ Pobieranie wiadomości już w toku dla:', sessionToken?.substring(0, 10) + '...');
        return {
          status: 'error',
          message: 'Pobieranie już w toku',
          messages: []
        };
      }

      // Dodaj do listy w toku
      fetchingInProgress.add(sessionToken);
      
      console.log('🌐 Pobieranie wiadomości z serwera dla:', sessionToken?.substring(0, 10) + '...');
      
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
          decryptedMessages.push({
            ...message,
            content: '[Nie można odszyfrować wiadomości]',
            decryption_error: true
          });
        }
      }
      
      // Zapisz wiadomości lokalnie (zapobiegaj duplikatom)
      for (const message of decryptedMessages) {
        await this.storeMessage(sessionToken, message);
      }
      
      console.log(`✅ Pobrano i odszyfrowano ${decryptedMessages.length} wiadomości`);
      
      return {
        status: 'success',
        messages: decryptedMessages
      };
      
    } catch (error) {
      console.error('❌ Błąd pobierania wiadomości z serwera:', error);
      return {
        status: 'error',
        message: error.message,
        messages: []
      };
    } finally {
      // WAŻNE: Zawsze usuń z listy w toku
      fetchingInProgress.delete(sessionToken);
    }
  }

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

    
