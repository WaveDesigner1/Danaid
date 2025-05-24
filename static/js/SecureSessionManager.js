/**
 * SecureSessionManager - POPRAWIONA wersja z automatyczną wymianą kluczy
 * Używa UnifiedCrypto i SocketIOHandler z automatyczną obsługą real-time
 */
class SecureSessionManager {
  constructor() {
    this.activeSessions = [];
    this.friends = [];
    this.onlineUsers = [];
    this.messages = {};
    this.currentSessionId = null;
    this.keyExchangeInProgress = new Set(); // NOWE: Śledzenie wymian kluczy w toku
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
    this.onKeyExchangeCompleted = null; // NOWE: Callback po zakończeniu wymiany kluczy
    
    console.log("SecureSessionManager zainicjalizowany z automatyczną wymianą kluczy", this.user);
  }

  /**
   * POPRAWIONA: Konfiguruje handlery dla SocketIOHandler z obsługą wymiany kluczy
   */
  setupSocketIOHandlers() {
    const setupHandlers = () => {
      if (!window.wsHandler) {
        console.error("SocketIOHandler nie jest dostępny globalnie");
        return;
      }
      
      // Obsługa nowych wiadomości
      window.wsHandler.on('new_message', (data) => {
        console.log("🆕 [SOCKET] Otrzymano nową wiadomość:", data);
        
        try {
          if (data.message && data.message.sender_id && 
              parseInt(data.message.sender_id) === parseInt(this.user.id)) {
            console.log("↩️ To nasza własna wiadomość, pomijam");
            return;
          }
          
          // Automatycznie odszyfruj i zapisz wiadomość
          this.handleIncomingMessage(data.session_token, data.message);
          
        } catch (error) {
          console.error("❌ Błąd przetwarzania wiadomości Socket.IO:", error);
        }
      });
      
      // NOWE: Obsługa otrzymania klucza sesji
      window.wsHandler.on('session_key_received', (data) => {
        console.log("🔑 [SOCKET] Otrzymano klucz sesji:", data);
        
        try {
          this.handleReceivedSessionKey(data.session_token, data.encrypted_key);
        } catch (error) {
          console.error("❌ Błąd obsługi otrzymanego klucza:", error);
        }
      });
      
      // NOWE: Obsługa zakończenia wymiany kluczy
      window.wsHandler.on('key_exchange_completed', (data) => {
        console.log("✅ [SOCKET] Wymiana kluczy zakończona:", data);
        
        try {
          this.keyExchangeInProgress.delete(data.session_token);
          
          // Odśwież listę sesji
          this.getActiveSessions();
          
          // Wywołaj callback jeśli istnieje
          if (this.onKeyExchangeCompleted) {
            this.onKeyExchangeCompleted(data.session_token);
          }
          
          console.log("🎉 Sesja gotowa do messaging:", data.session_token);
          
        } catch (error) {
          console.error("❌ Błąd obsługi zakończenia wymiany kluczy:", error);
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
      
      // Obsługa błędów Socket.IO
      window.wsHandler.on('error', (error) => {
        console.error("❌ [SOCKET] Błąd Socket.IO:", error);
      });

      // Obsługa rozłączenia
      window.wsHandler.on('disconnect', (reason) => {
        console.warn("🔌 [SOCKET] Rozłączono:", reason);
      });

      // Test połączenia
      window.wsHandler.on('connect', () => {
        console.log("✅ [SOCKET] Połączono - odświeżam dane...");
        
        // Po połączeniu odśwież dane
        setTimeout(() => {
          this.getActiveSessions();
          this.fetchFriends();
        }, 1000);
      });
      
      console.log("✅ Socket.IO handlers z wymianą kluczy skonfigurowane");
    };

    // Spróbuj teraz, jeśli nie to czekaj
    if (window.wsHandler) {
      setupHandlers();
    } else {
      setTimeout(setupHandlers, 1000);
    }
  }

  /**
   * NOWA: Obsługuje przychodzące wiadomości z automatycznym deszyfrowaniem
   */
  async handleIncomingMessage(sessionToken, message) {
    try {
      console.log('📨 Obsługa przychodzącej wiadomości:', {
        sessionToken: sessionToken?.substring(0, 10) + '...',
        messageId: message.id,
        hasContent: !!message.content
      });
      
      // Sprawdź czy mamy klucz sesji
      if (!window.unifiedCrypto.hasSessionKey(sessionToken)) {
        console.warn('⚠️ Brak klucza sesji, próbuję pobrać...');
        
        const keyResult = await this.retrieveSessionKey(sessionToken);
        if (!keyResult.success) {
          console.error('❌ Nie można pobrać klucza sesji:', keyResult.message);
          // Zapisz wiadomość jako niezdeszyfrowaną
          message.content = '[Nie można odszyfrować - brak klucza]';
          message.decryption_error = true;
        }
      }
      
      // Spróbuj odszyfrować wiadomość
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
            console.log('✅ Wiadomość odszyfrowana:', decryptedContent.substring(0, 50) + '...');
          }
        } catch (decryptError) {
          console.error('❌ Błąd deszyfrowania:', decryptError);
          message.content = '[Błąd deszyfrowania]';
          message.decryption_error = true;
        }
      }
      
      // Zapisz wiadomość
      await this.storeMessage(sessionToken, message);
      
      // Wywołaj callback dla UI
      if (this.onMessageReceived) {
        this.onMessageReceived(sessionToken, message);
      }
      
    } catch (error) {
      console.error('❌ Błąd obsługi przychodzącej wiadomości:', error);
    }
  }

  /**
   * NOWA: Obsługuje otrzymany klucz sesji
   */
  async handleReceivedSessionKey(sessionToken, encryptedKey) {
    try {
      console.log('🔑 Obsługa otrzymanego klucza sesji:', sessionToken?.substring(0, 10) + '...');
      
      if (!window.unifiedCrypto || !window.unifiedCrypto.hasPrivateKey()) {
        throw new Error('Brak klucza prywatnego do odszyfrowania');
      }
      
      // Odszyfruj klucz sesji
      const sessionKeyBase64 = await window.unifiedCrypto.decryptSessionKey(encryptedKey);
      
      // Zapisz klucz sesji
      window.unifiedCrypto.storeSessionKey(sessionToken, sessionKeyBase64);
      
      console.log('✅ Klucz sesji odszyfrowany i zapisany');
      
      // Potwierdź odebranie klucza
      const response = await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
      });
      
      if (response.ok) {
        const result = await response.json();
        if (result.status === 'success') {
          console.log('✅ Klucz sesji potwierdzony na serwerze');
          
          // Usuń z listy w toku
          this.keyExchangeInProgress.delete(sessionToken);
          
          // Odśwież listę sesji
          this.getActiveSessions();
        }
      }
      
    } catch (error) {
      console.error('❌ Błąd obsługi otrzymanego klucza sesji:', error);
      this.keyExchangeInProgress.delete(sessionToken);
    }
  }ługa nowych sesji utworzonych przez innych
      window.wsHandler.on('new_session_created', (data) => {
        console.log("🆕 [SOCKET] Ktoś utworzył nową sesję z nami:", data);
        
        // Odśwież listę aktywnych sesji
        this.getActiveSessions();
        
        // Jeśli to powiadomienie o nowej sesji, przygotuj się na wymianę kluczy
        if (data.session_token) {
          console.log("🔑 Przygotowuję się na wymianę kluczy dla sesji:", data.session_token);
        }
      });
  /**
   * NOWA: Automatycznie rozpoczyna wymianę kluczy dla sesji
   */
  async startAutomaticKeyExchange(sessionToken, sessionData) {
    try {
      console.log('🚀 Rozpoczynam automatyczną wymianę kluczy dla:', sessionToken?.substring(0, 10) + '...');
      
      // Sprawdź czy wymiana nie jest już w toku
      if (this.keyExchangeInProgress.has(sessionToken)) {
        console.log('⏳ Wymiana kluczy już w toku dla tej sesji');
        return { success: false, message: 'Wymiana kluczy w toku' };
      }
      
      // Dodaj do listy w toku
      this.keyExchangeInProgress.add(sessionToken);
      
      // Sprawdź czy jesteśmy inicjatorem
      if (!sessionData.is_initiator) {
        console.log('⏳ Czekam na klucz od inicjatora...');
        return { success: true, message: 'Czekam na klucz' };
      }
      
      console.log('🔑 Jestem inicjatorem - generuję klucz sesji...');
      
      // Wygeneruj nowy klucz sesji AES
      const sessionKey = await window.unifiedCrypto.generateSessionKey();
      const sessionKeyBase64 = await window.unifiedCrypto.exportSessionKey(sessionKey);
      
      // Zapisz klucz lokalnie
      window.unifiedCrypto.storeSessionKey(sessionToken, sessionKeyBase64);
      
      // Pobierz klucz publiczny odbiorcy
      const recipientPublicKeyResponse = await fetch(`/api/user/${sessionData.other_user.user_id}/public_key`);
      if (!recipientPublicKeyResponse.ok) {
        throw new Error('Nie można pobrać klucza publicznego odbiorcy');
      }
      
      const recipientKeyData = await recipientPublicKeyResponse.json();
      const recipientPublicKey = await window.unifiedCrypto.importPublicKeyFromPEM(recipientKeyData.public_key);
      
      // Zaszyfruj klucz sesji kluczem publicznym odbiorcy
      const encryptedSessionKey = await window.unifiedCrypto.encryptSessionKey(recipientPublicKey, sessionKey);
      
      // Wyślij zaszyfrowany klucz na serwer
      const keyExchangeResponse = await fetch(`/api/session/${sessionToken}/exchange_key`, {
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
      
      console.log('✅ Klucz sesji wygenerowany i wysłany, czekam na potwierdzenie...');
      
      return { success: true, message: 'Klucz wysłany, czekam na potwierdzenie' };
      
    } catch (error) {
      console.error('❌ Błąd automatycznej wymiany kluczy:', error);
      this.keyExchangeInProgress.delete(sessionToken);
      return { success: false, message: error.message };
    }
  }

  // Inicjalizuje bazę danych IndexedDB - BEZ ZMIAN
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

  // Pobieranie wiadomości z lokalnego magazynu - BEZ ZMIAN
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

  // Zapisywanie wiadomości do lokalnego magazynu - BEZ ZMIAN
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
   * Pobieranie lokalnych wiadomości z obsługą deszyfrowania - BEZ ZMIAN
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
   * POPRAWIONA: Inicjalizacja sesji czatu z automatyczną wymianą kluczy
   */
  async initSession(recipientId) {
    try {
      if (!this.user.id) {
        throw new Error("Użytkownik nie jest zalogowany");
      }
      
      console.log('🚀 Inicjalizacja sesji z:', recipientId);
      
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
      console.log("✅ Sesja zainicjowana:", {
        token: session.token?.substring(0, 10) + '...',
        needs_key_exchange: session.needs_key_exchange,
        auto_start: session.auto_start_key_exchange
      });
      
      // NOWE: Automatycznie rozpocznij wymianę kluczy jeśli potrzeba
      if (session.needs_key_exchange && session.auto_start_key_exchange) {
        console.log('🔑 Automatyczne rozpoczęcie wymiany kluczy...');
        
        // Małe opóźnienie żeby dać czas na setup
        setTimeout(async () => {
          const keyResult = await this.startAutomaticKeyExchange(session.token, session);
          
          if (keyResult.success) {
            console.log('✅ Wymiana kluczy rozpoczęta:', keyResult.message);
          } else {
            console.error('❌ Błąd wymiany kluczy:', keyResult.message);
          }
        }, 500);
      }
      
      // Aktualizuj listy
      await this.getActiveSessions();
      
      return {
        status: 'success',
        session_token: session.token,
        session: session
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
   * POPRAWIONA: Pobieranie aktywnych sesji z obsługą stanu wymiany kluczy
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
      
      console.log('📋 Zaktualizowane sesje:', {
        total: this.activeSessions.length,
        ready: this.activeSessions.filter(s => s.is_ready).length,
        pending_keys: this.activeSessions.filter(s => s.needs_key_exchange).length
      });
      
      // NOWE: Automatycznie sprawdź które sesje potrzebują wymiany kluczy
      for (const session of this.activeSessions) {
        if (session.needs_key_exchange && !this.keyExchangeInProgress.has(session.token)) {
          
          // Jeśli jesteśmy inicjatorem i nie ma klucza, rozpocznij wymianę
          if (session.is_initiator && !session.has_key) {
            console.log('🔑 Automatyczne uruchomienie wymiany kluczy dla sesji:', session.token?.substring(0, 10) + '...');
            
            setTimeout(async () => {
              await this.startAutomaticKeyExchange(session.token, session);
            }, 100);
          }
          // Jeśli nie jesteśmy inicjatorem, ale sesja ma klucz i nie został potwierdzony
          else if (!session.is_initiator && session.has_key && !session.key_acknowledged) {
            console.log('🔑 Próbuję pobrać i potwierdzić klucz sesji:', session.token?.substring(0, 10) + '...');
            
            setTimeout(async () => {
              const keyResult = await this.retrieveSessionKey(session.token);
              if (keyResult.success) {
                console.log('✅ Klucz sesji pobrany i potwierdzony automatycznie');
              }
            }, 100);
          }
        }
      }
      
      if (this.onSessionsUpdated) {
        this.onSessionsUpdated(this.activeSessions);
      }
      
      return {
        status: 'success',
        sessions: this.activeSessions
      };
      
    } catch (error) {
      console.error('❌ Błąd pobierania aktywnych sesji:', error);
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  /**
   * POPRAWIONA: Pobieranie klucza sesji z automatycznym potwierdzeniem
   */
  async retrieveSessionKey(sessionToken) {
    try {
      console.log('🔑 Pobieranie klucza sesji dla:', sessionToken?.substring(0, 10) + '...');
      
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
      
      // Odszyfruj klucz sesji używając UnifiedCrypto
      const sessionKeyBase64 = await window.unifiedCrypto.decryptSessionKey(data.encrypted_key);
      
      // Zapisz klucz sesji
      window.unifiedCrypto.storeSessionKey(sessionToken, sessionKeyBase64);
      
      console.log('✅ Klucz sesji odszyfrowany i zapisany');
      
      // AUTOMATYCZNE: Potwierdź odebranie klucza
      const ackResponse = await fetch(`/api/session/${sessionToken}/acknowledge_key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
      });
      
      if (ackResponse.ok) {
        const ackResult = await ackResponse.json();
        if (ackResult.status === 'success') {
          console.log('✅ Klucz sesji automatycznie potwierdzony');
        }
      }
      
      return {
        success: true,
        message: 'Klucz sesji odebrany i potwierdzony automatycznie'
      };
      
    } catch (error) {
      console.error('❌ Błąd pobierania klucza sesji:', error);
      return {
        success: false,
        message: error.message
      };
    }
  }
