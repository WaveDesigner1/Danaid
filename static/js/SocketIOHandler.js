/**
 * SocketIOHandler - POPRAWIONA obsługa dla lepszego real-time messaging
 * Tylko niewielkie zmiany dla lepszej współpracy z SecureSessionManager
 */

// DODANE: Lepsze obsługa zdarzeń Real-time w setupEventHandlers()
// 1. NAPRAWA: SocketIOHandler.js - zastąp metodę setupEventHandlers całkowicie
// (Usuń stary kod i wklej ten)

setupEventHandlers() {
  if (!this.socket) return;
  
  // Połączenie nawiązane
  this.socket.on('connect', () => {
    console.log('✅ Socket.IO połączony pomyślnie');
    this.isConnected = true;
    this._running = true;
    this.connectionAttempts = 0;
    
    // Zarejestruj użytkownika
    this.socket.emit('register_user', {
      user_id: this.userId
    });
    
    // Wyślij zaległe wiadomości
    this.processPendingMessages();
  });
  
  // Obsługa wiadomości
  this.socket.on('message', (data) => {
    console.log('📨 [SOCKET] Otrzymano wiadomość:', data.type);
    this.handleMessage(data);
  });
  
  // Nowe wiadomości
  this.socket.on('new_message', (data) => {
    console.log('🆕 [SOCKET] Nowa wiadomość');
    this.handleMessage({
      type: 'new_message',
      session_token: data.session_token,
      message: data.message
    });
  });
  
  // Błędy
  this.socket.on('error', (error) => {
    console.error('❌ Błąd Socket.IO:', error);
  });
  
  console.log('✅ Socket.IO handlers skonfigurowane');
}

// 2. NAPRAWA: SecureSessionManager.js - dodaj auto-wymianę kluczy w getActiveSessions
// (Dodaj na końcu metody getActiveSessions, przed return)

// DODAJ TO na końcu getActiveSessions() przed return:
for (const session of this.activeSessions) {
  if (session.needs_key_exchange && session.is_initiator && 
      !this.keyExchangeInProgress.has(session.token)) {
    console.log('🔑 Auto-wymiana kluczy dla sesji:', session.token?.substring(0, 10) + '...');
    setTimeout(() => {
      this.startAutomaticKeyExchange(session.token, session);
    }, 1000);
  }
}

// 3. NAPRAWA: Dodaj sprawdzenie klucza przed wysyłaniem w sendMessage
// (Zamień początek metody sendMessage w SecureSessionManager.js)

async sendMessage(sessionToken, content) {
  try {
    console.log('🚀 Wysyłanie wiadomości...');
    
    if (!window.unifiedCrypto) {
      throw new Error('UnifiedCrypto nie jest dostępny');
    }

    // NAPRAWIONE: Sprawdź i wygeneruj klucz jeśli brak
    let sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
    if (!sessionKeyBase64) {
      console.log('⚠️ Brak klucza sesji - próbuję wygenerować...');
      
      // Znajdź sesję
      const session = this.activeSessions.find(s => s.token === sessionToken);
      if (!session) {
        throw new Error('Nie znaleziono sesji');
      }
      
      // Uruchom wymianę kluczy
      if (session.is_initiator) {
        const keyResult = await this.startAutomaticKeyExchange(sessionToken, session);
        if (!keyResult.success) {
          throw new Error('Nie można wygenerować klucza: ' + keyResult.message);
        }
        
        // Poczekaj chwilę na klucz
        await new Promise(resolve => setTimeout(resolve, 2000));
        sessionKeyBase64 = window.unifiedCrypto.getSessionKey(sessionToken);
        
        if (!sessionKeyBase64) {
          throw new Error('Klucz nadal niedostępny - spróbuj ponownie');
        }
      } else {
        throw new Error('Czekam na klucz od rozmówcy - spróbuj za chwilę');
      }
    }
// POPRAWIONA: Obsługa wiadomości z lepszym routingiem
handleMessage(data) {
  try {
    console.log('🔄 [HANDLER] Przetwarzanie wiadomości typu:', data.type);
    
    // Wywołaj odpowiedni handler zdarzenia
    if (data.type && this.handlers[data.type]) {
      this.handlers[data.type](data);
    } else {
      console.warn('⚠️ [HANDLER] Brak handlera dla typu:', data.type);
      console.warn('⚠️ [HANDLER] Dostępne handlery:', Object.keys(this.handlers));
    }
  } catch (error) {
    console.error('❌ Błąd obsługi wiadomości Socket.IO:', error);
    console.error('❌ Data:', data);
  }
}

// DODANE: Metoda do synchronizacji po reconnect
requestSync() {
  if (this.isConnected && this.socket) {
    console.log('🔄 Żądanie synchronizacji danych...');
    this.socket.emit('sync_request', {
      user_id: this.userId,
      timestamp: new Date().toISOString()
    });
    return true;
  }
  return false;
}

// POPRAWIONA: Wysyłanie z lepszym debugowaniem
send(eventName, data) {
  if (!this.isConnected || !this.socket) {
    console.log('📤 [SEND] Socket nie połączony, dodaję do kolejki:', eventName);
    this.pendingMessages.push({ eventName, data });
    
    if (!this.isConnected && this.connectionAttempts < this.maxConnectionAttempts) {
      console.log('🔄 Socket.IO nie połączony, próba reconnect...');
      this.connect();
    }
    
    return false;
  }
  
  try {
    console.log('📤 [SEND] Wysyłanie:', {
      event: eventName,
      dataKeys: Object.keys(data || {}),
      timestamp: new Date().toISOString()
    });
    
    this.socket.emit(eventName, data);
    return true;
  } catch (error) {
    console.error('❌ Błąd wysyłania wiadomości Socket.IO:', error);
    this.pendingMessages.push({ eventName, data });
    return false;
  }
}

// DODANE: Metoda do wysyłania heartbeat
sendHeartbeat() {
  if (this.isConnected) {
    return this.send('heartbeat', {
      user_id: this.userId,
      timestamp: new Date().toISOString()
    });
  }
  return false;
}

// POPRAWIONA: Restart z synchronizacją
restart() {
  console.log('🔄 Restartowanie połączenia Socket.IO...');
  this.close();
  this.connectionAttempts = 0;
  setTimeout(() => {
    this.connect().then(() => {
      // Po reconnect poproś o synchronizację
      setTimeout(() => {
        this.requestSync();
      }, 1000);
    });
  }, 1000);
}
