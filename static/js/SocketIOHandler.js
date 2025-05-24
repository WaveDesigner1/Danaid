/**
 * SocketIOHandler - POPRAWIONA obsługa dla lepszego real-time messaging
 * Tylko niewielkie zmiany dla lepszej współpracy z SecureSessionManager
 */

// DODANE: Lepsze obsługa zdarzeń Real-time w setupEventHandlers()
setupEventHandlers() {
  if (!this.socket) return;
  
  // Połączenie nawiązane
  this.socket.on('connect', () => {
    console.log('✅ Socket.IO połączony pomyślnie');
    console.log('Socket ID:', this.socket.id);
    this.isConnected = true;
    this._running = true;
    this.connectionAttempts = 0;
    
    // Zarejestruj użytkownika
    this.socket.emit('register_user', {
      user_id: this.userId
    });
    
    // Wyślij zaległe wiadomości
    this.processPendingMessages();
    
    // NOWE: Poproś o synchronizację po połączeniu
    this.socket.emit('sync_request', {
      user_id: this.userId,
      timestamp: new Date().toISOString()
    });
  });
  
  // Rozłączenie
  this.socket.on('disconnect', (reason) => {
    this.isConnected = false;
    this._running = false;
    console.log(`🔌 Socket.IO rozłączony: ${reason}`);
    
    if (reason !== 'io client disconnect') {
      console.log('⏳ Automatyczne połączenie ponowne...');
    }
  });
  
  // Błędy połączenia
  this.socket.on('connect_error', (error) => {
    console.error('❌ Błąd połączenia Socket.IO:', error);
    this.isConnected = false;
    
    if (error.message && error.message.includes('Mixed Content')) {
      console.error('🚨 Problem z Mixed Content - sprawdź konfigurację HTTPS/WSS');
    }
  });
  
  // Potwierdzenie połączenia
  this.socket.on('connection_ack', (data) => {
    console.log('✅ Połączenie Socket.IO potwierdzone:', data.message);
  });
  
  // POPRAWIONA: Otrzymane wiadomości - lepsze debugowanie
  this.socket.on('message', (data) => {
    console.log('📨 [SOCKET] Otrzymano wiadomość:', {
      type: data.type,
      hasSessionToken: !!data.session_token,
      hasMessage: !!data.message,
      messageId: data.message?.id
    });
    this.handleMessage(data);
  });
  
  // DODANE: Obsługa nowych wiadomości (dedykowane zdarzenie)
  this.socket.on('new_message', (data) => {
    console.log('🆕 [SOCKET] Dedykowane zdarzenie new_message:', {
      session_token: data.session_token?.substring(0, 10) + '...',
      message_id: data.message?.id,
      sender_id: data.message?.sender_id,
      content_preview: data.message?.content?.substring(0, 30) + '...'
    });
    
    // Przekaż do głównego handlera
    this.handleMessage({
      type: 'new_message',
      session_token: data.session_token,
      message: data.message
    });
  });
  
  // DODANE: Obsługa wymiany kluczy
  this.socket.on('session_key_received', (data) => {
    console.log('🔑 [SOCKET] Otrzymano klucz sesji:', {
      session_token: data.session_token?.substring(0, 10) + '...',
      has_encrypted_key: !!data.encrypted_key
    });
    
    this.handleMessage({
      type: 'session_key_received',
      session_token: data.session_token,
      encrypted_key: data.encrypted_key
    });
  });
  
  // DODANE: Potwierdzenie zakończenia wymiany kluczy
  this.socket.on('key_exchange_completed', (data) => {
    console.log('✅ [SOCKET] Wymiana kluczy zakończona:', {
      session_token: data.session_token?.substring(0, 10) + '...'
    });
    
    this.handleMessage({
      type: 'key_exchange_completed',
      session_token: data.session_token
    });
  });
  
  // Potwierdzenie dostarczenia wiadomości
  this.socket.on('message_delivered', (data) => {
    console.log('✅ Wiadomość dostarczona:', data);
    if (this.handlers['message_delivered']) {
      this.handlers['message_delivered'](data);
    }
  });
  
  // DODANE: Synchronizacja po reconnect
  this.socket.on('sync_response', (data) => {
    console.log('🔄 [SOCKET] Otrzymano dane synchronizacji:', {
      sessions_count: data.sessions?.length || 0,
      messages_count: data.messages?.length || 0
    });
    
    // Przekaż dane synchronizacji do handlera
    if (data.sessions) {
      this.handleMessage({
        type: 'session_update',
        sessions: data.sessions
      });
    }
    
    if (data.messages) {
      data.messages.forEach(msg => {
        this.handleMessage({
          type: 'new_message',
          session_token: msg.session_token,
          message: msg
        });
      });
    }
  });
  
  // Błędy od serwera
  this.socket.on('error', (error) => {
    console.error('❌ Błąd od serwera Socket.IO:', error);
  });
  
  // Ping/Pong dla keep-alive
  this.socket.on('pong', (data) => {
    console.log('🏓 Otrzymano pong:', data.timestamp);
  });
  
  // DODANE: Status użytkowników online
  this.socket.on('user_status_change', (data) => {
    console.log('🟢 [SOCKET] Zmiana statusu użytkownika:', {
      user_id: data.user_id,
      is_online: data.is_online
    });
    
    this.handleMessage({
      type: 'user_status_change',
      user_id: data.user_id,
      is_online: data.is_online
    });
  });
  
  this.socket.on('online_users', (data) => {
    console.log('👥 [SOCKET] Lista użytkowników online:', data.users?.length || 0);
    
    this.handleMessage({
      type: 'online_users',
      users: data.users
    });
  });
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
