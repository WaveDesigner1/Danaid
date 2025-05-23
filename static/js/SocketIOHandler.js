/**
 * SocketIOHandler - Obsługa połączeń Socket.IO dla Railway
 * Zastępuje WebSocketHandler.js
 */
class SocketIOHandler {
  constructor() {
    this.socket = null;
    this.connectionAttempts = 0;
    this.maxConnectionAttempts = 5;
    this.reconnectInterval = 5000;
    this.handlers = {};
    this.userId = sessionStorage.getItem('user_id');
    this.isConnected = false;
    this.pendingMessages = [];
    this._running = false;
    
    console.log('SocketIOHandler initialized with user ID:', this.userId);
    
    // Automatyczne łączenie po inicjalizacji
    if (this.userId) {
      this.connect();
    }
  }
  
  /**
   * Łączy się z serwerem Socket.IO
   */
  async connect() {
    if (this.connectionAttempts >= this.maxConnectionAttempts) {
      console.error('Przekroczono maksymalną liczbę prób połączenia Socket.IO');
      return false;
    }
    
    if (!this.userId) {
      console.error('Brak ID użytkownika do połączenia Socket.IO');
      return false;
    }
    
    this.connectionAttempts++;
    
    try {
      // Pobierz konfigurację Socket.IO z serwera
      const config = await this.getSocketConfig();
      
      console.log(`Próba połączenia Socket.IO (#${this.connectionAttempts}):`, config.socketUrl);
      
      // Sprawdź czy Socket.IO jest dostępne
      if (typeof io === 'undefined') {
        console.error('Socket.IO client library nie jest załadowana');
        return false;
      }
      
      // Utwórz połączenie Socket.IO
      this.socket = io(config.socketUrl, {
        path: config.path || '/socket.io/',
        transports: ['websocket', 'polling'], // Fallback na polling
        upgrade: true,
        rememberUpgrade: true,
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5,
        timeout: 20000
      });
      
      // Skonfiguruj handlery zdarzeń
      this.setupEventHandlers();
      
      return true;
    } catch (error) {
      console.error('Błąd tworzenia połączenia Socket.IO:', error);
      this.scheduleReconnect();
      return false;
    }
  }
  
  /**
   * Pobiera konfigurację Socket.IO z serwera
   */
  async getSocketConfig() {
    try {
      const response = await fetch('/api/websocket/config');
      if (response.ok) {
        return await response.json();
      }
    } catch (e) {
      console.warn('Nie udało się pobrać konfiguracji Socket.IO, używam domyślnej');
    }
    
    // Domyślna konfiguracja
    const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
    return {
      socketUrl: `${protocol}//${window.location.host}`,
      path: '/socket.io/'
    };
  }
  
  /**
   * Konfiguruje handlery zdarzeń Socket.IO
   */
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
    });
    
    // Potwierdzenie połączenia
    this.socket.on('connection_ack', (data) => {
      console.log('✅ Połączenie Socket.IO potwierdzone:', data.message);
    });
    
    // Otrzymane wiadomości
    this.socket.on('message', (data) => {
      console.log('📨 Otrzymano wiadomość Socket.IO:', data.type);
      this.handleMessage(data);
    });
    
    // Potwierdzenie dostarczenia wiadomości
    this.socket.on('message_delivered', (data) => {
      console.log('✅ Wiadomość dostarczona:', data);
      if (this.handlers['message_delivered']) {
        this.handlers['message_delivered'](data);
      }
    });
    
    // Błędy od serwera
    this.socket.on('error', (error) => {
      console.error('❌ Błąd od serwera Socket.IO:', error);
    });
    
    // Ping/Pong
    this.socket.on('pong', (data) => {
      console.log('Otrzymano pong:', data.timestamp);
    });
  }
  
  /**
   * Obsługuje przychodzące wiadomości
   */
  handleMessage(data) {
    try {
      // Wywołaj odpowiedni handler zdarzenia
      if (data.type && this.handlers[data.type]) {
        this.handlers[data.type](data);
      }
    } catch (error) {
      console.error('Błąd obsługi wiadomości Socket.IO:', error);
    }
  }
  
  /**
   * Wysyła wiadomość przez Socket.IO
   */
  send(eventName, data) {
    if (!this.isConnected || !this.socket) {
      // Zapisz wiadomość do wysłania później
      this.pendingMessages.push({ eventName, data });
      
      if (!this.isConnected && this.connectionAttempts < this.maxConnectionAttempts) {
        console.log('🔄 Socket.IO nie połączony, próba reconnect...');
        this.connect();
      }
      
      return false;
    }
    
    try {
      this.socket.emit(eventName, data);
      return true;
    } catch (error) {
      console.error('❌ Błąd wysyłania wiadomości Socket.IO:', error);
      this.pendingMessages.push({ eventName, data });
      return false;
    }
  }
  
  /**
   * Wysyła wiadomość czatu
   */
  sendMessage(recipientId, sessionToken, content, iv, header, messageId) {
    return this.send('send_message', {
      recipient_id: recipientId,
      session_token: sessionToken,
      content: content,
      iv: iv,
      header: header,
      message_id: messageId
    });
  }
  
  /**
   * Wysyła potwierdzenie przeczytania
   */
  sendReadReceipt(senderId, messageId, sessionToken) {
    return this.send('send_read_receipt', {
      sender_id: senderId,
      message_id: messageId,
      session_token: sessionToken
    });
  }
  
  /**
   * Wysyła ping
   */
  sendPing() {
    return this.send('ping', {});
  }
  
  /**
   * Przetwarza oczekujące wiadomości
   */
  processPendingMessages() {
    if (this.pendingMessages.length === 0 || !this.isConnected) return;
    
    console.log(`📤 Przetwarzanie ${this.pendingMessages.length} oczekujących wiadomości`);
    const pending = [...this.pendingMessages];
    this.pendingMessages = [];
    
    for (const message of pending) {
      if (!this.send(message.eventName, message.data)) {
        console.log('❌ Nie udało się wysłać oczekujących wiadomości');
        break;
      }
    }
  }
  
  /**
   * Planuje ponowne połączenie
   */
  scheduleReconnect() {
    if (this.connectionAttempts < this.maxConnectionAttempts) {
      setTimeout(() => {
        console.log(`🔄 Ponowna próba połączenia (${this.connectionAttempts + 1}/${this.maxConnectionAttempts})...`);
        this.connect();
      }, this.reconnectInterval);
    } else {
      console.error('❌ Wyczerpano wszystkie próby połączenia Socket.IO');
      // Informuj użytkownika o problemie
      if (window.chatInterface) {
        window.chatInterface.showNotification(
          'Problem z połączeniem Socket.IO. Odśwież stronę lub spróbuj później.', 
          'warning', 
          10000
        );
      }
    }
  }
  
  /**
   * Rejestruje obsługę typu wiadomości
   */
  on(type, callback) {
    this.handlers[type] = callback;
    console.log(`📝 Zarejestrowano handler dla: ${type}`);
  }
  
  /**
   * Usuwa handler dla typu wiadomości
   */
  off(type) {
    delete this.handlers[type];
    console.log(`🗑️ Usunięto handler dla: ${type}`);
  }
  
  /**
   * Sprawdza czy użytkownik jest online (kompatybilność)
   */
  is_user_online(user_id) {
    return this.isConnected;
  }
  
  /**
   * Wysyła wiadomość do konkretnego użytkownika (kompatybilność)
   */
  send_to_user(user_id, message) {
    return this.send('direct_message', {
      recipient_id: user_id,
      message: message,
      timestamp: new Date().toISOString()
    });
  }
  
  /**
   * Zamyka połączenie
   */
  close() {
    if (this.socket) {
      console.log('🔌 Zamykanie połączenia Socket.IO...');
      this.socket.disconnect();
    }
    this.isConnected = false;
    this._running = false;
  }
  
  /**
   * Rozłącza połączenie Socket.IO (alias dla metody close)
   */
  disconnect() {
    this.close();
  }
  
  /**
   * Restartuje połączenie Socket.IO
   */
  restart() {
    console.log('🔄 Restartowanie połączenia Socket.IO...');
    this.close();
    this.connectionAttempts = 0;
    setTimeout(() => {
      this.connect();
    }, 1000);
  }
  
  /**
   * Sprawdza status połączenia
   */
  getStatus() {
    return {
      isConnected: this.isConnected,
      connectionAttempts: this.connectionAttempts,
      pendingMessages: this.pendingMessages.length,
      userId: this.userId,
      socketId: this.socket ? this.socket.id : null
    };
  }
}

// Inicjalizacja globalnego handlera Socket.IO
window.wsHandler = new SocketIOHandler();

// Debugowanie w konsoli
console.log('🔧 SocketIOHandler załadowany:', window.wsHandler.getStatus());
