/**
 * WebSocketHandler - NAPRAWIONA obsługa połączeń WebSocket dla Railway
 */
class WebSocketHandler {
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
    
    // Automatyczne łączenie po inicjalizacji
    if (this.userId) {
      this.connect();
    }
  }
  
  /**
   * NAPRAWIONA autodetekcja WebSocket URL dla Railway
   */
  connect() {
    if (this.connectionAttempts >= this.maxConnectionAttempts) {
      console.error('Przekroczono maksymalną liczbę prób połączenia WebSocket');
      return false;
    }
    
    if (!this.userId) {
      console.error('Brak ID użytkownika do połączenia WebSocket');
      return false;
    }
    
    this.connectionAttempts++;
    
    // NAPRAWIONA KONFIGURACJA WebSocket dla Railway
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const hostname = window.location.hostname;
    let wsUrl;
    
    if (hostname.includes('railway.app')) {
      // Railway - WebSocket na tym samym hoście ale port 8081
      // Railway może wymagać tego samego hosta co główna aplikacja
      wsUrl = `${protocol}//${hostname}/ws/chat/${this.userId}`;
      console.log("Railway detected - using same host for WebSocket");
    } else if (hostname === 'localhost' || hostname === '127.0.0.1') {
      // Lokalne środowisko - WebSocket na porcie 8081
      wsUrl = `ws://localhost:8081/ws/chat/${this.userId}`;
      console.log("Local environment detected");
    } else {
      // Inne środowiska - spróbuj portu 8081
      wsUrl = `${protocol}//${hostname}:8081/ws/chat/${this.userId}`;
      console.log("Generic environment - trying port 8081");
    }
    
    console.log(`Próba połączenia WebSocket (#${this.connectionAttempts}): ${wsUrl}`);
    
    try {
      this.socket = new WebSocket(wsUrl);
      
      this.socket.onopen = this.handleOpen.bind(this);
      this.socket.onmessage = this.handleMessage.bind(this);
      this.socket.onclose = this.handleClose.bind(this);
      this.socket.onerror = this.handleError.bind(this);
      
      return true;
    } catch (error) {
      console.error('Błąd tworzenia połączenia WebSocket:', error);
      this.scheduleReconnect();
      return false;
    }
  }
  
  /**
   * Obsługuje otwarcie połączenia
   */
  handleOpen() {
    console.log('✅ WebSocket połączony pomyślnie');
    this.isConnected = true;
    this._running = true;
    this.connectionAttempts = 0;
    
    // Wyślij wiadomość inicjalizującą
    this.send({
      type: 'connection_established',
      user_id: this.userId,
      timestamp: new Date().toISOString()
    });
    
    // Wyślij zaległe wiadomości
    this.processPendingMessages();
  }
  
  /**
   * Obsługuje przychodzące wiadomości
   */
  handleMessage(event) {
    try {
      const data = JSON.parse(event.data);
      console.log('📨 Otrzymano wiadomość WebSocket:', data.type);
      
      // Odpowiedź na ping
      if (data.type === 'ping') {
        this.send({ type: 'pong', timestamp: new Date().toISOString() });
        return;
      }
      
      // Potwierdzenie połączenia
      if (data.type === 'connection_ack') {
        console.log('✅ Połączenie WebSocket potwierdzone');
        return;
      }
      
      // Wywołaj odpowiedni handler zdarzenia
      if (data.type && this.handlers[data.type]) {
        this.handlers[data.type](data);
      }
    } catch (error) {
      console.error('Błąd obsługi wiadomości WebSocket:', error);
    }
  }
  
  /**
   * Obsługuje zamknięcie połączenia
   */
  handleClose(event) {
    this.isConnected = false;
    this._running = false;
    console.log(`🔌 WebSocket rozłączony: kod ${event.code}, powód: ${event.reason}`);
    
    if (event.code !== 1000) { // Jeśli to nie jest normalne zamknięcie
      console.log(`⏳ Planowanie ponownego połączenia za ${this.reconnectInterval}ms...`);
      this.scheduleReconnect();
    }
  }
  
  /**
   * Obsługuje błędy połączenia
   */
  handleError(error) {
    console.error('❌ Błąd WebSocket:', error);
    this.isConnected = false;
    
    // Jeśli to pierwszy błąd, spróbuj alternatywnego URL
    if (this.connectionAttempts === 1) {
      console.log('🔄 Próba alternatywnej konfiguracji WebSocket...');
      this.tryAlternativeConnection();
    }
  }
  
  /**
   * NOWA: Próba alternatywnej konfiguracji WebSocket dla Railway
   */
  tryAlternativeConnection() {
    if (!this.userId) return;
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const hostname = window.location.hostname;
    
    // Spróbuj bez konkretnego portu (może Railway proxy wszystko przez 443/80)
    const alternativeUrl = `${protocol}//${hostname}/websocket/chat/${this.userId}`;
    
    console.log(`🔄 Próba alternatywnego URL: ${alternativeUrl}`);
    
    try {
      if (this.socket) {
        this.socket.close();
      }
      
      this.socket = new WebSocket(alternativeUrl);
      
      this.socket.onopen = this.handleOpen.bind(this);
      this.socket.onmessage = this.handleMessage.bind(this);
      this.socket.onclose = this.handleClose.bind(this);
      this.socket.onerror = (error) => {
        console.error('❌ Alternatywne połączenie też nie działa:', error);
        this.scheduleReconnect();
      };
      
    } catch (error) {
      console.error('❌ Błąd alternatywnego połączenia:', error);
      this.scheduleReconnect();
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
      console.error('❌ Wyczerpano wszystkie próby połączenia WebSocket');
      // Informuj użytkownika o problemie
      if (window.chatInterface) {
        window.chatInterface.showNotification(
          'Problem z połączeniem WebSocket. Odśwież stronę lub spróbuj później.', 
          'warning', 
          10000
        );
      }
    }
  }
  
  /**
   * Wysyła wiadomość przez WebSocket
   */
  send(data) {
    if (!this.isConnected || !this.socket || this.socket.readyState !== WebSocket.OPEN) {
      // Zapisz wiadomość do wysłania później
      this.pendingMessages.push(data);
      
      if (!this.isConnected && this.connectionAttempts < this.maxConnectionAttempts) {
        console.log('🔄 WebSocket nie połączony, próba reconnect...');
        this.connect();
      }
      
      return false;
    }
    
    try {
      const messageStr = JSON.stringify(data);
      this.socket.send(messageStr);
      return true;
    } catch (error) {
      console.error('❌ Błąd wysyłania wiadomości WebSocket:', error);
      this.pendingMessages.push(data);
      return false;
    }
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
      if (!this.send(message)) {
        // Jeśli nie udało się wysłać, zatrzymaj przetwarzanie
        console.log('❌ Nie udało się wysłać oczekujących wiadomości');
        break;
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
    return this.send({
      type: 'direct_message',
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
      console.log('🔌 Zamykanie połączenia WebSocket...');
      this.socket.close(1000, 'Zamknięcie przez użytkownika');
    }
    this.isConnected = false;
    this._running = false;
  }
  
  /**
   * Rozłącza połączenie WebSocket (alias dla metody close)
   */
  disconnect() {
    this.close();
  }
  
  /**
   * Restartuje połączenie WebSocket
   */
  restart() {
    console.log('🔄 Restartowanie połączenia WebSocket...');
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
      userId: this.userId
    };
  }
}

// Inicjalizacja globalnego handlera WebSocket
window.wsHandler = new WebSocketHandler();

// Debugowanie w konsoli
console.log('🔧 WebSocketHandler załadowany:', window.wsHandler.getStatus());
