// Zaktualizowany WebSocketHandler.js dla Railway.app

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
   * Nawiązuje połączenie WebSocket
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
    
    // Określ URL WebSocket - używamy tego samego hosta co strona
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/chat/${this.userId}`;
    
    console.log(`Próba połączenia WebSocket: ${wsUrl}`);
    
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
    console.log('WebSocket połączony pomyślnie');
    this.isConnected = true;
    this._running = true;
    this.connectionAttempts = 0;
    
    // Wyślij wiadomość inicjalizującą
    this.send({
      type: 'connection_established',
      user_id: this.userId
    });
    
    // Wyślij zaległe wiadomości
    this.processPendingMessages();
  }
  
  /**
   * Obsługuje przychodzące wiadomości
   */
  handleMessage(event) {
    try {
      console.log('Otrzymano wiadomość WebSocket:', event.data);
      const data = JSON.parse(event.data);
      
      // Odpowiedź na ping
      if (data.type === 'ping') {
        console.log('Otrzymano ping, wysyłanie pong');
        this.send({ type: 'pong' });
        return;
      }
      
      // Wywołaj odpowiedni handler zdarzenia
      if (data.type && this.handlers[data.type]) {
        console.log(`Wywołanie handlera dla typu: ${data.type}`);
        this.handlers[data.type](data);
      } else {
        console.log(`Brak handlera dla typu: ${data.type}`);
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
    console.log(`WebSocket rozłączony: ${event.code} - ${event.reason}`);
    
    if (event.code !== 1000) { // Jeśli to nie jest normalne zamknięcie
      this.scheduleReconnect();
    }
  }
  
  /**
   * Obsługuje błędy połączenia
   */
  handleError(error) {
    console.error('Błąd WebSocket:', error);
    this.isConnected = false;
  }
  
  /**
   * Planuje ponowne połączenie
   */
  scheduleReconnect() {
    if (this.connectionAttempts < this.maxConnectionAttempts) {
      console.log(`Ponowna próba połączenia za ${this.reconnectInterval}ms...`);
      setTimeout(() => this.connect(), this.reconnectInterval);
    }
  }
  
  /**
   * Wysyła wiadomość przez WebSocket
   */
  send(data) {
    if (!this.isConnected || !this.socket || this.socket.readyState !== WebSocket.OPEN) {
      console.log('WebSocket nie jest połączony. Zapisano wiadomość do późniejszego wysłania:', data);
      // Zapisz wiadomość do wysłania później
      this.pendingMessages.push(data);
      
      if (!this.isConnected) {
        this.connect();
      }
      
      return false;
    }
    
    try {
      const messageStr = JSON.stringify(data);
      console.log('Wysyłanie wiadomości WebSocket:', messageStr);
      this.socket.send(messageStr);
      return true;
    } catch (error) {
      console.error('Błąd wysyłania wiadomości WebSocket:', error);
      this.pendingMessages.push(data);
      return false;
    }
  }
  
  /**
   * Przetwarza oczekujące wiadomości
   */
  processPendingMessages() {
    if (this.pendingMessages.length === 0 || !this.isConnected) return;
    
    console.log(`Przetwarzanie ${this.pendingMessages.length} oczekujących wiadomości`);
    const pending = [...this.pendingMessages];
    this.pendingMessages = [];
    
    for (const message of pending) {
      this.send(message);
    }
  }
  
  /**
   * Rejestruje obsługę typu wiadomości
   */
  on(type, callback) {
    console.log(`Rejestracja handlera dla typu: ${type}`);
    this.handlers[type] = callback;
  }
  
  /**
   * Sprawdza czy użytkownik jest online
   */
  is_user_online(user_id) {
    return this.isConnected; // Uproszczona implementacja
  }
  
  /**
   * Wysyła wiadomość do konkretnego użytkownika
   */
  send_to_user(user_id, message) {
    console.log(`Wysyłanie wiadomości do użytkownika ${user_id}:`, message);
    return this.send({
      type: 'direct_message',
      recipient_id: user_id,
      message: message
    });
  }
  
  /**
   * Zamyka połączenie
   */
  close() {
    if (this.socket) {
      this.socket.close(1000, 'Zamknięcie przez użytkownika');
    }
  }
}

// Inicjalizacja globalnego handlara WebSocket
window.wsHandler = new WebSocketHandler();
