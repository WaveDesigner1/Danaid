/**
 * WebSocketHandler.js - Zarządzanie połączeniami WebSocket
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
    
    // Określ odpowiedni URL WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Używamy tego samego hosta co aktualny serwer
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/chat/${this.userId}`;
    
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
    console.log('WebSocket połączony');
    this.isConnected = true;
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
      const data = JSON.parse(event.data);
      
      // Odpowiedź na ping
      if (data.type === 'ping') {
        this.send({ type: 'pong' });
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
      // Zapisz wiadomość do wysłania później
      this.pendingMessages.push(data);
      
      if (!this.isConnected) {
        this.connect();
      }
      
      return false;
    }
    
    try {
      this.socket.send(JSON.stringify(data));
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
    this.handlers[type] = callback;
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
