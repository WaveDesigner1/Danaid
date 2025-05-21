/**
 * WebSocketHandler - Zoptymalizowana obsługa połączeń WebSocket
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
   * Nawiązuje połączenie WebSocket z autodetekcją konfiguracji
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
    
    // Autodetekcja konfiguracji WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let wsHost = window.location.host;
    let wsPath = `/ws/chat/${this.userId}`;
    
    // Sprawdź, czy konfiguracja jest dostępna
    if (window._env && window._env.wsUrl) {
      wsHost = window._env.wsUrl;
    }
    
    const wsUrl = `${protocol}//${wsHost}${wsPath}`;
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
      const data = JSON.parse(event.data);
      console.log('Otrzymano wiadomość WebSocket:', data.type);
      
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
    this._running = false;
    console.log(`WebSocket rozłączony: ${event.code}`);
    
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
      const messageStr = JSON.stringify(data);
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
    this.handlers[type] = callback;
  }
  
  /**
   * Sprawdza czy użytkownik jest online
   */
  is_user_online(user_id) {
    return this.isConnected;
  }
  
  /**
   * Wysyła wiadomość do konkretnego użytkownika
   */
  send_to_user(user_id, message) {
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

/**
 * Rozłącza połączenie WebSocket (alias dla metody close)
 */
disconnect() {
  this.close();
}
// Inicjalizacja globalnego handlara WebSocket
window.wsHandler = new WebSocketHandler();
