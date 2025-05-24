/**
 * SocketIOHandler -
 */

class SocketIOHandler {
  constructor(config = {}) {
    this.userId = config.userId || null;
    this.socket = null;
    this.isConnected = false;
    this.connectionAttempts = 0;
    this.maxConnectionAttempts = 5;
    this.pendingMessages = [];
    this.handlers = {};
    this._running = false;
    
    console.log('🔧 SocketIOHandler zainicjalizowany');
  }

  // Konfiguracja handlerów zdarzeń
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
    
    // Rozłączenie
    this.socket.on('disconnect', () => {
      console.log('🔌 Socket.IO rozłączony');
      this.isConnected = false;
      this._running = false;
    });
    
    console.log('✅ Socket.IO handlers skonfigurowane');
  }

  // Obsługa wiadomości z lepszym routingiem
  handleMessage(data) {
    try {
      console.log('🔄 [HANDLER] Przetwarzanie wiadomości typu:', data.type);
      
      // Wywołaj odpowiedni handler zdarzenia
      if (data.type && this.handlers[data.type]) {
        this.handlers[data.type](data);
      } else {
        console.warn('⚠️ [HANDLER] Brak handlera dla typu:', data.type);
        console.warn('⚠️ [HANDLER] Dostępne handlery:', Object.keys(this.handlers));
        
        // Domyślna obsługa - przekaż do SecureSessionManager
        if (window.secureSessionManager && typeof window.secureSessionManager.handleSocketMessage === 'function') {
          window.secureSessionManager.handleSocketMessage(data);
        }
      }
    } catch (error) {
      console.error('❌ Błąd obsługi wiadomości Socket.IO:', error);
      console.error('❌ Data:', data);
    }
  }

  // Połączenie z serwerem
  async connect(serverUrl = null) {
    try {
      if (this.socket && this.isConnected) {
        console.log('Socket.IO już połączony');
        return true;
      }

      const url = serverUrl || 'http://danaid.up.railway.app';
      console.log('🔄 Łączenie z Socket.IO:', url);

      if (typeof io === 'undefined') {
        throw new Error('Socket.IO library nie jest załadowana');
      }

      this.socket = io(url, {
        transports: ['websocket', 'polling'],
        timeout: 10000,
        forceNew: true
      });

      this.setupEventHandlers();
      
      // Czekaj na połączenie
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Timeout połączenia Socket.IO'));
        }, 10000);

        this.socket.on('connect', () => {
          clearTimeout(timeout);
          resolve(true);
        });

        this.socket.on('connect_error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });

    } catch (error) {
      console.error('❌ Błąd połączenia Socket.IO:', error);
      this.connectionAttempts++;
      
      if (this.connectionAttempts < this.maxConnectionAttempts) {
        console.log(`🔄 Próba ponownego połączenia (${this.connectionAttempts}/${this.maxConnectionAttempts})...`);
        setTimeout(() => this.connect(serverUrl), 2000);
      }
      
      return false;
    }
  }

  // Wysyłanie z lepszym debugowaniem
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

  // Przetwarzanie zaległych wiadomości
  processPendingMessages() {
    if (this.pendingMessages.length === 0) return;
    
    console.log(`📤 Wysyłanie ${this.pendingMessages.length} zaległych wiadomości...`);
    
    const messages = [...this.pendingMessages];
    this.pendingMessages = [];
    
    messages.forEach(({ eventName, data }) => {
      this.send(eventName, data);
    });
  }

  // Metoda do synchronizacji po reconnect
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

  // Metoda do wysyłania heartbeat
  sendHeartbeat() {
    if (this.isConnected) {
      return this.send('heartbeat', {
        user_id: this.userId,
        timestamp: new Date().toISOString()
      });
    }
    return false;
  }

  // Dodanie handlera dla określonego typu wiadomości
  addHandler(type, handler) {
    this.handlers[type] = handler;
    console.log(`✅ Dodano handler dla typu: ${type}`);
  }

  // Usunięcie handlera
  removeHandler(type) {
    delete this.handlers[type];
    console.log(`🗑️ Usunięto handler dla typu: ${type}`);
  }

  // Zamknięcie połączenia
  close() {
    if (this.socket) {
      console.log('🔌 Zamykanie połączenia Socket.IO...');
      this.socket.disconnect();
      this.socket = null;
      this.isConnected = false;
      this._running = false;
    }
  }

  // Restart z synchronizacją
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

  // Sprawdzenie statusu
  getStatus() {
    return {
      connected: this.isConnected,
      running: this._running,
      attempts: this.connectionAttempts,
      pendingMessages: this.pendingMessages.length,
      handlers: Object.keys(this.handlers)
    };
  }
}

// Export dla użycia w innych modułach
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SocketIOHandler;
}

// Globalna dostępność
window.SocketIOHandler = SocketIOHandler;
