/**
 * Menedżer sesji czatu - Zoptymalizowana wersja bez przechowywania wiadomości na serwerze
 */
class ChatSessionManager {
    constructor() {
        this.sessions = {};
        this.messages = {}; // Przechowuje wiadomości lokalnie
        this.pendingHandshakes = {};
        
        // Nasłuchiwanie na nowe wiadomości za pomocą WebSocket
        this.initWebSocket();
        
        // Załaduj wiadomości z IndexedDB przy inicjalizacji
        this.loadMessagesFromStorage();
    }
    
    /**
     * Inicjalizacja WebSocket do odbierania wiadomości w czasie rzeczywistym
     */
    initWebSocket() {
        const userId = sessionStorage.getItem('user_id');
        if (!userId) return;
        
        this.socket = new WebSocket(`wss://${window.location.host}/ws/chat/${userId}`);
        
        this.socket.onopen = () => {
            console.log('WebSocket połączony');
        };
        
        this.socket.onmessage = async (event) => {
            const data = JSON.parse(event.data);
            
            // Obsługa przychodzących wiadomości
            if (data.type === 'new_message') {
                await this.handleIncomingMessage(data.session_token, data.message);
            }
            // Obsługa zmian w sesjach
            else if (data.type === 'session_update') {
                await this.refreshSession(data.session_token);
            }
        };
        
        this.socket.onclose = () => {
            console.log('WebSocket rozłączony, próba ponownego połączenia za 5s...');
            setTimeout(() => this.initWebSocket(), 5000);
        };
    }
    
    /**
     * Obsługuje przychodzącą wiadomość
     */
    async handleIncomingMessage(sessionToken, encryptedMsg) {
        // Pobierz klucz sesji
        const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
        if (!sessionKeyBase64) {
            console.error('Brak klucza sesji dla wiadomości');
            return;
        }
        
        try {
            // Importuj klucz sesji
            const sessionKey = await window.chatCrypto.importSessionKey(sessionKeyBase64);
            
            // Odszyfruj wiadomość
            const encryptedMessage = {
                iv: encryptedMsg.iv,
                encryptedData: encryptedMsg.content
            };
            
            const decryptedContent = await window.chatCrypto.decryptMessage(encryptedMessage, sessionKey);
            
            // Dodaj odszyfrowaną wiadomość do lokalnego magazynu
            if (!this.messages[sessionToken]) {
                this.messages[sessionToken] = [];
            }
            
            this.messages[sessionToken].push({
                ...encryptedMsg,
                content: decryptedContent,
                timestamp: new Date().toISOString()
            });
            
            // Zapisz wiadomości do lokalnego magazynu
            this.saveMessagesToStorage();
            
            // Wywołaj callback jeśli istnieje
            if (this.onMessageReceived) {
                this.onMessageReceived(sessionToken, this.messages[sessionToken]);
            }
            
        } catch (error) {
            console.error('Błąd podczas obsługi przychodzących wiadomości:', error);
        }
    }
    
    /**
     * Inicjuje nową sesję czatu z użytkownikiem
     */
    async initSession(recipientId) {
        try {
            // 1. Inicjuj sesję na serwerze (tylko metadane, bez przechowywania wiadomości)
            const sessionResponse = await fetch('/api/session/init', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient_id: recipientId })
            });
            
            if (!sessionResponse.ok) {
                throw new Error(`HTTP Error: ${sessionResponse.status}`);
            }
            
            const sessionData = await sessionResponse.json();
            
            if (sessionData.status !== 'success') {
                throw new Error(sessionData.message || 'Błąd inicjacji sesji');
            }
            
            const session = sessionData.session;
            
            // Zapisz sesję w lokalnym stanie
            this.sessions[session.token] = session;
            
            // Inicjuj lokalny magazyn wiadomości dla sesji
            if (!this.messages[session.token]) {
                this.messages[session.token] = [];
            }
            
            // 2. Jeśli sesja już istnieje i ma klucz, po prostu ją zwróć
            if (session.has_key && session.key_acknowledged) {
                const sessionKeyBase64 = localStorage.getItem(`session_key_${session.token}`);
                if (sessionKeyBase64) {
                    try {
                        const sessionKey = await window.chatCrypto.importSessionKey(sessionKeyBase64);
                        return {
                            status: 'success',
                            session: session,
                            sessionKey: sessionKey
                        };
                    } catch (e) {
                        console.error('Błąd importu klucza sesji:', e);
                    }
                }
            }
            
            // 3. Jeśli jesteśmy inicjatorem i nie ma klucza, zainicjuj handshake
            if (session.initiator_id === parseInt(sessionStorage.getItem('user_id'))) {
                return await this.initiateHandshake(session);
            }
            
            // 4. Jeśli jesteśmy odbiorcą, sprawdź czy jest klucz do odebrania
            if (session.has_key && !session.key_acknowledged) {
                return await this.receiveHandshake(session);
            }
            
            // 5. W przeciwnym razie zwróć sesję bez klucza
            return {
                status: 'pending',
                message: 'Sesja utworzona, czekam na wymianę kluczy',
                session: session
            };
            
        } catch (error) {
            console.error('Błąd inicjacji sesji:', error);
            return {
                status: 'error',
                message: error.message
            };
        }
    }
    
    /**
     * Inicjuje handshake jako nadawca
     */
    async initiateHandshake(session) {
        try {
            // 1. Pobierz klucz publiczny odbiorcy
            const keyResponse = await fetch(`/api/user/${session.recipient_id}/public_key`);
            
            if (!keyResponse.ok) throw new Error(`HTTP Error: ${keyResponse.status}`);
            
            const keyData = await keyResponse.json();
            
            if (keyData.status !== 'success') {
                throw new Error(keyData.message || 'Błąd pobierania klucza publicznego');
            }
            
            // 2. Importuj klucz publiczny odbiorcy
            const recipientPublicKey = await window.chatCrypto.importPublicKeyFromPEM(keyData.public_key);
            
            // 3. Wygeneruj klucz sesji AES
            const sessionKey = await window.chatCrypto.generateSessionKey();
            const sessionKeyBase64 = await window.chatCrypto.exportSessionKey(sessionKey);
            
            // 4. Zaszyfruj klucz sesji kluczem publicznym odbiorcy
            const encryptedSessionKey = await window.chatCrypto.encryptSessionKey(sessionKeyBase64, recipientPublicKey);
            
            // 5. Prześlij zaszyfrowany klucz sesji
            const exchangeResponse = await fetch(`/api/session/${session.token}/exchange_key`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ encrypted_key: encryptedSessionKey })
            });
            
            if (!exchangeResponse.ok) throw new Error(`HTTP Error: ${exchangeResponse.status}`);
            
            const exchangeData = await exchangeResponse.json();
            
            if (exchangeData.status !== 'success') {
                throw new Error(exchangeData.message || 'Błąd wymiany klucza');
            }
            
            // 6. Zapisz klucz sesji w localStorage
            localStorage.setItem(`session_key_${session.token}`, sessionKeyBase64);
            
            // 7. Zaktualizuj sesję w lokalnym stanie
            this.sessions[session.token] = {
                ...session,
                has_key: true
            };
            
            // 8. Zwróć klucz i sesję
            return {
                status: 'success',
                message: 'Klucz sesji wygenerowany i wysłany',
                session: this.sessions[session.token],
                sessionKey: sessionKey
            };
            
        } catch (error) {
            console.error('Błąd inicjacji handshake:', error);
            return {
                status: 'error',
                message: error.message
            };
        }
    }
    
    /**
     * Odbiera i przetwarza handshake jako odbiorca
     */
    async receiveHandshake(session) {
        try {
            // 1. Pobierz zaszyfrowany klucz sesji
            const keyResponse = await fetch(`/api/session/${session.token}/key`);
            
            if (!keyResponse.ok) throw new Error(`HTTP Error: ${keyResponse.status}`);
            
            const keyData = await keyResponse.json();
            
            if (keyData.status !== 'success') {
                throw new Error(keyData.message || 'Błąd pobierania klucza sesji');
            }
            
            const encryptedSessionKey = keyData.encrypted_key;
            
            // 2. Odszyfruj kluczem prywatnym
            const decryptedSessionKeyBase64 = await window.chatCrypto.decryptSessionKey(encryptedSessionKey);
            
            // 3. Importuj klucz sesji
            const sessionKey = await window.chatCrypto.importSessionKey(decryptedSessionKeyBase64);
            
            // 4. Zapisz klucz w localStorage
            localStorage.setItem(`session_key_${session.token}`, decryptedSessionKeyBase64);
            
            // 5. Potwierdź odebranie klucza na serwerze
            const ackResponse = await fetch(`/api/session/${session.token}/acknowledge_key`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            if (!ackResponse.ok) throw new Error(`HTTP Error: ${ackResponse.status}`);
            
            const ackData = await ackResponse.json();
            
            if (ackData.status !== 'success') {
                throw new Error(ackData.message || 'Błąd potwierdzenia klucza');
            }
            
            // 6. Zaktualizuj sesję w lokalnym stanie
            this.sessions[session.token] = {
                ...session,
                has_key: true,
                key_acknowledged: true
            };
            
            // 7. Zwróć klucz i sesję
            return {
                status: 'success',
                message: 'Klucz sesji odebrany i potwierdzony',
                session: this.sessions[session.token],
                sessionKey: sessionKey
            };
            
        } catch (error) {
            console.error('Błąd odbierania handshake:', error);
            return {
                status: 'error',
                message: error.message
            };
        }
    }
    
    /**
     * Pobiera wszystkie aktywne sesje użytkownika
     */
    async getActiveSessions() {
        try {
            const response = await fetch('/api/sessions/active');
            
            if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
            
            const data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Błąd pobierania sesji');
            }
            
            // Aktualizuj lokalny stan
            data.sessions.forEach(session => {
                this.sessions[session.token] = session;
            });
            
            return {
                status: 'success',
                sessions: data.sessions
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
     * Wysyła zaszyfrowaną wiadomość
     */
    async sendMessage(sessionToken, message) {
        try {
            // 1. Sprawdź czy mamy klucz sesji
            const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
            if (!sessionKeyBase64) {
                throw new Error('Brak klucza sesji w pamięci lokalnej');
            }
            
            // 2. Importuj klucz sesji
            const sessionKey = await window.chatCrypto.importSessionKey(sessionKeyBase64);
            
            // 3. Zaszyfruj wiadomość
            const encryptedData = await window.chatCrypto.encryptMessage(message, sessionKey);
            
            // 4. Wyślij wiadomość (serwer nie przechowuje, tylko przekazuje)
            const response = await fetch('/api/message/relay', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_token: sessionToken,
                    content: encryptedData.encryptedData,
                    iv: encryptedData.iv
                })
            });
            
            if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
            
            const data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Błąd wysyłania wiadomości');
            }
            
            // 5. Zapisz wiadomość lokalnie
            if (!this.messages[sessionToken]) {
                this.messages[sessionToken] = [];
            }
            
            const newMessage = {
                id: data.message_id || Date.now().toString(),
                sender_id: parseInt(sessionStorage.getItem('user_id')),
                content: message,
                timestamp: new Date().toISOString()
            };
            
            this.messages[sessionToken].push(newMessage);
            
            // 6. Zapisz do lokalnego magazynu
            this.saveMessagesToStorage();
            
            // 7. Wywołaj callback jeśli istnieje
            if (this.onMessageSent) {
                this.onMessageSent(sessionToken, newMessage);
            }
            
            return {
                status: 'success',
                message: 'Wiadomość wysłana',
                messageData: newMessage
            };
            
        } catch (error) {
            console.error('Błąd wysyłania wiadomości:', error);
            return {
                status: 'error',
                message: error.message
            };
        }
    }
    
    /**
     * Pobiera wiadomości z lokalnego magazynu
     */
    getLocalMessages(sessionToken) {
        if (!this.messages[sessionToken]) {
            return {
                status: 'success',
                messages: []
            };
        }
        
        return {
            status: 'success',
            messages: this.messages[sessionToken]
        };
    }
    
    /**
     * Zapisuje wiadomości do lokalnego magazynu (IndexedDB)
     */
    async saveMessagesToStorage() {
        try {
            const db = await this._openDatabase();
            const tx = db.transaction('messages', 'readwrite');
            const store = tx.objectStore('messages');
            
            // Zapisz każdą sesję wiadomości
            for (const [sessionToken, sessionMessages] of Object.entries(this.messages)) {
                await store.put({
                    sessionToken: sessionToken,
                    messages: sessionMessages,
                    lastUpdated: new Date().toISOString()
                });
            }
            
            await tx.complete;
            console.log('Wiadomości zapisane do lokalnego magazynu');
            return true;
            
        } catch (error) {
            console.error('Błąd podczas zapisywania wiadomości:', error);
            return false;
        }
    }
    
    /**
     * Ładuje wiadomości z lokalnego magazynu (IndexedDB)
     */
    async loadMessagesFromStorage() {
        try {
            const db = await this._openDatabase();
            const tx = db.transaction('messages', 'readonly');
            const store = tx.objectStore('messages');
            
            // Pobierz wszystkie rekordy
            const allRecords = await store.getAll();
            
            // Załaduj do pamięci
            allRecords.forEach(record => {
                this.messages[record.sessionToken] = record.messages;
            });
            
            console.log('Wiadomości załadowane z lokalnego magazynu');
            return true;
            
        } catch (error) {
            console.error('Błąd podczas ładowania wiadomości:', error);
            return false;
        }
    }
    
    /**
     * Otwiera połączenie z IndexedDB
     * @private
     */
    _openDatabase() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('SecureChatMessages', 1);
            
            request.onupgradeneeded = event => {
                const db = event.target.result;
                
                // Magazyn wiadomości z kluczem sessionToken
                if (!db.objectStoreNames.contains('messages')) {
                    db.createObjectStore('messages', { keyPath: 'sessionToken' });
                }
            };
            
            request.onsuccess = event => resolve(event.target.result);
            request.onerror = event => reject(event.target.error);
        });
    }
}

// Inicjalizacja menedżera sesji czatu
window.chatSessionManager = new ChatSessionManager();

// Automatyczne zapisywanie wiadomości co 5 minut
setInterval(() => {
    window.chatSessionManager.saveMessagesToStorage();
}, 5 * 60 * 1000);
