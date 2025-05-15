/**
 * Chat Session Manager - Zarządzanie sesją czatu i wymianą kluczy
 */
class ChatSessionManager {
    constructor() {
        this.sessionCache = {};  // Cache aktywnych sesji
        this.pendingHandshakes = {}; // Oczekujące handshake'i
    }
    
    /**
     * Inicjuje nową sesję czatu z użytkownikiem
     * @param {string} recipientId - ID użytkownika, z którym chcemy nawiązać komunikację
     * @returns {Promise<Object>} - Informacje o sesji
     */
    async initSession(recipientId) {
        try {
            // 1. Inicjuj sesję na serwerze
            const sessionResponse = await fetch('/api/session/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
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
            
            // Zapisz sesję w cache
            this.sessionCache[session.token] = session;
            
            // 2. Jeśli sesja już istnieje i ma klucz, po prostu ją zwróć
            if (session.has_key && session.key_acknowledged) {
                // Sprawdź, czy mamy zapisany klucz sesji w localStorage
                const sessionKeyBase64 = localStorage.getItem(`session_key_${session.token}`);
                if (sessionKeyBase64) {
                    // Spróbuj zaimportować klucz
                    try {
                        const sessionKey = await window.chatCrypto.importSessionKey(sessionKeyBase64);
                        return {
                            status: 'success',
                            session: session,
                            sessionKey: sessionKey
                        };
                    } catch (e) {
                        console.error('Błąd importu klucza sesji:', e);
                        // Jeśli nie udało się zaimportować, wymusimy nowy handshake
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
     * @param {Object} session - Sesja czatu
     * @returns {Promise<Object>} - Wynik handshake'a
     */
    async initiateHandshake(session) {
        try {
            // 1. Pobierz klucz publiczny odbiorcy
            const keyResponse = await fetch(`/api/user/${session.recipient_id}/public_key`);
            
            if (!keyResponse.ok) {
                throw new Error(`HTTP Error: ${keyResponse.status}`);
            }
            
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
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ encrypted_key: encryptedSessionKey })
            });
            
            if (!exchangeResponse.ok) {
                throw new Error(`HTTP Error: ${exchangeResponse.status}`);
            }
            
            const exchangeData = await exchangeResponse.json();
            
            if (exchangeData.status !== 'success') {
                throw new Error(exchangeData.message || 'Błąd wymiany klucza');
            }
            
            // 6. Zapisz klucz sesji w localStorage
            localStorage.setItem(`session_key_${session.token}`, sessionKeyBase64);
            
            // 7. Zaktualizuj sesję w cache
            this.sessionCache[session.token] = {
                ...session,
                has_key: true
            };
            
            // 8. Zwróć klucz i sesję
            return {
                status: 'success',
                message: 'Klucz sesji wygenerowany i wysłany',
                session: this.sessionCache[session.token],
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
     * @param {Object} session - Sesja czatu
     * @returns {Promise<Object>} - Wynik handshake'a
     */
    async receiveHandshake(session) {
        try {
            // 1. Pobierz zaszyfrowany klucz sesji
            const keyResponse = await fetch(`/api/session/${session.token}/key`);
            
            if (!keyResponse.ok) {
                throw new Error(`HTTP Error: ${keyResponse.status}`);
            }
            
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
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!ackResponse.ok) {
                throw new Error(`HTTP Error: ${ackResponse.status}`);
            }
            
            const ackData = await ackResponse.json();
            
            if (ackData.status !== 'success') {
                throw new Error(ackData.message || 'Błąd potwierdzenia klucza');
            }
            
            // 6. Zaktualizuj sesję w cache
            this.sessionCache[session.token] = {
                ...session,
                has_key: true,
                key_acknowledged: true
            };
            
            // 7. Zwróć klucz i sesję
            return {
                status: 'success',
                message: 'Klucz sesji odebrany i potwierdzony',
                session: this.sessionCache[session.token],
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
     * Sprawdza status sesji i klucza
     * @param {string} sessionToken - Token sesji
     * @returns {Promise<Object>} - Status sesji
     */
    async checkSessionStatus(sessionToken) {
        try {
            const response = await fetch(`/api/session/${sessionToken}/validate`);
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Błąd walidacji sesji');
            }
            
            // Aktualizuj cache
            this.sessionCache[sessionToken] = data.session;
            
            // Sprawdź czy mamy klucz w localStorage
            const hasLocalKey = localStorage.getItem(`session_key_${sessionToken}`) !== null;
            
            return {
                status: 'success',
                session: data.session,
                hasLocalKey: hasLocalKey
            };
            
        } catch (error) {
            console.error('Błąd sprawdzania statusu sesji:', error);
            return {
                status: 'error',
                message: error.message
            };
        }
    }
    
    /**
     * Pobiera wszystkie aktywne sesje użytkownika
     * @returns {Promise<Object>} - Lista aktywnych sesji
     */
    async getActiveSessions() {
        try {
            const response = await fetch('/api/sessions/active');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Błąd pobierania sesji');
            }
            
            // Aktualizuj cache
            data.sessions.forEach(session => {
                this.sessionCache[session.token] = session;
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
     * @param {string} sessionToken - Token sesji
     * @param {string} message - Wiadomość do wysłania
     * @returns {Promise<Object>} - Status wysyłania
     */
    async sendMessage(sessionToken, message) {
        try {
            // 1. Pobierz sesję i klucz
            const sessionStatus = await this.checkSessionStatus(sessionToken);
            
            if (sessionStatus.status !== 'success' || !sessionStatus.hasLocalKey) {
                throw new Error('Brak ważnej sesji lub klucza');
            }
            
            // 2. Pobierz klucz sesji z localStorage
            const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
            if (!sessionKeyBase64) {
                throw new Error('Brak klucza sesji w pamięci lokalnej');
            }
            
            // 3. Importuj klucz sesji
            const sessionKey = await window.chatCrypto.importSessionKey(sessionKeyBase64);
            
            // 4. Zaszyfruj wiadomość
            const encryptedData = await window.chatCrypto.encryptMessage(message, sessionKey);
            
            // 5. Wyślij wiadomość
            const response = await fetch('/api/message/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    session_token: sessionToken,
                    content: encryptedData.encryptedData,
                    iv: encryptedData.iv
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Błąd wysyłania wiadomości');
            }
            
            return {
                status: 'success',
                message: 'Wiadomość wysłana',
                messageId: data.message.id,
                timestamp: data.message.timestamp
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
     * Pobiera i deszyfruje wiadomości z sesji
     * @param {string} sessionToken - Token sesji
     * @returns {Promise<Object>} - Odszyfrowane wiadomości
     */
    async getMessages(sessionToken) {
        try {
            // 1. Pobierz sesję i klucz
            const sessionStatus = await this.checkSessionStatus(sessionToken);
            
            if (sessionStatus.status !== 'success' || !sessionStatus.hasLocalKey) {
                throw new Error('Brak ważnej sesji lub klucza');
            }
            
            // 2. Pobierz klucz sesji z localStorage
            const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
            if (!sessionKeyBase64) {
                throw new Error('Brak klucza sesji w pamięci lokalnej');
            }
            
            // 3. Importuj klucz sesji
            const sessionKey = await window.chatCrypto.importSessionKey(sessionKeyBase64);
            
            // 4. Pobierz zaszyfrowane wiadomości
            const response = await fetch(`/api/messages/${sessionToken}`);
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Błąd pobierania wiadomości');
            }
            
            // 5. Odszyfruj wiadomości
            const decryptedMessages = [];
            for (const msg of data.messages) {
                try {
                    const encryptedMessage = {
                        iv: msg.iv,
                        encryptedData: msg.content
                    };
                    
                    const decryptedContent = await window.chatCrypto.decryptMessage(encryptedMessage, sessionKey);
                    
                    decryptedMessages.push({
                        ...msg,
                        content: decryptedContent
                    });
                } catch (decryptError) {
                    console.error('Błąd deszyfrowania wiadomości:', decryptError);
                    // Dodaj informację o błędzie deszyfrowania
                    decryptedMessages.push({
                        ...msg,
                        content: '[Nie można odszyfrować wiadomości]',
                        decryptError: true
                    });
                }
            }
            
            return {
                status: 'success',
                messages: decryptedMessages
            };
            
        } catch (error) {
            console.error('Błąd pobierania wiadomości:', error);
            return {
                status: 'error',
                message: error.message
            };
        }
    }
}

// Inicjalizacja menedżera sesji czatu
window.chatSessionManager = new ChatSessionManager();
