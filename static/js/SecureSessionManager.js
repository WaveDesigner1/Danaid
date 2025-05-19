/**
 * SecureSessionManager.js - Część 1/3
 * 
 * Zarządzanie sesjami komunikacyjnymi z szyfrowaniem end-to-end
 * Zapewnia interfejs do:
 * - Inicjalizacji i zarządzania sesjami bezpiecznej komunikacji
 * - Integracji z WebSocket dla komunikacji w czasie rzeczywistym
 * - Przechowywania lokalnego wiadomości z wykorzystaniem IndexedDB
 */

class SecureSessionManager {
    constructor() {
        // Stan sesji użytkownika
        this.user = {
            id: null,
            username: null,
            isAdmin: false,
            isLoggedIn: false
        };
        
        // Stan czatu
        this.activeSessions = [];
        this.currentSessionId = null;
        this.friends = [];
        this.onlineUsers = [];
        
        // WebSocket
        this.socket = null;
        this.socketReconnectDelay = 1000;
        this.socketMaxReconnectDelay = 30000;
        
        // Callbacks
        this.onMessageReceived = null;
        this.onSessionsUpdated = null;
        this.onFriendsUpdated = null;
        this.onOnlineStatusChanged = null;
        
        // IndexedDB inicjalizacja
        this.initializeDatabase();
        
        // Załaduj stan z localStorage
        this.loadState();
        
        // Sprawdź, czy użytkownik jest zalogowany
        this.checkLoginStatus();
        
        // Nasłuchiwanie na zdarzenia storage dla synchronizacji między kartami
        window.addEventListener('storage', (event) => {
            if (event.key === 'chat_user_state') {
                this.loadState();
            }
        });
    }
    
    /**
     * Sprawdza, czy użytkownik jest zalogowany
     */
    checkLoginStatus() {
        // Sprawdź w localStorage/sessionStorage
        const isLoggedIn = (
            sessionStorage.getItem('isLoggedIn') === 'true' || 
            localStorage.getItem('isLoggedIn') === 'true'
        );
        
        if (isLoggedIn) {
            // Pobierz dane użytkownika
            this.user.id = sessionStorage.getItem('user_id') || localStorage.getItem('user_id');
            this.user.username = sessionStorage.getItem('username') || localStorage.getItem('username');
            this.user.isAdmin = (sessionStorage.getItem('is_admin') === 'true' || localStorage.getItem('is_admin') === 'true');
            this.user.isLoggedIn = true;
            
            // Zainicjuj WebSocket, jeśli użytkownik jest zalogowany
            this.initializeWebSocket();
            
            // Pobierz aktywne sesje i znajomych
            this.fetchActiveSessions();
            this.fetchFriends();
            this.fetchOnlineUsers();
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Aktualizuje stan zalogowania użytkownika
     */
    login(userData) {
        this.user.id = userData.user_id;
        this.user.username = userData.username;
        this.user.isAdmin = userData.is_admin === true;
        this.user.isLoggedIn = true;
        
        // Zapisz dane w storage
        sessionStorage.setItem('isLoggedIn', 'true');
        sessionStorage.setItem('user_id', this.user.id);
        sessionStorage.setItem('username', this.user.username);
        sessionStorage.setItem('is_admin', this.user.isAdmin);
        
        // Zapisz również w localStorage dla trwałości między sesjami
        localStorage.setItem('isLoggedIn', 'true');
        localStorage.setItem('user_id', this.user.id);
        localStorage.setItem('username', this.user.username);
        localStorage.setItem('is_admin', this.user.isAdmin);
        
        // Zapisz stan do localStorage (dla synchronizacji między kartami)
        this.saveState();
        
        // Zainicjuj WebSocket
        this.initializeWebSocket();
        
        // Pobierz aktywne sesje i znajomych
        this.fetchActiveSessions();
        this.fetchFriends();
        this.fetchOnlineUsers();
        
        return true;
    }
    
    /**
     * Wylogowuje użytkownika
     */
    logout() {
        // Zamknij WebSocket
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        
        // Resetuj stan
        this.user = {
            id: null,
            username: null,
            isAdmin: false,
            isLoggedIn: false
        };
        
        this.activeSessions = [];
        this.currentSessionId = null;
        this.friends = [];
        this.onlineUsers = [];
        
        // Wyczyść dane sesji
        sessionStorage.removeItem('isLoggedIn');
        sessionStorage.removeItem('user_id');
        sessionStorage.removeItem('username');
        sessionStorage.removeItem('is_admin');
        
        // Wyczyść tylko status zalogowania w localStorage, ale zachowaj identyfikator i nazwę
        localStorage.setItem('isLoggedIn', 'false');
        
        // Zapisz stan
        this.saveState();
        
        // Wyślij ciche wylogowanie do serwera
        fetch('/silent-logout', {
            method: 'POST',
            credentials: 'same-origin'
        }).catch(error => {
            console.error('Błąd podczas cichego wylogowania:', error);
        });
        
        return true;
    }
    
    /**
     * Inicjalizuje połączenie WebSocket
     */
    initializeWebSocket() {
        if (!this.user.isLoggedIn || !this.user.id) {
            console.error('Próba inicjalizacji WebSocket bez zalogowanego użytkownika');
            return;
        }
        
        // Zamknij istniejące połączenie, jeśli istnieje
        if (this.socket) {
            this.socket.close();
        }
        
        // Utwórz nowe połączenie
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/chat/${this.user.id}`;
        
        this.socket = new WebSocket(wsUrl);
        
        // Obsługa zdarzeń WebSocket
        this.socket.onopen = this.handleSocketOpen.bind(this);
        this.socket.onmessage = this.handleSocketMessage.bind(this);
        this.socket.onclose = this.handleSocketClose.bind(this);
        this.socket.onerror = this.handleSocketError.bind(this);
    }
    
    /**
     * Obsługuje otwarcie połączenia WebSocket
     */
    handleSocketOpen(event) {
        console.log('WebSocket połączony');
        
        // Resetuj opóźnienie ponownego połączenia
        this.socketReconnectDelay = 1000;
        
        // Wyślij potwierdzenie połączenia
        this.sendToSocket({
            type: 'connection_established',
            user_id: this.user.id
        });
    }
    
    /**
     * Obsługuje wiadomości z WebSocket
     */
    async handleSocketMessage(event) {
        try {
            const data = JSON.parse(event.data);
            
            switch (data.type) {
                case 'new_message':
                    await this.handleNewMessage(data);
                    break;
                    
                case 'session_update':
                    await this.handleSessionUpdate(data);
                    break;
                    
                case 'user_status_change':
                    this.handleUserStatusChange(data);
                    break;
                    
                case 'friend_request':
                    this.handleFriendRequest(data);
                    break;
                    
                case 'friend_added':
                    await this.fetchFriends();
                    break;
                    
                case 'ping':
                    // Odpowiedz pong, aby utrzymać połączenie
                    this.sendToSocket({ type: 'pong' });
                    break;
                    
                default:
                    console.warn('Nieznany typ wiadomości WebSocket:', data.type);
                    break;
            }
        } catch (error) {
            console.error('Błąd przetwarzania wiadomości WebSocket:', error);
        }
    }
    
    /**
     * Obsługuje zamknięcie połączenia WebSocket
     */
    handleSocketClose(event) {
        console.log('WebSocket rozłączony:', event.code, event.reason);
        
        // Próba ponownego połączenia z opóźnieniem wykładniczym
        if (this.user.isLoggedIn) {
            console.log(`Ponowne połączenie za ${this.socketReconnectDelay}ms...`);
            
            setTimeout(() => {
                this.initializeWebSocket();
            }, this.socketReconnectDelay);
            
            // Zwiększ opóźnienie wykładniczo (max 30 sekund)
            this.socketReconnectDelay = Math.min(
                this.socketReconnectDelay * 1.5, 
                this.socketMaxReconnectDelay
            );
        }
    }
    
    /**
     * Obsługuje błędy WebSocket
     */
    handleSocketError(error) {
        console.error('Błąd WebSocket:', error);
    }
    
    /**
     * Wysyła dane przez WebSocket
     */
    sendToSocket(data) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify(data));
            return true;
        } else {
            console.warn('Próba wysłania danych przez zamknięty WebSocket');
            return false;
        }
    }
    /**
     * Obsługuje nową wiadomość z WebSocket
     */
    async handleNewMessage(data) {
        try {
            const { session_token, message } = data;
            
            // Pobierz sesję
            const session = this.activeSessions.find(s => s.token === session_token);
            
            if (!session) {
                console.warn('Odebrano wiadomość dla nieznanej sesji:', session_token);
                
                // Pobierz sesje na nowo
                await this.fetchActiveSessions();
                return;
            }
            
            // Pobierz klucz sesji
            const sessionKeyBase64 = localStorage.getItem(`session_key_${session.token}`);
            
            if (!sessionKeyBase64) {
                console.error('Brak klucza sesji dla wiadomości');
                return;
            }
            
            // Odszyfruj wiadomość
            try {
                // Importuj klucz sesji
                const sessionKey = await window.e2eeProtocol.importSessionKey(sessionKeyBase64);
                
                // Odszyfruj wiadomość
                const encryptedMessage = {
                    iv: message.iv,
                    encryptedData: message.content
                };
                
                const decryptedContent = await window.chatCrypto.decryptMessage(encryptedMessage, sessionKey);
                
                // Dodaj odszyfrowaną wiadomość do lokalnego magazynu
                const newMessage = {
                    id: message.id,
                    sender_id: message.sender_id,
                    content: decryptedContent,
                    timestamp: message.timestamp || new Date().toISOString(),
                    is_read: false
                };
                
                // Zapisz wiadomość w bazie danych
                await this.storeMessage(session.token, newMessage);
                
                // Powiadom o nowej wiadomości
                if (this.onMessageReceived) {
                    this.onMessageReceived(session.token, newMessage);
                }
                
                // Oznacz jako przeczytaną, jeśli to bieżąca sesja
                if (this.currentSessionId === session.token) {
                    this.markMessageAsRead(session.token, newMessage.id);
                    
                    // Wyślij potwierdzenie do serwera
                    this.sendMessageReadReceipt(session.token, newMessage.id);
                }
            } catch (error) {
                console.error('Błąd odszyfrowania wiadomości:', error);
            }
        } catch (error) {
            console.error('Błąd przetwarzania nowej wiadomości:', error);
        }
    }
    
    /**
     * Obsługuje aktualizację sesji z WebSocket
     */
    async handleSessionUpdate(data) {
        const { session_token } = data;
        
        // Sprawdź, czy to już istniejąca sesja
        const sessionIndex = this.activeSessions.findIndex(s => s.token === session_token);
        
        if (sessionIndex >= 0) {
            // Zaktualizuj sesję
            await this.refreshSession(session_token);
        } else {
            // Pobierz wszystkie sesje
            await this.fetchActiveSessions();
        }
    }
    
    /**
     * Obsługuje zmianę statusu użytkownika
     */
    handleUserStatusChange(data) {
        const { user_id, is_online } = data;
        
        // Aktualizuj listę użytkowników online
        const userIndex = this.onlineUsers.findIndex(u => u.user_id === user_id);
        
        if (is_online && userIndex === -1) {
            // Dodaj do listy online
            this.fetchUserInfo(user_id).then(userInfo => {
                if (userInfo) {
                    this.onlineUsers.push(userInfo);
                    
                    // Wywołaj callback
                    if (this.onOnlineStatusChanged) {
                        this.onOnlineStatusChanged(this.onlineUsers);
                    }
                }
            });
        } else if (!is_online && userIndex !== -1) {
            // Usuń z listy online
            this.onlineUsers.splice(userIndex, 1);
            
            // Wywołaj callback
            if (this.onOnlineStatusChanged) {
                this.onOnlineStatusChanged(this.onlineUsers);
            }
        }
    }
    
    /**
     * Obsługuje żądanie dodania do znajomych
     */
    handleFriendRequest(data) {
        const { from_user } = data;
        
        // Wyświetl notyfikację o nowym żądaniu
        this.showFriendRequestNotification(from_user);
        
        // Odśwież listę znajomych
        this.fetchFriends();
    }
    
    /**
     * Wyświetla powiadomienie o prośbie o dodanie do znajomych
     */
    showFriendRequestNotification(user) {
        // Sprawdź wsparcie dla powiadomień
        if (!("Notification" in window)) {
            console.warn("Ten przeglądarka nie obsługuje powiadomień");
            return;
        }
        
        // Sprawdź uprawnienia
        if (Notification.permission === "granted") {
            new Notification("Nowa prośba o dodanie do znajomych", {
                body: `${user.username} chce dodać Cię do znajomych`,
                icon: "/static/images/friend-request.png"
            });
        } else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(permission => {
                if (permission === "granted") {
                    new Notification("Nowa prośba o dodanie do znajomych", {
                        body: `${user.username} chce dodać Cię do znajomych`,
                        icon: "/static/images/friend-request.png"
                    });
                }
            });
        }
    }
    
    /**
     * Pobiera informacje o użytkowniku
     */
    async fetchUserInfo(userId) {
        try {
            const response = await fetch(`/api/user/${userId}/info`);
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const userData = await response.json();
            
            if (userData.status === 'success') {
                return userData.user;
            } else {
                throw new Error(userData.message || 'Błąd pobierania informacji o użytkowniku');
            }
        } catch (error) {
            console.error(`Błąd pobierania informacji o użytkowniku ${userId}:`, error);
            return null;
        }
    }
    
    /**
     * Pobiera aktywne sesje czatu
     */
    async fetchActiveSessions() {
        try {
            if (!this.user.isLoggedIn) {
                return [];
            }
            
            const response = await fetch('/api/sessions/active');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.activeSessions = data.sessions;
                
                // Aktualizuj stan w localStorage
                this.saveState();
                
                // Wywołaj callback
                if (this.onSessionsUpdated) {
                    this.onSessionsUpdated(this.activeSessions);
                }
                
                return this.activeSessions;
            } else {
                throw new Error(data.message || 'Błąd pobierania aktywnych sesji');
            }
        } catch (error) {
            console.error('Błąd pobierania aktywnych sesji:', error);
            return [];
        }
    }
    
    /**
     * Pobiera listę znajomych
     */
    async fetchFriends() {
        try {
            if (!this.user.isLoggedIn) {
                return [];
            }
            
            const response = await fetch('/api/friends');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.friends = data.friends;
                
                // Zapisz stan
                this.saveState();
                
                // Wywołaj callback
                if (this.onFriendsUpdated) {
                    this.onFriendsUpdated(this.friends);
                }
                
                return this.friends;
            } else {
                throw new Error(data.message || 'Błąd pobierania znajomych');
            }
        } catch (error) {
            console.error('Błąd pobierania znajomych:', error);
            return [];
        }
    }
    
    /**
     * Pobiera listę użytkowników online
     */
    async fetchOnlineUsers() {
        try {
            if (!this.user.isLoggedIn) {
                return [];
            }
            
            const response = await fetch('/api/online_users');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.onlineUsers = data.online_users;
                
                // Wywołaj callback
                if (this.onOnlineStatusChanged) {
                    this.onOnlineStatusChanged(this.onlineUsers);
                }
                
                return this.onlineUsers;
            } else {
                throw new Error(data.message || 'Błąd pobierania użytkowników online');
            }
        } catch (error) {
            console.error('Błąd pobierania użytkowników online:', error);
            return [];
        }
    }
    
    /**
     * Wysyła zaproszenie do znajomych
     */
    async sendFriendRequest(username) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            const response = await fetch('/api/friends/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Odśwież listę znajomych
                await this.fetchFriends();
                
                return {
                    success: true,
                    message: data.message || 'Zaproszenie wysłane pomyślnie'
                };
            } else {
                throw new Error(data.message || 'Błąd wysyłania zaproszenia');
            }
        } catch (error) {
            console.error('Błąd wysyłania zaproszenia:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
    
    /**
     * Akceptuje zaproszenie do znajomych
     */
    async acceptFriendRequest(requestId) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            const response = await fetch('/api/friends/accept', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ request_id: requestId })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Odśwież listę znajomych
                await this.fetchFriends();
                
                return {
                    success: true,
                    message: data.message || 'Zaproszenie zaakceptowane'
                };
            } else {
                throw new Error(data.message || 'Błąd akceptacji zaproszenia');
            }
        } catch (error) {
            console.error('Błąd akceptacji zaproszenia:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
    
    /**
     * Odrzuca zaproszenie do znajomych
     */
    async rejectFriendRequest(requestId) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            const response = await fetch('/api/friends/reject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ request_id: requestId })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Odśwież listę znajomych
                await this.fetchFriends();
                
                return {
                    success: true,
                    message: data.message || 'Zaproszenie odrzucone'
                };
            } else {
                throw new Error(data.message || 'Błąd odrzucenia zaproszenia');
            }
        } catch (error) {
            console.error('Błąd odrzucenia zaproszenia:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
    
    /**
     * Inicjuje nową sesję czatu
     */
    async initSession(recipientId) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            // Najpierw sprawdź, czy już mamy sesję z tym użytkownikiem
            const existingSession = this.activeSessions.find(
                session => session.other_user.user_id === recipientId
            );
            
            if (existingSession) {
                // Ustaw aktywną sesję
                this.setCurrentSession(existingSession.token);
                
                return {
                    success: true,
                    session: existingSession
                };
            }
            
            // Inicjuj nową sesję
            const response = await fetch('/api/session/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ recipient_id: recipientId })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Pobierz sesje na nowo
                await this.fetchActiveSessions();
                
                // Ustaw aktywną sesję
                this.setCurrentSession(data.session.token);
                
                // Jeśli jesteśmy inicjatorem i nie ma klucza, zainicjuj handshake
                if (data.session.initiator_id === parseInt(this.user.id) && !data.session.has_key) {
                    await this.initiateHandshake(data.session);
                }
                
                return {
                    success: true,
                    session: data.session
                };
            } else {
                throw new Error(data.message || 'Błąd inicjacji sesji');
            }
        } catch (error) {
            console.error('Błąd inicjacji sesji:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
    /**
     * Obsługuje nową wiadomość z WebSocket
     */
    async handleNewMessage(data) {
        try {
            const { session_token, message } = data;
            
            // Pobierz sesję
            const session = this.activeSessions.find(s => s.token === session_token);
            
            if (!session) {
                console.warn('Odebrano wiadomość dla nieznanej sesji:', session_token);
                
                // Pobierz sesje na nowo
                await this.fetchActiveSessions();
                return;
            }
            
            // Pobierz klucz sesji
            const sessionKeyBase64 = localStorage.getItem(`session_key_${session.token}`);
            
            if (!sessionKeyBase64) {
                console.error('Brak klucza sesji dla wiadomości');
                return;
            }
            
            // Odszyfruj wiadomość
            try {
                // Importuj klucz sesji
                const sessionKey = await window.e2eeProtocol.importSessionKey(sessionKeyBase64);
                
                // Odszyfruj wiadomość
                const encryptedMessage = {
                    iv: message.iv,
                    encryptedData: message.content
                };
                
                const decryptedContent = await window.chatCrypto.decryptMessage(encryptedMessage, sessionKey);
                
                // Dodaj odszyfrowaną wiadomość do lokalnego magazynu
                const newMessage = {
                    id: message.id,
                    sender_id: message.sender_id,
                    content: decryptedContent,
                    timestamp: message.timestamp || new Date().toISOString(),
                    is_read: false
                };
                
                // Zapisz wiadomość w bazie danych
                await this.storeMessage(session.token, newMessage);
                
                // Powiadom o nowej wiadomości
                if (this.onMessageReceived) {
                    this.onMessageReceived(session.token, newMessage);
                }
                
                // Oznacz jako przeczytaną, jeśli to bieżąca sesja
                if (this.currentSessionId === session.token) {
                    this.markMessageAsRead(session.token, newMessage.id);
                    
                    // Wyślij potwierdzenie do serwera
                    this.sendMessageReadReceipt(session.token, newMessage.id);
                }
            } catch (error) {
                console.error('Błąd odszyfrowania wiadomości:', error);
            }
        } catch (error) {
            console.error('Błąd przetwarzania nowej wiadomości:', error);
        }
    }
    
    /**
     * Obsługuje aktualizację sesji z WebSocket
     */
    async handleSessionUpdate(data) {
        const { session_token } = data;
        
        // Sprawdź, czy to już istniejąca sesja
        const sessionIndex = this.activeSessions.findIndex(s => s.token === session_token);
        
        if (sessionIndex >= 0) {
            // Zaktualizuj sesję
            await this.refreshSession(session_token);
        } else {
            // Pobierz wszystkie sesje
            await this.fetchActiveSessions();
        }
    }
    
    /**
     * Obsługuje zmianę statusu użytkownika
     */
    handleUserStatusChange(data) {
        const { user_id, is_online } = data;
        
        // Aktualizuj listę użytkowników online
        const userIndex = this.onlineUsers.findIndex(u => u.user_id === user_id);
        
        if (is_online && userIndex === -1) {
            // Dodaj do listy online
            this.fetchUserInfo(user_id).then(userInfo => {
                if (userInfo) {
                    this.onlineUsers.push(userInfo);
                    
                    // Wywołaj callback
                    if (this.onOnlineStatusChanged) {
                        this.onOnlineStatusChanged(this.onlineUsers);
                    }
                }
            });
        } else if (!is_online && userIndex !== -1) {
            // Usuń z listy online
            this.onlineUsers.splice(userIndex, 1);
            
            // Wywołaj callback
            if (this.onOnlineStatusChanged) {
                this.onOnlineStatusChanged(this.onlineUsers);
            }
        }
    }
    
    /**
     * Obsługuje żądanie dodania do znajomych
     */
    handleFriendRequest(data) {
        const { from_user } = data;
        
        // Wyświetl notyfikację o nowym żądaniu
        this.showFriendRequestNotification(from_user);
        
        // Odśwież listę znajomych
        this.fetchFriends();
    }
    
    /**
     * Wyświetla powiadomienie o prośbie o dodanie do znajomych
     */
    showFriendRequestNotification(user) {
        // Sprawdź wsparcie dla powiadomień
        if (!("Notification" in window)) {
            console.warn("Ten przeglądarka nie obsługuje powiadomień");
            return;
        }
        
        // Sprawdź uprawnienia
        if (Notification.permission === "granted") {
            new Notification("Nowa prośba o dodanie do znajomych", {
                body: `${user.username} chce dodać Cię do znajomych`,
                icon: "/static/images/friend-request.png"
            });
        } else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(permission => {
                if (permission === "granted") {
                    new Notification("Nowa prośba o dodanie do znajomych", {
                        body: `${user.username} chce dodać Cię do znajomych`,
                        icon: "/static/images/friend-request.png"
                    });
                }
            });
        }
    }
    
    /**
     * Pobiera informacje o użytkowniku
     */
    async fetchUserInfo(userId) {
        try {
            const response = await fetch(`/api/user/${userId}/info`);
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const userData = await response.json();
            
            if (userData.status === 'success') {
                return userData.user;
            } else {
                throw new Error(userData.message || 'Błąd pobierania informacji o użytkowniku');
            }
        } catch (error) {
            console.error(`Błąd pobierania informacji o użytkowniku ${userId}:`, error);
            return null;
        }
    }
    
    /**
     * Pobiera aktywne sesje czatu
     */
    async fetchActiveSessions() {
        try {
            if (!this.user.isLoggedIn) {
                return [];
            }
            
            const response = await fetch('/api/sessions/active');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.activeSessions = data.sessions;
                
                // Aktualizuj stan w localStorage
                this.saveState();
                
                // Wywołaj callback
                if (this.onSessionsUpdated) {
                    this.onSessionsUpdated(this.activeSessions);
                }
                
                return this.activeSessions;
            } else {
                throw new Error(data.message || 'Błąd pobierania aktywnych sesji');
            }
        } catch (error) {
            console.error('Błąd pobierania aktywnych sesji:', error);
            return [];
        }
    }
    
    /**
     * Pobiera listę znajomych
     */
    async fetchFriends() {
        try {
            if (!this.user.isLoggedIn) {
                return [];
            }
            
            const response = await fetch('/api/friends');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.friends = data.friends;
                
                // Zapisz stan
                this.saveState();
                
                // Wywołaj callback
                if (this.onFriendsUpdated) {
                    this.onFriendsUpdated(this.friends);
                }
                
                return this.friends;
            } else {
                throw new Error(data.message || 'Błąd pobierania znajomych');
            }
        } catch (error) {
            console.error('Błąd pobierania znajomych:', error);
            return [];
        }
    }
    
    /**
     * Pobiera listę użytkowników online
     */
    async fetchOnlineUsers() {
        try {
            if (!this.user.isLoggedIn) {
                return [];
            }
            
            const response = await fetch('/api/online_users');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.onlineUsers = data.online_users;
                
                // Wywołaj callback
                if (this.onOnlineStatusChanged) {
                    this.onOnlineStatusChanged(this.onlineUsers);
                }
                
                return this.onlineUsers;
            } else {
                throw new Error(data.message || 'Błąd pobierania użytkowników online');
            }
        } catch (error) {
            console.error('Błąd pobierania użytkowników online:', error);
            return [];
        }
    }
    
    /**
     * Wysyła zaproszenie do znajomych
     */
    async sendFriendRequest(username) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            const response = await fetch('/api/friends/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Odśwież listę znajomych
                await this.fetchFriends();
                
                return {
                    success: true,
                    message: data.message || 'Zaproszenie wysłane pomyślnie'
                };
            } else {
                throw new Error(data.message || 'Błąd wysyłania zaproszenia');
            }
        } catch (error) {
            console.error('Błąd wysyłania zaproszenia:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
    
    /**
     * Akceptuje zaproszenie do znajomych
     */
    async acceptFriendRequest(requestId) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            const response = await fetch('/api/friends/accept', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ request_id: requestId })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Odśwież listę znajomych
                await this.fetchFriends();
                
                return {
                    success: true,
                    message: data.message || 'Zaproszenie zaakceptowane'
                };
            } else {
                throw new Error(data.message || 'Błąd akceptacji zaproszenia');
            }
        } catch (error) {
            console.error('Błąd akceptacji zaproszenia:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
    
    /**
     * Odrzuca zaproszenie do znajomych
     */
    async rejectFriendRequest(requestId) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            const response = await fetch('/api/friends/reject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ request_id: requestId })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Odśwież listę znajomych
                await this.fetchFriends();
                
                return {
                    success: true,
                    message: data.message || 'Zaproszenie odrzucone'
                };
            } else {
                throw new Error(data.message || 'Błąd odrzucenia zaproszenia');
            }
        } catch (error) {
            console.error('Błąd odrzucenia zaproszenia:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
    
    /**
     * Inicjuje nową sesję czatu
     */
    async initSession(recipientId) {
        try {
            if (!this.user.isLoggedIn) {
                throw new Error('Użytkownik nie jest zalogowany');
            }
            
            // Najpierw sprawdź, czy już mamy sesję z tym użytkownikiem
            const existingSession = this.activeSessions.find(
                session => session.other_user.user_id === recipientId
            );
            
            if (existingSession) {
                // Ustaw aktywną sesję
                this.setCurrentSession(existingSession.token);
                
                return {
                    success: true,
                    session: existingSession
                };
            }
            
            // Inicjuj nową sesję
            const response = await fetch('/api/session/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ recipient_id: recipientId })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                // Pobierz sesje na nowo
                await this.fetchActiveSessions();
                
                // Ustaw aktywną sesję
                this.setCurrentSession(data.session.token);
                
                // Jeśli jesteśmy inicjatorem i nie ma klucza, zainicjuj handshake
                if (data.session.initiator_id === parseInt(this.user.id) && !data.session.has_key) {
                    await this.initiateHandshake(data.session);
                }
                
                return {
                    success: true,
                    session: data.session
                };
            } else {
                throw new Error(data.message || 'Błąd inicjacji sesji');
            }
        } catch (error) {
            console.error('Błąd inicjacji sesji:', error);
            
            return {
                success: false,
                message: error.message
            };
        }
    }
