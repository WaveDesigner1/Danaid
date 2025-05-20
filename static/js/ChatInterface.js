/**
 * ChatInterface.js - Interfejs użytkownika dla aplikacji czatu Danaid
 * Obsługuje interakcje z interfejsem czatu, w tym wysyłanie i odbieranie wiadomości
 */

class ChatInterface {
    constructor(sessionManager) {
        // Inicjalizacja menedżera sesji i elementów DOM
        this.sessionManager = sessionManager || window.sessionManager;
        this.friendsList = document.getElementById('friend-list');
        this.messagesContainer = document.getElementById('messages');
        this.messageInput = document.getElementById('message-input');
        this.sendButton = document.getElementById('send-button');
        this.addFriendBtn = document.getElementById('add-friend-btn');
        
        // Stan aplikacji
        this.currentSessionToken = null;
        this.currentUser = null;
        this.friends = [];
        this.onlineUsers = [];
        this.sessions = [];
        this.lastMessageTimes = {};
        this.pendingRequests = []; // Do przechowywania oczekujących zaproszeń
        
        // System wzmianek
        this.mentionedUsers = [];
        this.mentionSuggestions = null;
        this.currentMentionPosition = -1;
        this.selectedMentionIndex = 0;
        
        // Inicjalizacja
        this.initializeEvents();
        this.loadUserData();
        this.initializeFriendRequestNotifications(); // Inicjalizacja powiadomień o zaproszeniach
        this.loadFriends();
        this.loadSessions();
        
        // Sprawdź połączenie WebSocket
        setTimeout(() => this.checkWebSocketConnection(), 1000);
    }
    
    /**
     * Inicjalizacja nasłuchiwania zdarzeń
     */
    initializeEvents() {
        // Przycisk wysyłania wiadomości
        this.sendButton.addEventListener('click', () => this.sendMessage());
        
        // Obsługa Enter do wysyłania wiadomości
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });
        
        // Detekcja wzmianek i nawigacja
        this.messageInput.addEventListener('input', () => this.handleMentionInput());
        this.messageInput.addEventListener('keydown', (e) => this.handleMentionNavigation(e));
        
        // Zamykanie sugestii wzmianek po kliknięciu poza nimi
        document.addEventListener('click', (e) => {
            if (this.mentionSuggestions && !this.mentionSuggestions.contains(e.target) && e.target !== this.messageInput) {
                this.closeMentionSuggestions();
            }
        });
        
        // Obsługa modalu dodawania znajomych
        if (this.addFriendBtn) {
            this.addFriendBtn.addEventListener('click', () => {
                const modal = document.getElementById('add-friend-modal');
                if (modal) modal.style.display = 'block';
            });
        }
        
        // Zamykanie modalu dodawania znajomego
        const closeBtn = document.querySelector('.search-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                const modal = document.getElementById('add-friend-modal');
                if (modal) modal.style.display = 'none';
            });
        }
        
        // Przycisk wysyłania zaproszenia
        const sendFriendRequestBtn = document.getElementById('send-friend-request-btn');
        if (sendFriendRequestBtn) {
            sendFriendRequestBtn.addEventListener('click', () => this.sendFriendRequest());
        }

        // Nasłuchiwanie na zdarzenia z menedżera sesji
        if (this.sessionManager) {
            this.sessionManager.onMessageReceived = (sessionToken, message) => this.displayNewMessage(sessionToken, message);
            this.sessionManager.onSessionsUpdated = (sessions) => this.updateSessionsList(sessions);
            this.sessionManager.onFriendsUpdated = (friends) => this.updateFriendsList(friends);
            this.sessionManager.onOnlineStatusChanged = (onlineUsers) => this.updateOnlineStatus(onlineUsers);
            
            // Dodajemy obsługę powiadomień o zaproszeniach
            this.sessionManager.onFriendRequestReceived = (data) => {
                console.log("Odebrano zaproszenie:", data);
                this.loadPendingRequests();
            };
        }
    }
    
    /**
     * Ładuje dane użytkownika
     */
    loadUserData() {
        this.currentUser = {
            id: sessionStorage.getItem('user_id'),
            username: sessionStorage.getItem('username'),
            isAdmin: sessionStorage.getItem('is_admin') === 'true'
        };
        
        // Aktualizuj informacje w interfejsie
        const usernameDisplay = document.getElementById('username');
        if (usernameDisplay && this.currentUser.username) {
            usernameDisplay.textContent = this.currentUser.username;
        }
    }

/**
     * Ładuje listę znajomych z serwera
     */
    async loadFriends() {
        try {
            const response = await fetch('/api/friends');
            if (!response.ok) throw new Error('Błąd pobierania znajomych');
            
            const data = await response.json();
            if (data.status === 'success') {
                this.friends = data.friends;
                this.updateFriendsList(this.friends);
            }
        } catch (error) {
            console.error('Błąd ładowania znajomych:', error);
            this.showNotification('Błąd ładowania znajomych', 'error');
        }
    }

    /**
     * Ładuje aktywne sesje czatu z serwera
     */
    async loadSessions() {
        try {
            if (!this.sessionManager) return;
            
            const result = await this.sessionManager.getActiveSessions();
            if (result.status === 'success') {
                this.sessions = result.sessions;
                this.updateSessionsList(this.sessions);
                
                // Wybierz pierwszą sesję, jeśli jest dostępna
                if (this.sessions.length > 0 && !this.currentSessionToken) {
                    this.switchSession(this.sessions[0].token);
                }
            }
        } catch (error) {
            console.error('Błąd ładowania sesji:', error);
            this.showNotification('Błąd ładowania sesji czatu', 'error');
        }
    }
    
    /**
     * Aktualizuje listę sesji i znajomych w interfejsie
     */
    updateSessionsList(sessions) {
        this.sessions = sessions;
        this.renderFriendsList();
    }
    
    updateFriendsList(friends) {
        this.friends = friends;
        this.renderFriendsList();
    }
    
    /**
     * Aktualizuje status online użytkowników
     */
    updateOnlineStatus(onlineUsers) {
        this.onlineUsers = onlineUsers;
        
        // Aktualizuj wskaźniki statusu online w interfejsie
        const friendItems = document.querySelectorAll('.friend-item');
        friendItems.forEach(item => {
            const userId = item.dataset.userId;
            const statusIndicator = item.querySelector('.status-indicator');
            
            if (!statusIndicator) return;
            
            if (this.isUserOnline(userId)) {
                statusIndicator.classList.add('online');
                statusIndicator.classList.remove('offline');
            } else {
                statusIndicator.classList.add('offline');
                statusIndicator.classList.remove('online');
            }
        });
    }
    
    /**
     * Sprawdza, czy użytkownik jest online
     */
    isUserOnline(userId) {
        return this.onlineUsers.some(u => u.user_id === userId);
    }
    
    /**
     * Renderuje listę znajomych i sesji czatu
     */
    renderFriendsList() {
        if (!this.friendsList) return;
        
        // Wyczyść listę
        this.friendsList.innerHTML = '';
        
        // Dodaj aktywne sesje
        if (this.sessions.length > 0) {
            const sessionHeader = document.createElement('div');
            sessionHeader.className = 'friends-header';
            sessionHeader.textContent = 'Aktywne rozmowy';
            this.friendsList.appendChild(sessionHeader);
            
            this.sessions.forEach(session => {
                const otherUser = session.other_user;
                const listItem = this.createFriendListItem(otherUser, session.token);
                this.friendsList.appendChild(listItem);
            });
        }
        
        // Dodaj znajomych bez aktywnych sesji
        const friendsWithoutSession = this.friends.filter(friend => 
            !this.sessions.some(session => session.other_user.user_id === friend.user_id)
        );
        
        if (friendsWithoutSession.length > 0) {
            const friendsHeader = document.createElement('div');
            friendsHeader.className = 'friends-header';
            friendsHeader.textContent = 'Znajomi';
            this.friendsList.appendChild(friendsHeader);
            
            friendsWithoutSession.forEach(friend => {
                const listItem = this.createFriendListItem(friend);
                this.friendsList.appendChild(listItem);
            });
        }
    }
    
    /**
     * Tworzy element listy dla znajomego/sesji
     */
    createFriendListItem(user, sessionToken = null) {
        const li = document.createElement('li');
        li.className = 'friend-item';
        li.dataset.userId = user.user_id;
        
        if (sessionToken) {
            li.dataset.sessionToken = sessionToken;
            if (sessionToken === this.currentSessionToken) {
                li.classList.add('active');
            }
        }
        
        // Avatar i statusu
        const avatarDiv = document.createElement('div');
        avatarDiv.className = 'friend-avatar';
        avatarDiv.textContent = user.username.charAt(0).toUpperCase();
        
        const statusIndicator = document.createElement('div');
        statusIndicator.className = 'status-indicator';
        statusIndicator.classList.add(this.isUserOnline(user.user_id) ? 'online' : 'offline');
        avatarDiv.appendChild(statusIndicator);
        
        // Informacje o użytkowniku
        const infoDiv = document.createElement('div');
        infoDiv.className = 'friend-info';
        
        const nameDiv = document.createElement('div');
        nameDiv.className = 'friend-name';
        nameDiv.textContent = user.username;
        infoDiv.appendChild(nameDiv);
        
        // Obsługa kliknięcia
        li.addEventListener('click', async () => {
            if (sessionToken) {
                this.switchSession(sessionToken);
            } else {
                await this.initSession(user.user_id);
            }
        });
        
        li.appendChild(avatarDiv);
        li.appendChild(infoDiv);
        return li;
    }

/**
     * Inicjuje nową sesję czatu z użytkownikiem
     */
    async initSession(userId) {
        try {
            console.log(`Inicjalizacja sesji z użytkownikiem ${userId}`);
            
            // Sprawdź, czy mamy menedżera sesji
            if (!this.sessionManager) {
                console.error("Brak menedżera sesji");
                this.showNotification("Błąd inicjalizacji sesji: brak menedżera sesji", "error");
                return;
            }
            
            // Pokaż powiadomienie o ładowaniu
            this.showNotification("Inicjalizacja sesji czatu...", "info", 2000);
            
            const result = await this.sessionManager.initSession(userId);
            console.log("Wynik inicjalizacji sesji:", result);
            
            if (result.success) {
                // Upewnij się, że session token został ustawiony
                if (!result.session || !result.session.token) {
                    console.error("Inicjalizacja sesji nie zwróciła poprawnego tokenu");
                    this.showNotification("Błąd inicjalizacji sesji", "error");
                    return;
                }
                
                // Zaktualizuj listy
                await this.loadSessions();
                
                // Przełącz na nową sesję
                this.switchSession(result.session.token);
                
                console.log(`Sesja zainicjalizowana: ${result.session.token}`);
            } else {
                console.error(`Błąd inicjalizacji sesji: ${result.message}`);
                this.showNotification(result.message || 'Błąd inicjacji sesji', 'error');
            }
        } catch (error) {
            console.error('Błąd inicjacji sesji:', error);
            this.showNotification('Nie udało się rozpocząć rozmowy: ' + error.message, 'error');
        }
    }

    /**
     * Przełącza aktywną sesję
     */
    switchSession(sessionToken) {
        console.log(`Przełączanie na sesję: ${sessionToken}`);
        
        if (!sessionToken) {
            console.error("Próba przełączenia na pustą sesję");
            return;
        }
        
        if (sessionToken === this.currentSessionToken) {
            console.log("Już jesteśmy na tej sesji");
            return;
        }
        
        // Zapisz poprzedni token sesji (dla debugowania)
        const prevSessionToken = this.currentSessionToken;
        
        // Ustaw nowy token sesji
        this.currentSessionToken = sessionToken;
        console.log(`Token sesji zmieniony: ${prevSessionToken} -> ${this.currentSessionToken}`);
        
        // Aktualizuj aktywny element na liście
        const friendItems = document.querySelectorAll('.friend-item');
        friendItems.forEach(item => {
            if (item.dataset.sessionToken === sessionToken) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });
        
        // Pobierz sesję
        const session = this.sessions.find(s => s.token === sessionToken);
        if (!session) {
            console.error(`Nie znaleziono sesji o tokenie ${sessionToken}`);
            this.showNotification("Błąd: nie znaleziono sesji", "error");
            return;
        }
        
        // Wyświetl nazwę użytkownika w nagłówku czatu
        const chatHeaderTitle = document.querySelector('#chat-header h2');
        if (chatHeaderTitle) {
            chatHeaderTitle.textContent = session.other_user.username;
        }
        
        // Sprawdź, czy jest klucz sesji
        const hasSessionKey = localStorage.getItem(`session_key_${sessionToken}`);
        console.log(`Klucz sesji ${sessionToken} istnieje: ${!!hasSessionKey}`);
        
        // Załaduj wiadomości
        this.loadMessages(sessionToken);
        
        // Jeśli nie ma klucza sesji, spróbuj go pobrać
        if (!hasSessionKey && session.has_key) {
            console.log("Pobieranie klucza sesji...");
            // Wykonaj to asynchronicznie, aby nie blokować UI
            setTimeout(async () => {
                try {
                    await this.ensureSessionReady();
                } catch (e) {
                    console.error("Błąd pobierania klucza sesji:", e);
                }
            }, 500);
        }
    }
    
    /**
     * Ładuje wiadomości dla sesji
     */
    async loadMessages(sessionToken) {
        if (!this.sessionManager) return;
        
        // Wyczyść kontener wiadomości
        this.messagesContainer.innerHTML = '';
        
        try {
            // Pobierz wiadomości z lokalnego magazynu
            const result = this.sessionManager.getLocalMessages(sessionToken);
            
            if (result.status === 'success') {
                // Wyświetl wiadomości
                const messages = result.messages;
                messages.forEach(message => this.addMessageToUI(message));
                
                // Przewiń na dół
                this.scrollToBottom();
            }
        } catch (error) {
            console.error('Błąd ładowania wiadomości:', error);
            this.showNotification('Błąd ładowania wiadomości', 'error');
        }
    }
    
    /**
     * Dodaje nową wiadomość do interfejsu
     */
    addMessageToUI(message) {
        // Utwórz element wiadomości
        const messageElement = this.createMessageElement(message);
        this.messagesContainer.appendChild(messageElement);
        
        // Zapisz czas ostatniej wiadomości
        this.lastMessageTimes[this.currentSessionToken] = new Date(message.timestamp);
        
        // Przewiń na dół
        this.scrollToBottom();
    }
    
    /**
     * Tworzy element pojedynczej wiadomości
     */
    createMessageElement(message) {
        const messageDiv = document.createElement('div');
        
        // Określ, czy wiadomość jest wysłana przez aktualnego użytkownika
        const isSent = message.sender_id === parseInt(this.currentUser.id);
        messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
        
        // Zawartość wiadomości
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        contentDiv.innerHTML = this.formatMessageWithMentions(message.content);
        
        // Informacje o wiadomości
        const infoDiv = document.createElement('div');
        infoDiv.className = 'message-info';
        
        // Czas
        const timeSpan = document.createElement('span');
        timeSpan.className = 'message-time';
        timeSpan.textContent = this.formatTime(message.timestamp);
        
        // Status (tylko dla wysłanych wiadomości)
        if (isSent) {
            const statusSpan = document.createElement('span');
            statusSpan.className = 'message-status';
            statusSpan.textContent = message.is_read ? '✓✓' : '✓';
            statusSpan.classList.add(message.is_read ? 'read' : 'delivered');
            infoDiv.appendChild(statusSpan);
        }
        
        infoDiv.appendChild(timeSpan);
        messageDiv.appendChild(contentDiv);
        messageDiv.appendChild(infoDiv);
        
        return messageDiv;
    }
