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

    /**
     * Formatuje wzmianki w treści wiadomości
     */
    formatMessageWithMentions(text) {
        // Zamień wzmiankę w tekście na odpowiednio formatowane HTML
        return text.replace(/@(\w+)/g, '<span class="mention">@$1</span>');
    }
    
    /**
     * Formatuje czas wiadomości
     */
    formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        
        // Format godziny
        const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        if (date >= today) {
            return timeStr;
        } else if (date >= yesterday) {
            return `Wczoraj, ${timeStr}`;
        } else {
            return `${date.toLocaleDateString()} ${timeStr}`;
        }
    }
    
    /**
     * Przewija widok wiadomości na dół
     */
    scrollToBottom() {
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }
    
    /**
     * Sprawdza, czy sesja jest gotowa do wysyłania wiadomości
     */
    async ensureSessionReady() {
        if (!this.currentSessionToken) {
            console.error("Brak aktywnej sesji");
            this.showNotification("Brak aktywnej sesji", "error");
            return false;
        }
        
        // Sprawdź, czy klucz sesji istnieje
        const sessionKey = localStorage.getItem(`session_key_${this.currentSessionToken}`);
        
        if (!sessionKey) {
            console.log("Brak klucza sesji, próba pobrania...");
            
            try {
                // Znajdź sesję w liście
                const session = this.sessions.find(s => s.token === this.currentSessionToken);
                
                if (!session) {
                    this.showNotification("Sesja nie istnieje", "error");
                    return false;
                }
                
                // Sprawdź, czy sesja ma klucz
                if (!session.has_key) {
                    this.showNotification("Sesja nie ma ustalonego klucza szyfrowania", "error");
                    return false;
                }
                
                // Pobierz klucz z serwera
                const result = await this.sessionManager.retrieveSessionKey(this.currentSessionToken);
                
                if (!result.success) {
                    this.showNotification("Nie można pobrać klucza sesji: " + result.message, "error");
                    return false;
                }
                
                // Sprawdź, czy klucz został pobrany
                if (!localStorage.getItem(`session_key_${this.currentSessionToken}`)) {
                    this.showNotification("Nie udało się odszyfrować klucza sesji", "error");
                    return false;
                }
            } catch (error) {
                console.error("Błąd podczas pobierania klucza sesji:", error);
                this.showNotification("Błąd podczas pobierania klucza sesji", "error");
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Funkcja obsługująca wysyłanie wiadomości
     */
    async sendMessage() {
        const content = this.messageInput.value.trim();
        if (!content) {
            console.error("Nie można wysłać pustej wiadomości");
            return;
        }
        
        // Sprawdź, czy mamy token sesji
        if (!this.currentSessionToken) {
            console.error("Brak aktywnej sesji");
            
            // Sprawdź, czy mamy wybrane jakieś okno czatu
            const activeItem = document.querySelector('.friend-item.active');
            if (activeItem) {
                // Jest wybrane okno czatu, ale nie ma tokenu sesji - to błąd
                this.showNotification("Błąd sesji czatu. Spróbuj odświeżyć stronę.", "error");
            } else {
                // Nie ma wybranego okna czatu - poinformuj użytkownika
                this.showNotification("Wybierz znajomego z listy, aby rozpocząć rozmowę", "info");
                
                // Jeśli jest lista znajomych i istnieje znajomy, automatycznie wybierz pierwszego
                if (this.friends && this.friends.length > 0) {
                    console.log("Próba automatycznego wyboru pierwszego znajomego");
                    try {
                        await this.initSession(this.friends[0].user_id);
                        // Po inicjalizacji sesji, spróbuj ponownie wysłać wiadomość
                        setTimeout(() => this.sendMessage(), 500);
                    } catch (e) {
                        console.error("Błąd automatycznego wyboru znajomego:", e);
                    }
                }
            }
            return;
        }
        
        // Sprawdź gotowość sesji przed wysłaniem
        const isSessionReady = await this.ensureSessionReady();
        if (!isSessionReady) {
            console.error("Sesja nie jest gotowa do wysyłania wiadomości");
            return;
        }
        
        try {
            console.log("Próba wysłania wiadomości");
            
            // Wykrywanie wzmianek
            const mentions = this.detectMentions(content);
            
            // Wyślij wiadomość przez menedżer sesji
            const result = await this.sessionManager.sendMessage(this.currentSessionToken, content, mentions);
            
            if (result.status === 'success') {
                // Dodaj wiadomość do interfejsu
                this.addMessageToUI(result.messageData);
                
                // Wyczyść pole wejściowe
                this.messageInput.value = '';
                
                // Zamknij sugestie wzmianek, jeśli są otwarte
                this.closeMentionSuggestions();
            } else {
                console.error("Błąd podczas wysyłania:", result.message);
                this.showNotification(result.message || 'Błąd wysyłania wiadomości', "error");
            }
        } catch (error) {
            console.error('Błąd wysyłania wiadomości:', error);
            this.showNotification('Nie udało się wysłać wiadomości: ' + error.message, "error");
        }
    }

    /**
     * Obsługuje nową wiadomość z WebSocket
     */
    displayNewMessage(sessionToken, message) {
        // Sprawdź, czy to wiadomość dla aktualnie wyświetlanej sesji
        if (sessionToken === this.currentSessionToken) {
            // Dodaj wiadomość do interfejsu
            this.addMessageToUI(message);
            
            // Oznacz wiadomość jako przeczytaną
            this.markMessageAsRead(sessionToken, message.id);
        } else {
            // Zaktualizuj licznik nieprzeczytanych wiadomości w innej sesji
            const sessionItem = document.querySelector(`.friend-item[data-session-token="${sessionToken}"]`);
            if (sessionItem) {
                let unreadBadge = sessionItem.querySelector('.unread-badge');
                
                if (!unreadBadge) {
                    unreadBadge = document.createElement('div');
                    unreadBadge.className = 'unread-badge';
                    sessionItem.querySelector('.friend-info').appendChild(unreadBadge);
                    unreadBadge.textContent = '1';
                } else {
                    const count = parseInt(unreadBadge.textContent);
                    unreadBadge.textContent = (count + 1).toString();
                }
                
                // Powiadomienie dźwiękowe
                this.playNotificationSound();
                
                // Pokaż powiadomienie desktopowe, jeśli strona jest w tle
                this.showDesktopNotification(sessionToken, message);
            }
        }
    }
    
    /**
     * Oznacza wiadomość jako przeczytaną
     */
    markMessageAsRead(sessionToken, messageId) {
        if (!this.sessionManager) return;
        this.sessionManager.markMessageAsRead(sessionToken, messageId);
    }
    
    /**
     * Obsługuje wprowadzanie tekstu z potencjalnymi wzmiankami
     */
    async handleMentionInput() {
        // Pobierz tekst i pozycję kursora
        const text = this.messageInput.value;
        const cursorPosition = this.messageInput.selectionStart;
        
        // Resetuj stan wzmianek
        this.closeMentionSuggestions();
        
        // Znajdź ostatnią wzmiankę przed kursorem
        const textBeforeCursor = text.substring(0, cursorPosition);
        const mentionMatch = textBeforeCursor.match(/@(\w*)$/);
        
        if (mentionMatch) {
            console.log("Wykryto wzmiankę:", mentionMatch[0]);
            
            // Zapamiętaj pozycję wzmianki
            this.currentMentionPosition = mentionMatch.index;
            const query = mentionMatch[1].toLowerCase();
            
            // Upewnij się, że mamy załadowaną listę znajomych
            if (!this.friends || this.friends.length === 0) {
                try {
                    console.log("Brak znajomych, próba odświeżenia...");
                    await this.loadFriends();
                } catch (e) {
                    console.error("Błąd ładowania znajomych:", e);
                }
            }
            
            // Filtruj znajomych pasujących do zapytania
            const filteredFriends = this.friends.filter(friend => 
                friend.username.toLowerCase().includes(query)
            );
            
            console.log("Znaleziono pasujących znajomych:", filteredFriends.length);
            
            if (filteredFriends.length > 0) {
                this.showMentionSuggestions(filteredFriends, query);
            }
        }
    }
    
    /**
     * Pokazuje sugestie wzmianek
     */
    showMentionSuggestions(users, query) {
        // Utwórz lub pobierz kontener sugestii
        if (!this.mentionSuggestions) {
            this.mentionSuggestions = document.createElement('div');
            this.mentionSuggestions.className = 'mention-suggestions';
            document.body.appendChild(this.mentionSuggestions);
        }
        
        // Wyczyść poprzednie sugestie
        this.mentionSuggestions.innerHTML = '';
        
        // Dodaj nowe sugestie
        users.forEach((user, index) => {
            const suggestion = document.createElement('div');
            suggestion.className = 'mention-item';
            suggestion.textContent = user.username;
            
            if (index === this.selectedMentionIndex) {
                suggestion.classList.add('selected');
            }
            
            suggestion.addEventListener('click', () => {
                this.insertMention(user.username);
            });
            
            this.mentionSuggestions.appendChild(suggestion);
        });
        
        // Ustaw pozycję kontenera sugestii pod wzmianką
        const coords = this.getCaretCoordinates();
        this.mentionSuggestions.style.top = `${coords.bottom}px`;
        this.mentionSuggestions.style.left = `${coords.left}px`;
        
        // Zapamiętaj użytkowników
        this.mentionedUsers = users;
        this.selectedMentionIndex = 0;
    }
    
    /**
     * Pobiera pozycję kursora
     */
    getCaretCoordinates() {
        const inputRect = this.messageInput.getBoundingClientRect();
        return {
            left: inputRect.left,
            bottom: inputRect.bottom + window.scrollY
        };
    }
    
    /**
     * Obsługuje nawigację po sugestiach wzmianek
     */
    handleMentionNavigation(e) {
        if (!this.mentionSuggestions || this.mentionedUsers.length === 0) return;
        
        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                this.selectedMentionIndex = (this.selectedMentionIndex + 1) % this.mentionedUsers.length;
                this.updateSelectedMention();
                break;
                
            case 'ArrowUp':
                e.preventDefault();
                this.selectedMentionIndex = (this.selectedMentionIndex - 1 + this.mentionedUsers.length) % this.mentionedUsers.length;
                this.updateSelectedMention();
                break;
                
            case 'Tab':
            case 'Enter':
                if (this.mentionSuggestions) {
                    e.preventDefault();
                    this.insertMention(this.mentionedUsers[this.selectedMentionIndex].username);
                }
                break;
                
            case 'Escape':
                this.closeMentionSuggestions();
                break;
        }
    }
    
    /**
     * Aktualizuje zaznaczoną wzmiankę w sugestiach
     */
    updateSelectedMention() {
        const items = this.mentionSuggestions.querySelectorAll('.mention-item');
        
        items.forEach((item, index) => {
            if (index === this.selectedMentionIndex) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        });
    }
    
    /**
     * Wstawia wybraną wzmiankę do pola wejściowego
     */
    insertMention(username) {
        if (this.currentMentionPosition === -1) return;
        
        const text = this.messageInput.value;
        const cursorPosition = this.messageInput.selectionStart;
        
        // Znajdź początek i koniec wzmianki
        const textBeforeCursor = text.substring(0, cursorPosition);
        const mentionMatch = textBeforeCursor.match(/@(\w*)$/);
        
        if (mentionMatch) {
            const mentionStart = mentionMatch.index;
            const mentionEnd = cursorPosition;
            
            // Wstaw wzmiankę
            const newText = text.substring(0, mentionStart) + '@' + username + ' ' + text.substring(mentionEnd);
            this.messageInput.value = newText;
            
            // Ustaw kursor za wstawioną wzmianką
            const newPosition = mentionStart + username.length + 2; // +2 for @ and space
            this.messageInput.setSelectionRange(newPosition, newPosition);
            
            // Zamknij sugestie
            this.closeMentionSuggestions();
            
            // Ustaw focus z powrotem na pole wejściowe
            this.messageInput.focus();
        }
    }
    
    /**
     * Zamyka sugestie wzmianek
     */
    closeMentionSuggestions() {
        if (this.mentionSuggestions) {
            this.mentionSuggestions.remove();
            this.mentionSuggestions = null;
        }
        
        this.currentMentionPosition = -1;
        this.mentionedUsers = [];
        this.selectedMentionIndex = 0;
    }
    
    /**
     * Wykrywa wzmianki w wiadomości
     */
    detectMentions(message) {
        const mentionRegex = /@(\w+)/g;
        const mentions = [];
        let match;
        
        while ((match = mentionRegex.exec(message)) !== null) {
            mentions.push(match[1]); // Pobierz nazwę użytkownika bez @
        }
        
        return mentions;
    }
    /**
     * Odtwarza dźwięk powiadomienia
     */
    playNotificationSound() {
        try {
            const audio = new Audio('/static/sounds/notification.mp3');
            audio.volume = 0.5;
            audio.play().catch(err => {
                console.log('Nie można odtworzyć dźwięku powiadomienia', err);
            });
        } catch (error) {
            console.log('Błąd odtwarzania dźwięku', error);
        }
    }
    
    /**
     * Pokazuje powiadomienie desktopowe
     */
    showDesktopNotification(sessionToken, message) {
        // Sprawdź, czy strona jest w tle i czy przeglądarka obsługuje powiadomienia
        if (!("Notification" in window) || document.visibilityState !== "hidden") return;
        
        const session = this.sessions.find(s => s.token === sessionToken);
        if (!session) return;
        
        // Tytuł i treść powiadomienia
        const username = session.other_user.username;
        const title = `Nowa wiadomość od ${username}`;
        
        // Treść powiadomienia (skrócona)
        let content = message.content;
        if (content.length > 50) {
            content = content.substring(0, 47) + '...';
        }
        
        // Sprawdź uprawnienia
        if (Notification.permission === "granted") {
            new Notification(title, {
                body: content,
                icon: '/static/images/notification-icon.png'
            });
        } else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(permission => {
                if (permission === "granted") {
                    new Notification(title, {
                        body: content,
                        icon: '/static/images/notification-icon.png'
                    });
                }
            });
        }
    }
    
    /**
     * Sprawdza połączenie WebSocket
     */
    checkWebSocketConnection() {
        const userId = this.currentUser ? this.currentUser.id : null;
        if (!userId) {
            console.error("Brak ID użytkownika");
            return false;
        }
        
        try {
            // Utwórz testowe połączenie WebSocket
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.hostname}:8765/ws/chat/${userId}`;
            
            console.log(`Próba połączenia z WebSocket: ${wsUrl}`);
            const ws = new WebSocket(wsUrl);
            
            // Ustaw timeout na połączenie
            const connectionTimeout = setTimeout(() => {
                if (ws.readyState !== 1) {  // 1 = OPEN
                    console.error("Timeout na połączenie WebSocket");
                    ws.close();
                    this.showNotification("Problem z połączeniem - powiadomienia w czasie rzeczywistym mogą nie działać", "warning");
                }
            }, 5000);
            
            ws.onopen = () => {
                console.log("WebSocket połączony!");
                clearTimeout(connectionTimeout);
                
                // Wyślij wiadomość testową
                ws.send(JSON.stringify({
                    type: 'connection_established',
                    user_id: userId
                }));
                
                // Nasłuchuj na wiadomości, w tym zaproszenia do znajomych
                ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        console.log("Odebrano wiadomość WebSocket:", data);
                        
                        if (data.type === 'friend_request') {
                            console.log("Odebrano zaproszenie do znajomych przez WebSocket");
                            this.loadPendingRequests();
                            this.showNotification(`Nowe zaproszenie do znajomych od ${data.from_user.username}`, 'info');
                            this.playNotificationSound();
                        }
                    } catch (error) {
                        console.error("Błąd przetwarzania wiadomości WebSocket:", error);
                    }
                };
                
                // Zachowaj połączenie dla późniejszego użycia
                window._webSocketConnection = ws;
            };
            
            ws.onerror = (e) => {
                console.error("Błąd WebSocket:", e);
                clearTimeout(connectionTimeout);
                this.showNotification("Problem z połączeniem - powiadomienia w czasie rzeczywistym mogą nie działać", "warning");
            };
            
            ws.onclose = () => {
                console.log("WebSocket zamknięty");
                clearTimeout(connectionTimeout);
                
                // Próbuj ponownie połączyć po 5 sekundach
                setTimeout(() => {
                    this.checkWebSocketConnection();
                }, 5000);
            };
            
            return true;
        } catch (error) {
            console.error("Błąd podczas sprawdzania połączenia WebSocket:", error);
            return false;
        }
    }
    
    /**
     * Pokazuje powiadomienie w interfejsie
     */
    showNotification(message, type = 'info', duration = 5000) {
        // Utwórz element powiadomienia na podstawie szablonu
        const template = document.getElementById('notification-template');
        if (!template) {
            // Fallback jeśli nie ma szablonu
            console.log(`${type.toUpperCase()}: ${message}`);
            return;
        }
        
        const notification = document.importNode(template.content, true).querySelector('.notification');
        if (!notification) return;
        
        // Ustaw typ powiadomienia
        notification.classList.add(type);
        
        // Ustaw treść
        const content = notification.querySelector('.notification-content');
        if (content) content.textContent = message;
        
        // Dodaj obsługę zamykania
        const closeButton = notification.querySelector('.notification-close');
        if (closeButton) {
            closeButton.addEventListener('click', () => {
                notification.classList.add('closing');
                setTimeout(() => notification.remove(), 300);
            });
        }
        
        // Dodaj do dokumentu
        document.body.appendChild(notification);
        
        // Automatycznie zamknij po określonym czasie
        setTimeout(() => {
            if (document.body.contains(notification)) {
                notification.classList.add('closing');
                setTimeout(() => notification.remove(), 300);
            }
        }, duration);
    }

    /**
     * Inicjalizuje mechanizm powiadomień o zaproszeniach
     */
    initializeFriendRequestNotifications() {
        // Utwórz kontener dla ikony powiadomień, jeśli nie istnieje
        this.createNotificationIcon();
        
        // Załaduj oczekujące zaproszenia
        this.loadPendingRequests();
        
        // Okresowe sprawdzanie nowych zaproszeń (co 30 sekund)
        this._requestCheckInterval = setInterval(() => this.loadPendingRequests(), 30000);
        
        console.log("Zainicjalizowano system powiadomień o zaproszeniach");
    }

    /**
     * Tworzy ikonę powiadomień w interfejsie użytkownika
     */
    createNotificationIcon() {
        // Sprawdź, czy kontener nawigacji istnieje
        const navContainer = document.querySelector('.top-bar') || document.querySelector('header') || document.querySelector('nav');
        
        if (!navContainer) {
            console.error("Nie znaleziono kontenera nawigacji do umieszczenia ikony powiadomień");
            return;
        }
        
        // Sprawdź, czy ikona już istnieje
        if (document.getElementById('friend-request-notification')) {
            return;
        }
        
        // Utwórz ikonę powiadomień
        const notificationIcon = document.createElement('div');
        notificationIcon.id = 'friend-request-notification';
        notificationIcon.className = 'notification-icon';
        notificationIcon.innerHTML = `
            <i class="fa fa-user-plus"></i>
            <span class="notification-badge" id="friend-request-count">0</span>
        `;
        
        // Dodaj obsługę kliknięcia
        notificationIcon.addEventListener('click', () => {
            this.showFriendRequestsPanel();
        });
        
        // Dodaj ikonę do nawigacji
        navContainer.appendChild(notificationIcon);
        
        // Ukryj licznik na początku
        document.getElementById('friend-request-count').style.display = 'none';
        
        // Dodaj style, jeśli Font Awesome nie jest dostępny
        if (!document.querySelector('link[href*="font-awesome"]')) {
            const style = document.createElement('style');
            style.textContent = `
                .notification-icon {
                    position: relative;
                    cursor: pointer;
                    margin-right: 15px;
                    padding: 5px;
                    width: 24px;
                    height: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .notification-icon::before {
                    content: '👥';
                    font-size: 18px;
                }
                
                .notification-badge {
                    position: absolute;
                    top: -5px;
                    right: -5px;
                    background-color: #f44336;
                    color: white;
                    border-radius: 50%;
                    min-width: 18px;
                    height: 18px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    font-size: 12px;
                    padding: 0 3px;
                }
            `;
            document.head.appendChild(style);
        }
    }
    
    /**
     * Ładuje oczekujące zaproszenia do znajomych
     */
    async loadPendingRequests() {
        try {
            console.log("Sprawdzanie oczekujących zaproszeń...");
            const response = await fetch('/api/friend_requests/pending');
            
            if (!response.ok) {
                throw new Error(`Błąd HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            console.log("Odpowiedź z API zaproszeń:", data);
            
            // Zachowaj listę zaproszeń
            this.pendingRequests = data.status === 'success' ? data.requests : [];
            
            // Aktualizuj licznik i powiadomienia
            this.updateRequestsCounter();
            
            return this.pendingRequests;
        } catch (error) {
            console.error('Błąd ładowania zaproszeń:', error);
            return [];
        }
    }

    /**
     * Aktualizuje licznik zaproszeń
     */
    updateRequestsCounter() {
        const badge = document.getElementById('friend-request-count');
        const icon = document.getElementById('friend-request-notification');
        
        if (!badge || !icon) return;
        
        const count = this.pendingRequests ? this.pendingRequests.length : 0;
        
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'block';
            
            // Pokaż powiadomienie, jeśli to nowe zaproszenia
            if (!this._lastRequestCount || this._lastRequestCount < count) {
                this.showNotification(`Masz ${count} ${this.getPolishPluralForm(count, 'oczekujące zaproszenie', 'oczekujące zaproszenia', 'oczekujących zaproszeń')} do znajomych`, 'info');
                this.playNotificationSound();
            }
        } else {
            badge.style.display = 'none';
        }
        
        this._lastRequestCount = count;
    }
    
    /**
     * Zwraca polską odmianę słowa dla liczby
     */
    getPolishPluralForm(number, form1, form2, form5) {
        if (number === 1) {
            return form1;
        } else if (number % 10 >= 2 && number % 10 <= 4 && (number % 100 < 10 || number % 100 >= 20)) {
            return form2;
        } else {
            return form5;
        }
    }

    /**
     * Inicjalizuje mechanizm powiadomień o zaproszeniach
     */
    initializeFriendRequestNotifications() {
        // Utwórz kontener dla ikony powiadomień, jeśli nie istnieje
        this.createNotificationIcon();
        
        // Załaduj oczekujące zaproszenia
        this.loadPendingRequests();
        
        // Okresowe sprawdzanie nowych zaproszeń (co 30 sekund)
        this._requestCheckInterval = setInterval(() => this.loadPendingRequests(), 30000);
        
        console.log("Zainicjalizowano system powiadomień o zaproszeniach");
    }

    /**
     * Tworzy ikonę powiadomień w interfejsie użytkownika
     */
    createNotificationIcon() {
        // Sprawdź, czy kontener nawigacji istnieje
        const navContainer = document.querySelector('.top-bar') || document.querySelector('header') || document.querySelector('nav');
        
        if (!navContainer) {
            console.error("Nie znaleziono kontenera nawigacji do umieszczenia ikony powiadomień");
            return;
        }
        
        // Sprawdź, czy ikona już istnieje
        if (document.getElementById('friend-request-notification')) {
            return;
        }
        
        // Utwórz ikonę powiadomień
        const notificationIcon = document.createElement('div');
        notificationIcon.id = 'friend-request-notification';
        notificationIcon.className = 'notification-icon';
        notificationIcon.innerHTML = `
            <i class="fa fa-user-plus"></i>
            <span class="notification-badge" id="friend-request-count">0</span>
        `;
        
        // Dodaj obsługę kliknięcia
        notificationIcon.addEventListener('click', () => {
            this.showFriendRequestsPanel();
        });
        
        // Dodaj ikonę do nawigacji
        navContainer.appendChild(notificationIcon);
        
        // Ukryj licznik na początku
        document.getElementById('friend-request-count').style.display = 'none';
        
        // Dodaj style, jeśli Font Awesome nie jest dostępny
        if (!document.querySelector('link[href*="font-awesome"]')) {
            const style = document.createElement('style');
            style.textContent = `
                .notification-icon {
                    position: relative;
                    cursor: pointer;
                    margin-right: 15px;
                    padding: 5px;
                    width: 24px;
                    height: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .notification-icon::before {
                    content: '👥';
                    font-size: 18px;
                }
                
                .notification-badge {
                    position: absolute;
                    top: -5px;
                    right: -5px;
                    background-color: #f44336;
                    color: white;
                    border-radius: 50%;
                    min-width: 18px;
                    height: 18px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    font-size: 12px;
                    padding: 0 3px;
                }
            `;
            document.head.appendChild(style);
        }
    }
    
    /**
     * Ładuje oczekujące zaproszenia do znajomych
     */
    async loadPendingRequests() {
        try {
            console.log("Sprawdzanie oczekujących zaproszeń...");
            const response = await fetch('/api/friend_requests/pending');
            
            if (!response.ok) {
                throw new Error(`Błąd HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            console.log("Odpowiedź z API zaproszeń:", data);
            
            // Zachowaj listę zaproszeń
            this.pendingRequests = data.status === 'success' ? data.requests : [];
            
            // Aktualizuj licznik i powiadomienia
            this.updateRequestsCounter();
            
            return this.pendingRequests;
        } catch (error) {
            console.error('Błąd ładowania zaproszeń:', error);
            return [];
        }
    }

    /**
     * Aktualizuje licznik zaproszeń
     */
    updateRequestsCounter() {
        const badge = document.getElementById('friend-request-count');
        const icon = document.getElementById('friend-request-notification');
        
        if (!badge || !icon) return;
        
        const count = this.pendingRequests ? this.pendingRequests.length : 0;
        
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'block';
            
            // Pokaż powiadomienie, jeśli to nowe zaproszenia
            if (!this._lastRequestCount || this._lastRequestCount < count) {
                this.showNotification(`Masz ${count} ${this.getPolishPluralForm(count, 'oczekujące zaproszenie', 'oczekujące zaproszenia', 'oczekujących zaproszeń')} do znajomych`, 'info');
                this.playNotificationSound();
            }
        } else {
            badge.style.display = 'none';
        }
        
        this._lastRequestCount = count;
    }
    
    /**
     * Zwraca polską odmianę słowa dla liczby
     */
    getPolishPluralForm(number, form1, form2, form5) {
        if (number === 1) {
            return form1;
        } else if (number % 10 >= 2 && number % 10 <= 4 && (number % 100 < 10 || number % 100 >= 20)) {
            return form2;
        } else {
            return form5;
        }
    }

    /**
     * Wyświetla panel z zaproszeniami do znajomych
     */
    async showFriendRequestsPanel() {
        // Pobierz najnowsze zaproszenia
        let requests = this.pendingRequests;
        
        if (!requests || requests.length === 0) {
            // Spróbuj odświeżyć
            requests = await this.loadPendingRequests();
        }
        
        // Stwórz modal z listą zaproszeń, jeśli nie istnieje
        let modal = document.getElementById('friend-requests-modal');
        
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'friend-requests-modal';
            
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <span class="modal-close">&times;</span>
                        <h2>Zaproszenia do znajomych</h2>
                    </div>
                    <div id="friend-requests-list">
                        <!-- Tu będą zaproszenia -->
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            // Dodaj style dla modalu
            const style = document.createElement('style');
            style.textContent = `
                #friend-requests-modal {
                    display: none;
                    position: fixed;
                    z-index: 1000;
                    left: 0;
                    top: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0,0,0,0.4);
                }
                
                .modal-content {
                    background-color: #fefefe;
                    margin: 10% auto;
                    padding: 20px;
                    border-radius: 8px;
                    width: 80%;
                    max-width: 500px;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                }
                
                .modal-close {
                    color: #aaa;
                    float: right;
                    font-size: 28px;
                    font-weight: bold;
                    cursor: pointer;
                    line-height: 1;
                }
                
                .modal-header {
                    margin-bottom: 20px;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                }
                
                .friend-request-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 10px 0;
                    border-bottom: 1px solid #eee;
                }
            `;
            document.head.appendChild(style);
            
            // Dodaj obsługę zamykania
            modal.querySelector('.modal-close').addEventListener('click', () => {
                modal.style.display = 'none';
            });
            
            // Zamknij po kliknięciu poza modalem
            window.addEventListener('click', (event) => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }
        
        // Wypełnij listę zaproszeniami
        const requestsList = document.getElementById('friend-requests-list');
        requestsList.innerHTML = '';
        
        if (requests && requests.length > 0) {
            requests.forEach(request => {
                const item = document.createElement('div');
                item.className = 'friend-request-item';
                item.dataset.id = request.id;
                
                const userInfo = document.createElement('div');
                userInfo.className = 'user-info';
                
                const userName = document.createElement('div');
                userName.className = 'user-name';
                userName.textContent = request.username;
                
                const timestamp = document.createElement('div');
                timestamp.className = 'request-time';
                
                // Formatuj datę
                const requestDate = new Date(request.created_at);
                const now = new Date();
                const isToday = requestDate.toDateString() === now.toDateString();
                const dateFormat = isToday 
                    ? `Dzisiaj, ${requestDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
                    : requestDate.toLocaleString();
                
                timestamp.textContent = dateFormat;
                
                userInfo.appendChild(userName);
                userInfo.appendChild(timestamp);
                
                const actions = document.createElement('div');
                actions.className = 'request-actions';
                
                const acceptBtn = document.createElement('button');
                acceptBtn.className = 'accept-btn';
                acceptBtn.textContent = 'Akceptuj';
                acceptBtn.addEventListener('click', () => {
                    this.acceptFriendRequest(request.id);
                });
                
                const rejectBtn = document.createElement('button');
                rejectBtn.className = 'reject-btn';
                rejectBtn.textContent = 'Odrzuć';
                rejectBtn.addEventListener('click', () => {
                    this.rejectFriendRequest(request.id);
                });
                
                actions.appendChild(acceptBtn);
                actions.appendChild(rejectBtn);
                
                item.appendChild(userInfo);
                item.appendChild(actions);
                
                requestsList.appendChild(item);
            });
        } else {
            const noRequests = document.createElement('div');
            noRequests.className = 'no-requests';
            noRequests.textContent = 'Brak oczekujących zaproszeń';
            requestsList.appendChild(noRequests);
        }
        
        // Pokaż modal
        modal.style.display = 'block';
    }

    /**
     * Akceptuje zaproszenie do znajomych
     */
    async acceptFriendRequest(requestId) {
        try {
            const modal = document.getElementById('friend-requests-modal');
            const requestItem = modal.querySelector(`.friend-request-item[data-id="${requestId}"]`);
            
            if (requestItem) {
                // Pokazuj stan ładowania
                requestItem.classList.add('processing');
                const actions = requestItem.querySelector('.request-actions');
                if (actions) {
                    actions.innerHTML = '<div class="loading-spinner">Akceptowanie...</div>';
                }
            }
            
            const response = await fetch(`/api/friend_requests/${requestId}/accept`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin'
            });
            
            if (!response.ok) {
                throw new Error(`Błąd HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Odpowiedź na akceptację zaproszenia:', data);
            
            if (data.status === 'success') {
                this.showNotification('Zaproszenie zaakceptowane', 'success');
                
                // Odśwież listy
                await this.loadFriends();
                await this.loadPendingRequests();
                
                // Jeśli modal jest otwarty, zaktualizuj go
                if (modal) {
                    if (this.pendingRequests.length === 0) {
                        modal.style.display = 'none';
                    } else {
                        this.showFriendRequestsPanel();
                    }
                }
            } else {
                this.showNotification(data.message || 'Błąd akceptacji zaproszenia', 'error');
                if (requestItem) {
                    requestItem.classList.remove('processing');
                    this.showFriendRequestsPanel();
                }
            }
        } catch (error) {
            console.error('Błąd akceptacji zaproszenia:', error);
            this.showNotification('Wystąpił błąd podczas akceptacji zaproszenia', 'error');
            this.showFriendRequestsPanel();
        }
    }

    /**
     * Odrzuca zaproszenie do znajomych
     */
    async rejectFriendRequest(requestId) {
        try {
            const modal = document.getElementById('friend-requests-modal');
            const requestItem = modal.querySelector(`.friend-request-item[data-id="${requestId}"]`);
            
            if (requestItem) {
                requestItem.classList.add('processing');
                const actions = requestItem.querySelector('.request-actions');
                if (actions) {
                    actions.innerHTML = '<div class="loading-spinner">Odrzucanie...</div>';
                }
            }
            
            const response = await fetch(`/api/friend_requests/${requestId}/reject`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin'
            });
            
            if (!response.ok) {
                throw new Error(`Błąd HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showNotification('Zaproszenie odrzucone', 'info');
                await this.loadPendingRequests();
                
                if (modal) {
                    if (this.pendingRequests.length === 0) {
                        modal.style.display = 'none';
                    } else {
                        this.showFriendRequestsPanel();
                    }
                }
            } else {
                this.showNotification(data.message || 'Błąd odrzucenia zaproszenia', 'error');
                if (requestItem) {
                    requestItem.classList.remove('processing');
                    this.showFriendRequestsPanel();
                }
            }
        } catch (error) {
            console.error('Błąd odrzucenia zaproszenia:', error);
            this.showNotification('Wystąpił błąd podczas odrzucenia zaproszenia', 'error');
            this.showFriendRequestsPanel();
        }
    }

    /**
     * Wysyła zaproszenie do znajomych
     */
    async sendFriendRequest() {
        const usernameInput = document.getElementById('friend-user-id');
        const statusDiv = document.getElementById('friend-request-status');
        
        if (!usernameInput || !statusDiv) {
            console.error('Brak elementów UI dla wysyłania zaproszeń');
            return;
        }
        
        const username = usernameInput.value.trim();
        if (!username) {
            statusDiv.textContent = 'Wprowadź nazwę użytkownika';
            statusDiv.className = 'search-error';
            statusDiv.style.display = 'block';
            return;
        }
        
        try {
            statusDiv.textContent = 'Wysyłanie zaproszenia...';
            statusDiv.className = 'search-no-results';
            statusDiv.style.display = 'block';
            
            // Sprawdź połączenie WebSocket przed wysłaniem
            this.checkWebSocketConnection();
            
            const response = await fetch('/api/friend_requests', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin',
                body: JSON.stringify({ username: username })
            });
            
            if (!response.ok) {
                throw new Error(`Błąd HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Odpowiedź serwera:', data);
            
            if (data.status === 'success') {
                statusDiv.textContent = data.message || 'Zaproszenie wysłane pomyślnie';
                statusDiv.className = 'search-no-results search-success';
                usernameInput.value = '';
                
                // Zamknij modal po 3 sekundach
                setTimeout(() => {
                    const modal = document.getElementById('add-friend-modal');
                    if (modal) modal.style.display = 'none';
                    
                    // Odśwież listę zaproszeń i znajomych
                    this.loadFriends();
                }, 3000);
             } else {
                statusDiv.textContent = data.message || 'Wystąpił błąd';
                statusDiv.className = 'search-error';
            }
        } catch (error) {
            console.error('Błąd wysyłania zaproszenia:', error);
            statusDiv.textContent = 'Wystąpił błąd sieciowy: ' + error.message;
            statusDiv.className = 'search-error';
        }
    }

                /**
     * Wysyła zaproszenie do znajomych (kontynuacja)
     */
    async sendFriendRequest() {
        const usernameInput = document.getElementById('friend-user-id');
        const statusDiv = document.getElementById('friend-request-status');
        
        if (!usernameInput || !statusDiv) {
            console.error('Brak elementów UI dla wysyłania zaproszeń');
            return;
        }
        
        const username = usernameInput.value.trim();
        if (!username) {
            statusDiv.textContent = 'Wprowadź nazwę użytkownika';
            statusDiv.className = 'search-error';
            statusDiv.style.display = 'block';
            return;
        }
        
        try {
            statusDiv.textContent = 'Wysyłanie zaproszenia...';
            statusDiv.className = 'search-no-results';
            statusDiv.style.display = 'block';
            
            // Sprawdź połączenie WebSocket przed wysłaniem
            this.checkWebSocketConnection();
            
            const response = await fetch('/api/friend_requests', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin',
                body: JSON.stringify({ username: username })
            });
            
            if (!response.ok) {
                throw new Error(`Błąd HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Odpowiedź serwera:', data);
            
            if (data.status === 'success') {
                statusDiv.textContent = data.message || 'Zaproszenie wysłane pomyślnie';
                statusDiv.className = 'search-no-results search-success';
                usernameInput.value = '';
                
                // Zamknij modal po 3 sekundach
                setTimeout(() => {
                    const modal = document.getElementById('add-friend-modal');
                    if (modal) modal.style.display = 'none';
                    
                    // Odśwież listę zaproszeń i znajomych
                    this.loadFriends();
                }, 3000);
            } else {
                statusDiv.textContent = data.message || 'Wystąpił błąd';
                statusDiv.className = 'search-error';
            }
        } catch (error) {
            console.error('Błąd wysyłania zaproszenia:', error);
            statusDiv.textContent = 'Wystąpił błąd sieciowy: ' + error.message;
            statusDiv.className = 'search-error';
        }
    }
    
    /**
     * Funkcja diagnostyczna do sprawdzania stanu sesji
     * Można ją wywołać z konsoli przeglądarki: chatInterface.debugSessionState()
     */
    debugSessionState() {
        console.group("Stan sesji czatu");
        console.log("Aktualny token sesji:", this.currentSessionToken);
        
        if (this.currentSessionToken) {
            const hasKey = localStorage.getItem(`session_key_${this.currentSessionToken}`);
            console.log(`Klucz sesji istnieje: ${!!hasKey}`);
            
            const session = this.sessions.find(s => s.token === this.currentSessionToken);
            if (session) {
                console.log("Informacje o sesji:", {
                    token: session.token,
                    initiator_id: session.initiator_id,
                    recipient_id: session.recipient_id,
                    has_key: session.has_key,
                    key_acknowledged: session.key_acknowledged,
                    other_user: session.other_user
                });
            } else {
                console.log("Nie znaleziono sesji w liście:", this.sessions);
            }
        }
        
        console.log("Wszystkie sesje:", this.sessions);
        console.log("Lista znajomych:", this.friends);
        console.log("Oczekujące zaproszenia:", this.pendingRequests);
        
        if (this.sessionManager) {
            console.log("SessionManager zainicjalizowany:", true);
            if (typeof this.sessionManager.getActiveSessions === 'function') {
                console.log("Metoda getActiveSessions istnieje");
            }
            if (typeof this.sessionManager.sendMessage === 'function') {
                console.log("Metoda sendMessage istnieje");
            }
        } else {
            console.log("SessionManager nie jest dostępny!");
        }
        
        // Sprawdź stan WebSocket
        if (window._webSocketConnection) {
            console.log("WebSocket połączenie:", {
                readyState: window._webSocketConnection.readyState,
                url: window._webSocketConnection.url
            });
        } else {
            console.log("Brak aktywnego połączenia WebSocket");
        }
        
        console.groupEnd();
        
        return "Diagnostyka zakończona - sprawdź konsolę";
    }
}

// Inicjalizacja interfejsu po załadowaniu dokumentu
document.addEventListener('DOMContentLoaded', () => {
    // Sprawdź, czy użytkownik jest zalogowany
    if (sessionStorage.getItem('isLoggedIn') === 'true' || localStorage.getItem('isLoggedIn') === 'true') {
        // Inicjalizuj interfejs czatu
        window.chatInterface = new ChatInterface(window.sessionManager);
        
        // Zapytaj o uprawnienia do powiadomień, jeśli jeszcze nie zostały udzielone
        if ("Notification" in window && Notification.permission === "default") {
            setTimeout(() => {
                Notification.requestPermission();
            }, 3000);
        }
        
        // Dodaj skrót do debugowania w konsoli
        window.debugChat = () => {
            if (window.chatInterface) {
                return window.chatInterface.debugSessionState();
            } else {
                console.error("ChatInterface nie jest inicjalizowany");
                return "Błąd - ChatInterface niedostępny";
            }
        };
    }
});
