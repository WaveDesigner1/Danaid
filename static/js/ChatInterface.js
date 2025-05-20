/**
 * ChatInterface.js - Interfejs użytkownika dla aplikacji czatu
 * Obsługuje interakcje z interfejsem czatu, w tym wysyłanie i odbieranie wiadomości
 */

class ChatInterface {
    constructor(sessionManager) {
        // Inicjalizacja menedżera sesji
        this.sessionManager = sessionManager || window.sessionManager;
        
        // Elementy DOM
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
        
        // Inicjalizacja
        this.initializeEvents();
        this.loadUserData();
        this.loadFriends();
        this.loadSessions();

        // System wzmianek
        this.mentionedUsers = [];
        this.mentionSuggestions = null;
        this.currentMentionPosition = -1;
        this.selectedMentionIndex = 0;
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
        
        // Detekcja wzmianek (@username)
        this.messageInput.addEventListener('input', () => this.handleMentionInput());
        this.messageInput.addEventListener('keydown', (e) => this.handleMentionNavigation(e));
        
        // Kliknięcie poza sugestiami wzmianek zamyka je
        document.addEventListener('click', (e) => {
            if (this.mentionSuggestions && !this.mentionSuggestions.contains(e.target) && e.target !== this.messageInput) {
                this.closeMentionSuggestions();
            }
        });
        
        // Dodawanie znajomego
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
        
        // Przycisk wysyłania zaproszenia do znajomych
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
     * Aktualizuje listę sesji w interfejsie
     */
    updateSessionsList(sessions) {
        this.sessions = sessions;
        this.renderFriendsList();
    }
    
    /**
     * Aktualizuje listę znajomych w interfejsie
     */
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
        
        // Nagłówek dla aktywnych sesji
        if (this.sessions.length > 0) {
            const sessionHeader = document.createElement('div');
            sessionHeader.className = 'friends-header';
            sessionHeader.textContent = 'Aktywne rozmowy';
            this.friendsList.appendChild(sessionHeader);
            
            // Dodaj elementy dla aktywnych sesji
            this.sessions.forEach(session => {
                const otherUser = session.other_user;
                const listItem = this.createFriendListItem(otherUser, session.token);
                this.friendsList.appendChild(listItem);
            });
        }
        
        // Nagłówek dla znajomych bez aktywnych sesji
        const friendsWithoutSession = this.friends.filter(friend => 
            !this.sessions.some(session => 
                session.other_user.user_id === friend.user_id
            )
        );
        
        if (friendsWithoutSession.length > 0) {
            const friendsHeader = document.createElement('div');
            friendsHeader.className = 'friends-header';
            friendsHeader.textContent = 'Znajomi';
            this.friendsList.appendChild(friendsHeader);
            
            // Dodaj elementy dla znajomych bez aktywnych sesji
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
        
        // Avatar
        const avatarDiv = document.createElement('div');
        avatarDiv.className = 'friend-avatar';
        avatarDiv.textContent = user.username.charAt(0).toUpperCase();
        
        // Status indicator
        const statusIndicator = document.createElement('div');
        statusIndicator.className = 'status-indicator';
        if (this.isUserOnline(user.user_id)) {
            statusIndicator.classList.add('online');
        } else {
            statusIndicator.classList.add('offline');
        }
        avatarDiv.appendChild(statusIndicator);
        
        // Info
        const infoDiv = document.createElement('div');
        infoDiv.className = 'friend-info';
        
        const nameDiv = document.createElement('div');
        nameDiv.className = 'friend-name';
        nameDiv.textContent = user.username;
        infoDiv.appendChild(nameDiv);
        
        // Obsługa kliknięcia
        li.addEventListener('click', async () => {
            if (sessionToken) {
                // Przełącz na istniejącą sesję
                this.switchSession(sessionToken);
            } else {
                // Inicjuj nową sesję
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
            const result = await this.sessionManager.initSession(userId);
            
            if (result.success) {
                // Zaktualizuj listy
                await this.loadSessions();
                
                // Przełącz na nową sesję
                this.switchSession(result.session.token);
            } else {
                this.showNotification(result.message || 'Błąd inicjacji sesji', 'error');
            }
        } catch (error) {
            console.error('Błąd inicjacji sesji:', error);
            this.showNotification('Nie udało się rozpocząć rozmowy', 'error');
        }
    }
    
    /**
     * Przełącza aktywną sesję
     */
    switchSession(sessionToken) {
        if (sessionToken === this.currentSessionToken) return;
        
        this.currentSessionToken = sessionToken;
        
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
        if (!session) return;
        
        // Wyświetl nazwę użytkownika w nagłówku czatu
        const chatHeaderTitle = document.querySelector('#chat-header h2');
        if (chatHeaderTitle) {
            chatHeaderTitle.textContent = session.other_user.username;
        }
        
        // Załaduj wiadomości
        this.loadMessages(sessionToken);
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
        
        // Przetwórz wzmianki w treści wiadomości
        const content = this.formatMessageWithMentions(message.content);
        contentDiv.innerHTML = content;
        
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
        
        // Określ, czy wiadomość jest z dzisiaj, wczoraj, czy wcześniej
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
     * Funkcja obsługująca wysyłanie wiadomości
     * Poprawiona wersja z obsługą błędów i dodatkowym logowaniem
     */
    async sendMessage() {
    const content = this.messageInput.value.trim();
    if (!content || !this.currentSessionToken) {
        console.error("Nie można wysłać wiadomości: pusty content lub brak tokenu sesji");
        console.log("Content:", content);
        console.log("Current session token:", this.currentSessionToken);
        return;
    }
    
    try {
        console.log("Próba wysłania wiadomości");
        console.log("Token sesji:", this.currentSessionToken);
        
        // Sprawdź klucz sesji w localStorage
        const sessionKey = localStorage.getItem(`session_key_${this.currentSessionToken}`);
        console.log("Klucz sesji istnieje:", !!sessionKey);
        
        // Sprawdź czy sessionManager jest poprawnie zainicjalizowany
        if (!this.sessionManager) {
            console.error("sessionManager nie jest dostępny");
            this.showNotification('Błąd połączenia z menedżerem sesji', 'error');
            return;
        }
        
        // Sprawdź czy chatCrypto jest dostępny
        console.log("chatCrypto dostępny:", !!window.chatCrypto);
        
        // Wykrywanie wzmianek
        const mentions = this.detectMentions(content);
        
        // Wyślij wiadomość przez menedżer sesji
        const result = await this.sessionManager.sendMessage(this.currentSessionToken, content, mentions);
        console.log("Wynik wysyłania wiadomości:", result);
        
        if (result.status === 'success') {
            // Dodaj wiadomość do interfejsu
            this.addMessageToUI(result.messageData);
            
            // Wyczyść pole wejściowe
            this.messageInput.value = '';
            
            // Zamknij sugestie wzmianek, jeśli są otwarte
            this.closeMentionSuggestions();
        } else {
            console.error("Błąd podczas wysyłania:", result.message);
            this.showNotification(result.message || 'Błąd wysyłania wiadomości', 'error');
        }
    } catch (error) {
        console.error('Błąd wysyłania wiadomości:', error);
        this.showNotification('Nie udało się wysłać wiadomości: ' + error.message, 'error');
    }
}

/**
 * Dodatkowa metoda debugowania do sprawdzania kluczy sesji
 */
checkSessionKeys() {
    if (this.currentSessionToken) {
        const sessionKey = localStorage.getItem(`session_key_${this.currentSessionToken}`);
        console.log("Klucz sesji dla tokenu", this.currentSessionToken, "istnieje:", !!sessionKey);
    } else {
        console.log("Brak aktywnej sesji");
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
     * Wysyła zaproszenie do znajomych
     */
    async sendFriendRequest() {
    // Pobierz nazwę użytkownika z pola
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
        // Wyślij żądanie API
        statusDiv.textContent = 'Wysyłanie zaproszenia...';
        statusDiv.className = 'search-no-results';
        statusDiv.style.display = 'block';
        
        console.log('Wysyłanie zaproszenia dla użytkownika:', username);
        
        const response = await fetch('/api/friend_requests', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username: username })
        });
        
        const data = await response.json();
        console.log('Odpowiedź serwera:', data);
        
        if (data.status === 'success') {
            statusDiv.textContent = data.message || 'Zaproszenie wysłane pomyślnie';
            statusDiv.className = 'search-no-results';
            usernameInput.value = '';
            
            // Zamknij modal po 3 sekundach
            setTimeout(() => {
                const modal = document.getElementById('add-friend-modal');
                if (modal) modal.style.display = 'none';
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

// W models.py
// Dodaj te dwie klasy do istniejącego pliku models.py

"""
class Friend(db.Model):
    '''Friends relationship model'''
    __tablename__ = 'friend'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'friend_id', name='uq_friend_user_friend'),
    )
    
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('friends', lazy='dynamic'))
    friend = db.relationship('User', foreign_keys=[friend_id], backref=db.backref('friended_by', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Friend {self.user_id} -> {self.friend_id}>'

class FriendRequest(db.Model):
    '''Friend request model'''
    __tablename__ = 'friend_request'
    
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('from_user_id', 'to_user_id', name='uq_request_from_to'),
    )
    
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref=db.backref('sent_requests', lazy='dynamic'))
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref=db.backref('received_requests', lazy='dynamic'))
    
    def __repr__(self):
        return f'<FriendRequest {self.from_user_id} -> {self.to_user_id} [{self.status}]>'
"""

# W chat.html
# Dodaj skrypt inicjalizujący dla dodawania znajomych
"""
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Inicjalizacja obsługi dodawania znajomych
    const addFriendBtn = document.getElementById('add-friend-btn');
    const friendUserIdInput = document.getElementById('friend-user-id');
    const sendFriendRequestBtn = document.getElementById('send-friend-request-btn');
    
    if (addFriendBtn && friendUserIdInput && sendFriendRequestBtn) {
        console.log('Inicjalizacja obsługi dodawania znajomych');
        
        // Obsługa przycisku dodawania znajomego
        addFriendBtn.addEventListener('click', function() {
            const modal = document.getElementById('add-friend-modal');
            if (modal) {
                modal.style.display = 'block';
                friendUserIdInput.value = '';
                const statusDiv = document.getElementById('friend-request-status');
                if (statusDiv) statusDiv.style.display = 'none';
            }
        });
        
        // Obsługa przycisku zamknięcia modalu
        const closeBtn = document.querySelector('.search-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', function() {
                const modal = document.getElementById('add-friend-modal');
                if (modal) modal.style.display = 'none';
            });
        }
        
        // Obsługa przycisku wysyłania zaproszenia
        sendFriendRequestBtn.addEventListener('click', function() {
            if (window.chatInterface && typeof window.chatInterface.sendFriendRequest === 'function') {
                window.chatInterface.sendFriendRequest();
            } else {
                console.error('Brak metody sendFriendRequest w chatInterface');
                const statusDiv = document.getElementById('friend-request-status');
                if (statusDiv) {
                    statusDiv.textContent = 'Błąd inicjalizacji interfejsu';
                    statusDiv.className = 'search-error';
                    statusDiv.style.display = 'block';
                }
            }
        });
    } else {
        console.warn('Brak elementów UI dla dodawania znajomych');
    }
});
</script>
    
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
     * Obsługuje wprowadzanie tekstu z potencjalnymi wzmiankami
     */
    handleMentionInput() {
        // Pobierz tekst i pozycję kursora
        const text = this.messageInput.value;
        const cursorPosition = this.messageInput.selectionStart;
        
        // Resetuj stan wzmianek
        this.closeMentionSuggestions();
        
        // Znajdź ostatnią wzmiankę przed kursorem
        const textBeforeCursor = text.substring(0, cursorPosition);
        const mentionMatch = textBeforeCursor.match(/@(\w*)$/);
        
        if (mentionMatch) {
            // Zapamiętaj pozycję wzmianki
            this.currentMentionPosition = mentionMatch.index;
            const query = mentionMatch[1].toLowerCase();
            
            // Filtruj znajomych pasujących do zapytania
            const filteredFriends = this.friends.filter(friend => 
                friend.username.toLowerCase().includes(query)
            );
            
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
        // Pobierz pozycję tekstowego elementu wejściowego
        const inputRect = this.messageInput.getBoundingClientRect();
        
        // Zwróć współrzędne względem strony
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
     * Odtwarza dźwięk powiadomienia
     */
    playNotificationSound() {
        // Implementacja odtwarzania dźwięku powiadomienia
        // np. nowy element audio odtwarzający plik
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
     * Pokazuje powiadomienie w interfejsie
     */
    showNotification(message, type = 'info') {
        // Utwórz element powiadomienia na podstawie szablonu
        const template = document.getElementById('notification-template');
        if (!template) return;
        
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
        
        // Automatycznie zamknij po 5 sekundach
        setTimeout(() => {
            if (document.body.contains(notification)) {
                notification.classList.add('closing');
                setTimeout(() => notification.remove(), 300);
            }
        }, 5000);
    }
}

// Inicjalizacja interfejsu po załadowaniu dokumentu
document.addEventListener('DOMContentLoaded', () => {
    // Sprawdź, czy użytkownik jest zalogowany
    if (sessionStorage.getItem('isLoggedIn') === 'true' || localStorage.getItem('isLoggedIn') === 'true') {
        // Inicjalizuj interfejs czatu
        window.chatInterface = new ChatInterface(window.sessionManager);
    }
});
       
