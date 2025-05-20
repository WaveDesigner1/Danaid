from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from models import User, ChatSession, Message, db, Friend, FriendRequest
import datetime
import hashlib
import json
import logging

# Konfiguracja logowania
logger = logging.getLogger(__name__)

chat_api = Blueprint('chat_api', __name__)

@chat_api.route('/api/user/<user_id>/public_key', methods=['GET'])
@login_required
def get_user_public_key(user_id):
    """Pobiera klucz publiczny użytkownika"""
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
        
    return jsonify({
        'status': 'success',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key
    })

@chat_api.route('/api/user/<user_id>/info', methods=['GET'])
@login_required
def get_user_info(user_id):
    """Pobiera podstawowe informacje o użytkowniku"""
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
        
    return jsonify({
        'status': 'success',
        'user': {
            'id': user.id,
            'user_id': user.user_id,
            'username': user.username,
            'is_online': user.is_online if hasattr(user, 'is_online') else False
        }
    })

@chat_api.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Pobiera listę wszystkich użytkowników (poza sobą)"""
    users = User.query.filter(User.id != current_user.id).all()
    
    user_list = [{
        'id': user.id,
        'user_id': user.user_id,
        'username': user.username,
        'is_online': user.is_online if hasattr(user, 'is_online') else False
    } for user in users]
    
    return jsonify({
        'status': 'success',
        'users': user_list
    })

@chat_api.route('/api/online_users', methods=['GET'])
@login_required
def get_online_users():
    """Pobiera listę użytkowników online"""
    try:
        # Sprawdź czy kolumna is_online istnieje w modelu
        if hasattr(User, 'is_online'):
            online_users = User.query.filter(User.is_online == True, User.id != current_user.id).all()
            
            user_list = [{
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username,
            } for user in online_users]
            
            return jsonify({
                'status': 'success',
                'online_users': user_list
            })
        else:
            # Jeśli kolumna nie istnieje, zwróć pustą listę
            return jsonify({
                'status': 'success',
                'online_users': [],
                'message': 'Funkcja statusu online nie jest dostępna'
            })
    except Exception as e:
        logger.error(f"Błąd pobierania użytkowników online: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """Inicjuje nową sesję czatu z innym użytkownikiem"""
    try:
        data = request.get_json()
        
        recipient_id = data.get('recipient_id')
        if not recipient_id:
            return jsonify({'status': 'error', 'message': 'Nie podano ID adresata'}), 400
            
        # Znajdź użytkownika, do którego chcemy pisać
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'status': 'error', 'message': 'Adresat nie istnieje'}), 404
            
        # Sprawdź, czy nie ma już aktywnej sesji między tymi użytkownikami
        existing_session = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient.id)) |
            ((ChatSession.initiator_id == recipient.id) & (ChatSession.recipient_id == current_user.id))
        ).filter(ChatSession.is_active == True, ChatSession.expires_at > datetime.datetime.utcnow()).first()
        
        if existing_session:
            # Zwróć informację czy istnieje już wymieniony klucz
            has_key = existing_session.encrypted_session_key is not None
            key_acknowledged = existing_session.key_acknowledged
            
            # Jeśli istnieje aktywna sesja, odśwież ją
            existing_session.last_activity = datetime.datetime.utcnow()
            existing_session.expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
            db.session.commit()
            
            # Określ drugiego uczestnika sesji
            other_user = recipient if existing_session.initiator_id == current_user.id else User.query.get(existing_session.initiator_id)
            
            return jsonify({
                'status': 'success',
                'message': 'Sesja odświeżona',
                'session': {
                    'id': existing_session.id,
                    'token': existing_session.session_token,
                    'expires_at': existing_session.expires_at.isoformat(),
                    'initiator_id': existing_session.initiator_id,
                    'recipient_id': existing_session.recipient_id,
                    'has_key': has_key,
                    'key_acknowledged': key_acknowledged,
                    'other_user': {
                        'id': other_user.id,
                        'user_id': other_user.user_id,
                        'username': other_user.username,
                        'is_online': other_user.is_online if hasattr(other_user, 'is_online') else False
                    }
                }
            })
        
        # Utwórz nową sesję
        import secrets
        import string
        
        # Generuj token sesji
        session_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        
        new_session = ChatSession(
            session_token=session_token,
            initiator_id=current_user.id,
            recipient_id=recipient.id,
            created_at=datetime.datetime.utcnow(),
            last_activity=datetime.datetime.utcnow(),
            expires_at=expires_at,
            is_active=True
        )
        
        db.session.add(new_session)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja utworzona',
            'session': {
                'id': new_session.id,
                'token': new_session.session_token,
                'expires_at': new_session.expires_at.isoformat(),
                'initiator_id': new_session.initiator_id,
                'recipient_id': new_session.recipient_id,
                'has_key': False,
                'key_acknowledged': False,
                'other_user': {
                    'id': recipient.id,
                    'user_id': recipient.user_id,
                    'username': recipient.username,
                    'is_online': recipient.is_online if hasattr(recipient, 'is_online') else False
                }
            }
        })
    except Exception as e:
        logger.error(f"Błąd inicjacji sesji: {e}")
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

/**

 * Zawiera funkcje obsługi wiadomości, sesji i znajomych
 */

    /**
     * Obsługuje nową wiadomość z WebSocket
     */
    async handleNewMessage(data) {
        try {
            const { session_token, message } = data;
            this.log('Otrzymano nową wiadomość dla sesji:', session_token);
            
            // Pobierz sesję
            const session = this.activeSessions.find(s => s.token === session_token);
            
            if (!session) {
                this.log('Odebrano wiadomość dla nieznanej sesji:', session_token);
                
                // Pobierz sesje na nowo
                await this.fetchActiveSessions();
                return;
            }
            
            // Pobierz klucz sesji
            const sessionKeyBase64 = localStorage.getItem(`session_key_${session_token}`);
            
            if (!sessionKeyBase64) {
                console.error('Brak klucza sesji dla wiadomości');
                return;
            }
            
            // Odszyfruj wiadomość
            try {
                // Importuj klucz sesji
                const sessionKey = await this.importSessionKey(sessionKeyBase64);
                
                // Odszyfruj wiadomość
                const encryptedMessage = {
                    iv: message.iv,
                    encryptedData: message.content
                };
                
                // Sprawdź czy window.chatCrypto jest dostępny
                if (!window.chatCrypto) {
                    console.error('window.chatCrypto nie jest dostępny');
                    return;
                }
                
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
                await this.storeMessage(session_token, newMessage);
                
                // Powiadom o nowej wiadomości
                if (this.onMessageReceived) {
                    this.onMessageReceived(session_token, newMessage);
                }
                
                // Oznacz jako przeczytaną, jeśli to bieżąca sesja
                if (this.currentSessionId === session_token) {
                    this.markMessageAsRead(session_token, newMessage.id);
                    
                    // Wyślij potwierdzenie do serwera
                    this.sendMessageReadReceipt(session_token, newMessage.id);
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
        this.log('Aktualizacja sesji:', session_token);
        
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
        this.log('Zmiana statusu użytkownika:', user_id, is_online);
        
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
        this.log('Nowe zaproszenie do znajomych od:', from_user.username);
        
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
            this.log("Ten przeglądarka nie obsługuje powiadomień");
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
            const response = await fetch(`/api/user/${userId}/public_key`);
            
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
            
            this.log('Pobieranie aktywnych sesji');
            
            const response = await fetch('/api/sessions/active');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.log('Otrzymano aktywne sesje:', data.sessions.length);
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
            
            this.log('Pobieranie znajomych');
            
            const response = await fetch('/api/friends');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.log('Otrzymano znajomych:', data.friends.length);
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
            
            this.log('Pobieranie użytkowników online');
            
            const response = await fetch('/api/online_users');
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.log('Otrzymano użytkowników online:', data.online_users.length);
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
            
            this.log('Wysyłanie zaproszenia do znajomych dla:', username);
            
            const response = await fetch('/api/friend_requests', {
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
                this.log('Zaproszenie wysłane pomyślnie');
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
            
            this.log('Akceptowanie zaproszenia:', requestId);
            
            const response = await fetch(`/api/friend_requests/${requestId}/accept`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
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
 * Zawiera funkcje obsługi wiadomości, sesji i inicjalizacji bazy danych
 */
 
    /**
     * Wysyła wiadomość
     */
    async sendMessage(sessionToken, content, mentions = []) {
    try {
        console.log('Wysyłanie wiadomości dla sesji:', sessionToken);
        
        // 1. Sprawdź czy mamy klucz sesji
        const sessionKeyBase64 = localStorage.getItem(`session_key_${sessionToken}`);
        if (!sessionKeyBase64) {
            throw new Error('Brak klucza sesji w pamięci lokalnej');
        }
        
        // 2. Sprawdź czy window.chatCrypto jest dostępny
        if (!window.chatCrypto) {
            console.error('window.chatCrypto nie jest dostępny');
            
            // Próba inicjalizacji chatCrypto, jeśli nie jest dostępny
            if (typeof ChatCrypto === 'function') {
                window.chatCrypto = new ChatCrypto();
                console.log('Zainicjalizowano ChatCrypto');
            } else {
                throw new Error('Moduł ChatCrypto nie jest dostępny');
            }
        }
        
        // 3. Importuj klucz sesji
        const sessionKey = await this.importSessionKey(sessionKeyBase64);
        
        // 4. Przygotuj dane wiadomości wraz z informacją o wzmiankach
        const messageData = {
            content: content,
            timestamp: new Date().toISOString(),
            sender_id: parseInt(sessionStorage.getItem('user_id')),
            message_id: this.generateUUID(),
            mentions: mentions
        };
        
        // 5. Zaszyfruj dane wiadomości
        const encoder = new TextEncoder();
        const jsonData = JSON.stringify(messageData);
        const messageBytes = encoder.encode(jsonData);
        
        // 6. Generuj wektor inicjalizacyjny
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // 7. Szyfruj
        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            messageBytes
        );
        
        console.log('Wiadomość zaszyfrowana, wysyłanie do serwera');
        
        // 8. Wyślij zaszyfrowaną wiadomość
        const response = await fetch('/api/message/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_token: sessionToken,
                content: this.arrayBufferToBase64(encryptedMessage),
                iv: this.arrayBufferToBase64(iv),
                mentions: mentions // Dodajemy informację o wzmiankach, które nie są szyfrowane
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status !== 'success') {
            throw new Error(data.message || 'Błąd wysyłania wiadomości');
        }
        
        console.log('Wiadomość wysłana pomyślnie');
        
        // 9. Zapisz wiadomość lokalnie
        if (!this.messages[sessionToken]) {
            this.messages[sessionToken] = [];
        }
        
        const newMessage = {
            id: data.message.id || messageData.message_id,
            sender_id: parseInt(sessionStorage.getItem('user_id')),
            content: content,
            timestamp: messageData.timestamp,
            mentions: mentions
        };
        
        this.messages[sessionToken].push(newMessage);
        
        // 10. Zapisz do lokalnego magazynu
        await this.storeMessage(sessionToken, newMessage);
        
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
 * Importuje klucz sesji z formatu Base64
 */
async importSessionKey(base64Key) {
    try {
        const rawKey = this.base64ToArrayBuffer(base64Key);
        return await window.crypto.subtle.importKey(
            "raw",
            rawKey,
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    } catch (error) {
        console.error('Błąd importowania klucza sesji:', error);
        throw new Error('Nie można zaimportować klucza sesji');
    }
}

/**
 * Generuje unikalny identyfikator UUID v4
 */
generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * Konwertuje ArrayBuffer na Base64
 */
arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Konwertuje Base64 na ArrayBuffer
 */
base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Zapisuje wiadomość w lokalnej bazie danych
 */
async storeMessage(sessionToken, message) {
    try {
        const db = await this._openDatabase();
        const tx = db.transaction('messages', 'readwrite');
        const store = tx.objectStore('messages');
        
        // Pobierz istniejące wiadomości
        let sessionMessages = await store.get(sessionToken);
        
        if (!sessionMessages) {
            sessionMessages = {
                sessionToken: sessionToken,
                messages: [],
                lastUpdated: new Date().toISOString()
            };
        }
        
        // Dodaj nową wiadomość
        sessionMessages.messages.push(message);
        sessionMessages.lastUpdated = new Date().toISOString();
        
        // Zapisz z powrotem do bazy
        await store.put(sessionMessages);
        
        return true;
    } catch (error) {
        console.error('Błąd zapisywania wiadomości:', error);
        return false;
    }
}

/**
 * Otwiera połączenie z IndexedDB
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
    
    /**
     * Oznacza wiadomość jako przeczytaną
     */
    async markMessageAsRead(sessionToken, messageId) {
        try {
            this.log('Oznaczanie wiadomości jako przeczytana:', messageId);
            
            const response = await fetch('/api/message/read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_token: sessionToken,
                    message_id: messageId
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }
            
            return true;
        } catch (error) {
            console.error('Błąd oznaczania wiadomości jako przeczytana:', error);
            return false;
        }
    }
    
    /**
     * Wysyła potwierdzenie przeczytania wiadomości
     */
    sendMessageReadReceipt(sessionToken, messageId) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.sendToSocket({
                type: 'read_receipt',
                session_token: sessionToken,
                message_id: messageId
            });
            return true;
        }
        return false;
    }
    
    /**
     * Importuje klucz sesji z formatu Base64
     */
    async importSessionKey(base64Key) {
        try {
            const rawKey = this.base64ToArrayBuffer(base64Key);
            return await window.crypto.subtle.importKey(
                "raw",
                rawKey,
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );
        } catch (error) {
            console.error('Błąd importowania klucza sesji:', error);
            throw new Error('Nie można zaimportować klucza sesji');
        }
    }
    
    /**
     * Generuje unikalny identyfikator UUID v4
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    
    /**
     * Konwertuje ArrayBuffer na Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    /**
     * Konwertuje Base64 na ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    /**
     * Zapisuje wiadomość w lokalnej bazie danych
     */
    async storeMessage(sessionToken, message) {
        try {
            const db = await this._openDatabase();
            const tx = db.transaction('messages', 'readwrite');
            const store = tx.objectStore('messages');
            
            // Pobierz istniejące wiadomości
            let sessionMessages = await store.get(sessionToken);
            
            if (!sessionMessages) {
                sessionMessages = {
                    sessionToken: sessionToken,
                    messages: [],
                    lastUpdated: new Date().toISOString()
                };
            }
            
            // Dodaj nową wiadomość
            sessionMessages.messages.push(message);
            sessionMessages.lastUpdated = new Date().toISOString();
            
            // Zapisz z powrotem do bazy
            await store.put(sessionMessages);
            
            return true;
        } catch (error) {
            console.error('Błąd zapisywania wiadomości:', error);
            return false;
        }
    }
    
    /**
     * Ładuje wiadomości z lokalnej bazy danych
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
            
            this.log('Wiadomości załadowane z lokalnego magazynu');
            return true;
            
        } catch (error) {
            console.error('Błąd podczas ładowania wiadomości:', error);
            return false;
        }
    }
    
    /**
     * Inicjalizuje bazę danych
     */
    async initializeDatabase() {
        try {
            const db = await this._openDatabase();
            this.log('Baza danych zainicjalizowana pomyślnie');
            return true;
        } catch (error) {
            console.error('Błąd inicjalizacji bazy danych:', error);
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
    
    /**
     * Ładuje stan z localStorage
     */
    loadState() {
        try {
            const stateJson = localStorage.getItem('chat_user_state');
            if (stateJson) {
                const state = JSON.parse(stateJson);
                
                if (state.user) this.user = state.user;
                if (state.friends) this.friends = state.friends;
                if (state.activeSessions) this.activeSessions = state.activeSessions;
            }
        } catch (error) {
            console.error('Błąd ładowania stanu:', error);
        }
    }
    
    /**
     * Zapisuje stan do localStorage
     */
    saveState() {
        try {
            const state = {
                user: this.user,
                friends: this.friends,
                activeSessions: this.activeSessions
            };
            
            localStorage.setItem('chat_user_state', JSON.stringify(state));
        } catch (error) {
            console.error('Błąd zapisywania stanu:', error);
        }
    }
}

// Inicjalizacja menedżera sesji czatu
window.sessionManager = new SecureSessionManager();

// Automatyczne zapisywanie wiadomości co 5 minut
setInterval(() => {
    if (window.sessionManager && typeof window.sessionManager.saveMessagesToStorage === 'function') {
        window.sessionManager.saveMessagesToStorage();
    }
}, 5 * 60 * 1000);
