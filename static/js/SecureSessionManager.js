/**
 * SecureSessionManager.js
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
            
