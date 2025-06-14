/**
 * EventBus.js - Global Event System
 * Signal-inspired: centralized event management for the entire chat application
 * Updated with complete friend system events
 */

class EventBus {
    constructor() {
        this.listeners = new Map();
        this.debugMode = false;
    }
    
    // Enable/disable debug logging
    setDebugMode(enabled) {
        this.debugMode = enabled;
        console.log(`EventBus debug mode ${enabled ? 'enabled' : 'disabled'}`);
    }
    
    // Subscribe to an event
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }
        this.listeners.get(event).push(callback);
        
        if (this.debugMode) {
            console.log(`EventBus: Subscribed to '${event}' (${this.listeners.get(event).length} listeners)`);
        }
    }
    
    // Subscribe to an event (one-time only)
    once(event, callback) {
        const wrappedCallback = (...args) => {
            callback(...args);
            this.off(event, wrappedCallback);
        };
        this.on(event, wrappedCallback);
    }
    
    // Unsubscribe from an event
    off(event, callback) {
        if (!this.listeners.has(event)) return;
        
        const listeners = this.listeners.get(event);
        const index = listeners.indexOf(callback);
        
        if (index > -1) {
            listeners.splice(index, 1);
            if (this.debugMode) {
                console.log(`EventBus: Unsubscribed from '${event}' (${listeners.length} listeners remaining)`);
            }
        }
        
        // Clean up empty event arrays
        if (listeners.length === 0) {
            this.listeners.delete(event);
        }
    }
    
    // Emit an event
    emit(event, data = null) {
        if (this.debugMode) {
            console.log(`EventBus: Emitting '${event}'`, data);
        }
        
        if (!this.listeners.has(event)) {
            if (this.debugMode) {
                console.warn(`EventBus: No listeners for event '${event}'`);
            }
            return;
        }
        
        const listeners = this.listeners.get(event);
        
        // Call all listeners
        listeners.forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error(`EventBus: Error in listener for '${event}':`, error);
            }
        });
    }
    
    // Get all registered events
    getEvents() {
        return Array.from(this.listeners.keys());
    }
    
    // Get listener count for an event
    getListenerCount(event) {
        return this.listeners.has(event) ? this.listeners.get(event).length : 0;
    }
    
    // Clear all listeners
    clear() {
        this.listeners.clear();
        if (this.debugMode) {
            console.log('EventBus: All listeners cleared');
        }
    }
    
    // Debug info
    getDebugInfo() {
        const info = {};
        for (const [event, listeners] of this.listeners) {
            info[event] = listeners.length;
        }
        return info;
    }
}

// Event Constants - Organized by category
const Events = {
    // ================================================
    // AUTHENTICATION EVENTS
    // ================================================
    AUTH_LOGIN: 'auth.login',
    AUTH_LOGOUT: 'auth.logout',
    AUTH_SESSION_EXPIRED: 'auth.sessionExpired',
    AUTH_USER_LOADED: 'auth.userLoaded',
    
    // ================================================
    // CONNECTION EVENTS
    // ================================================
    CONNECTION_ESTABLISHED: 'connection.established',
    CONNECTION_LOST: 'connection.lost',
    CONNECTION_RECONNECTING: 'connection.reconnecting',
    CONNECTION_RECONNECTED: 'connection.reconnected',
    CONNECTION_ERROR: 'connection.error',
    
    // ================================================
    // FRIEND SYSTEM EVENTS - EXPANDED
    // ================================================
    
    // Friend Requests - Sending
    FRIEND_ADD_REQUESTED: 'friend.addRequested',
    FRIEND_ADD_SUCCESS: 'friend.addSuccess',
    FRIEND_ADD_ERROR: 'friend.addError',
    
    // Friend Requests - Receiving
    FRIEND_REQUEST: 'friend.request',                    // Otrzymano nowe zaproszenie
    FRIEND_REQUEST_RESPONSE: 'friend.requestResponse',   // Odpowiedź na nasze zaproszenie
    FRIEND_REQUEST_COUNT_UPDATED: 'friend.requestCountUpdated',
    
    // Friend Requests - Handling
    FRIEND_REQUEST_ACCEPT: 'friend.requestAccept',
    FRIEND_REQUEST_REJECT: 'friend.requestReject',
    FRIEND_REQUEST_HANDLED: 'friend.requestHandled',
    
    // Friends List Management
    FRIENDS_LOADED: 'friends.loaded',
    FRIENDS_LIST_UPDATED: 'friends.listUpdated',
    FRIEND_ADDED: 'friend.added',                        // Znajomy dodany do listy
    FRIEND_REMOVED: 'friend.removed',                    // Znajomy usunięty z listy
    
    // Friend Removal
    FRIEND_REMOVE_REQUESTED: 'friend.removeRequested',
    FRIEND_REMOVE_SUCCESS: 'friend.removeSuccess',
    FRIEND_REMOVE_ERROR: 'friend.removeError',
    
    // Friend Status Updates
    FRIEND_STATUS_ONLINE: 'friend.statusOnline',
    FRIEND_STATUS_OFFLINE: 'friend.statusOffline',
    FRIEND_STATUS_UPDATED: 'friend.statusUpdated',
    
    // ================================================
    // CHAT SESSION EVENTS
    // ================================================
    SESSION_INIT_REQUESTED: 'session.initRequested',
    SESSION_INIT_SUCCESS: 'session.initSuccess',
    SESSION_INIT_ERROR: 'session.initError',
    SESSION_SWITCHED: 'session.switched',
    SESSION_LOADED: 'session.loaded',
    SESSION_EXPIRED: 'session.expired',
    SESSION_CLEAR_REQUESTED: 'session.clearRequested',
    SESSION_DELETE_REQUESTED: 'session.deleteRequested',
    SESSION_CLEARED: 'session.cleared',
    SESSION_DELETED: 'session.deleted',
    
    // ================================================
    // MESSAGE EVENTS
    // ================================================
    MESSAGE_SEND_REQUESTED: 'message.sendRequested',
    MESSAGE_SEND_SUCCESS: 'message.sendSuccess',
    MESSAGE_SEND_ERROR: 'message.sendError',
    MESSAGE_RECEIVED: 'message.received',
    MESSAGE_READ: 'message.read',
    MESSAGE_TYPING_START: 'message.typingStart',
    MESSAGE_TYPING_STOP: 'message.typingStop',
    
    // ================================================
    // CRYPTO EVENTS
    // ================================================
    CRYPTO_SYSTEM_READY: 'crypto.systemReady',
    CRYPTO_KEY_GENERATED: 'crypto.keyGenerated',
    CRYPTO_KEY_EXCHANGED: 'crypto.keyExchanged',
    CRYPTO_KEY_STORED: 'crypto.keyStored',
    CRYPTO_ENCRYPT_SUCCESS: 'crypto.encryptSuccess',
    CRYPTO_DECRYPT_SUCCESS: 'crypto.decryptSuccess',
    CRYPTO_ERROR: 'crypto.error',
    CRYPTO_CLEARED: 'crypto.cleared',
    
    // ================================================
    // UI EVENTS
    // ================================================
    UI_MODAL_SHOW: 'ui.modalShow',
    UI_MODAL_HIDE: 'ui.modalHide',
    UI_NOTIFICATION_SHOW: 'ui.notificationShow',
    UI_THEME_CHANGED: 'ui.themeChanged',
    UI_SIDEBAR_TOGGLE: 'ui.sidebarToggle',
    
    // ================================================
    // SYSTEM EVENTS
    // ================================================
    SYSTEM_READY: 'system.ready',
    SYSTEM_ERROR: 'system.error',
    SYSTEM_CLEANUP: 'system.cleanup',
    
    // ================================================
    // DATA EVENTS
    // ================================================
    DATA_REFRESH_REQUESTED: 'data.refreshRequested',
    DATA_REFRESH_SUCCESS: 'data.refreshSuccess',
    DATA_REFRESH_ERROR: 'data.refreshError',
    
    // ================================================
    // SOCKET.IO EVENTS
    // ================================================
    SOCKET_CONNECTED: 'socket.connected',
    SOCKET_DISCONNECTED: 'socket.disconnected',
    SOCKET_USER_STATUS: 'socket.userStatus',
    SOCKET_TYPING_STATUS: 'socket.typingStatus',
    
    // ================================================
    // DEBUG EVENTS
    // ================================================
    DEBUG_MODE_ENABLED: 'debug.modeEnabled',
    DEBUG_INFO_REQUESTED: 'debug.infoRequested'
};

// Create global instance
const eventBus = new EventBus();

// Export for ES6 modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { EventBus, Events, eventBus };
}

// Global window access
if (typeof window !== 'undefined') {
    window.EventBus = EventBus;
    window.Events = Events;
    window.eventBus = eventBus;
}

// Development helpers
if (typeof window !== 'undefined') {
    // Debug function
    window.debugEventBus = () => {
        eventBus.setDebugMode(true);
        console.log('EventBus Debug Info:', eventBus.getDebugInfo());
        console.log('Available Events:', Object.keys(Events));
    };
    
    // List all events
    window.listEvents = () => {
        console.log('All Available Events:');
        console.table(Events);
    };
    
    // Monitor specific event
    window.monitorEvent = (eventName) => {
        if (Events[eventName] || Object.values(Events).includes(eventName)) {
            const event = Events[eventName] || eventName;
            eventBus.on(event, (data) => {
                console.log(`🔔 Event '${event}' fired:`, data);
            });
            console.log(`Monitoring event: ${event}`);
        } else {
            console.error(`Event '${eventName}' not found. Use listEvents() to see available events.`);
        }
    };
    
    // Test event system
    window.testEventBus = () => {
        console.log('🧪 Testing EventBus...');
        
        // Test basic functionality
        const testEvent = 'test.event';
        let testPassed = false;
        
        eventBus.on(testEvent, (data) => {
            if (data && data.test === 'success') {
                testPassed = true;
                console.log('✅ EventBus test passed!');
            }
        });
        
        eventBus.emit(testEvent, { test: 'success' });
        
        if (!testPassed) {
            console.error('❌ EventBus test failed!');
        }
        
        // Cleanup
        eventBus.off(testEvent);
        
        return testPassed;
    };
}

// Auto-initialize debug mode in development
if (typeof window !== 'undefined' && window.location.hostname === 'localhost') {
    eventBus.setDebugMode(false); // Set to true for verbose logging
}

console.log('🚌 EventBus loaded with', Object.keys(Events).length, 'event types');

// Log system events for debugging
eventBus.on(Events.SYSTEM_READY, () => {
    console.log('✅ Chat system ready');
});

eventBus.on(Events.SYSTEM_ERROR, (error) => {
    console.error('❌ System error:', error);
});

eventBus.on(Events.CONNECTION_ESTABLISHED, () => {
    console.log('🔗 Connection established');
});

eventBus.on(Events.CONNECTION_LOST, () => {
    console.warn('⚠️ Connection lost');
});