/**
 * chat.js - Modular Chat System Entry Point
 * Signal-inspired: clean, maintainable, production-ready
 */

// Global chat engine instance
let chatEngine = null;

// Initialize chat system
async function initializeChat() {
    try {
        console.log('Initializing modular chat system...');
        
        // Check authentication
        const authResponse = await fetch('/api/check_auth');
        if (!authResponse.ok) {
            window.location.href = '/';
            return;
        }
        
        // Create and initialize chat engine
        chatEngine = new ChatEngine();
        await chatEngine.initialize();
        
        // Expose to window for debugging
        window.chatEngine = chatEngine;
        
        // Legacy compatibility
        setupLegacyCompatibility();
        
        console.log('Chat system initialized successfully');
        
    } catch (error) {
        console.error('Failed to initialize chat system:', error);
        showErrorMessage('Failed to initialize chat system: ' + error.message);
    }
}

// Legacy compatibility layer
function setupLegacyCompatibility() {
    // Expose methods that might be called from templates
    window.chatManager = {
        // Core methods
        sendMessage: () => eventBus.emit(Events.MESSAGE_SEND_REQUESTED),
        getCurrentSession: () => chatEngine.getCurrentSession(),
        getCurrentUser: () => chatEngine.getCurrentUser(),
        
        // Session management
        clearSessionMessages: () => eventBus.emit(Events.SESSION_CLEAR_REQUESTED),
        deleteSession: () => eventBus.emit(Events.SESSION_DELETE_REQUESTED),
        
        // Friends
        addFriend: (username) => eventBus.emit(Events.FRIEND_ADD_REQUESTED, { username }),
        removeFriend: (friendId) => eventBus.emit(Events.FRIEND_REMOVE_REQUESTED, { friendId }),
        
        // UI helpers
        _showFriendRequestsModal: () => showFriendRequestsModal(),
        
        // Debug
        getDebugInfo: () => chatEngine.getDebugInfo(),
        refresh: () => refreshData()
    };
    
    // Crypto manager compatibility
    window.cryptoManager = {
        hasPrivateKey: () => chatEngine.crypto.getStats().hasPrivateKey,
        getForwardSecrecyInfo: () => chatEngine.crypto.getStats(),
        encryptMessage: (key, msg) => chatEngine.crypto.encryptMessage(key, msg),
        decryptMessage: (key, data) => chatEngine.crypto.decryptMessage(key, data),
        generateSessionKey: () => chatEngine.crypto.generateSessionKey(),
        storeSessionKey: (token, key) => chatEngine.crypto.storeSessionKey(token, key),
        getSessionKey: (token) => chatEngine.crypto.getSessionKey(token)
    };
}

// Friend requests modal
function showFriendRequestsModal() {
    // Create or show friend requests modal
    let modal = document.getElementById('friend-requests-modal');
    
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'friend-requests-modal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Friend Requests</h3>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <div id="friend-requests-list">Loading...</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Event listeners
        modal.querySelector('.modal-close').addEventListener('click', () => {
            modal.style.display = 'none';
        });
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    }
    
    modal.style.display = 'block';
    loadFriendRequestsInModal();
}

async function loadFriendRequestsInModal() {
    try {
        const response = await fetch('/api/friend_requests/pending');
        const data = await response.json();
        
        const container = document.getElementById('friend-requests-list');
        if (!container) return;
        
        if (data.status === 'success' && data.requests.length > 0) {
            container.innerHTML = data.requests.map(req => `
                <div class="friend-request-item">
                    <div class="request-info">
                        <strong>${escapeHtml(req.username)}</strong>
                        <small>ID: ${req.sender_id}</small>
                    </div>
                    <div class="request-actions">
                        <button class="btn btn-success" onclick="handleFriendRequest(${req.id}, 'accept')">
                            Accept
                        </button>
                        <button class="btn btn-danger" onclick="handleFriendRequest(${req.id}, 'reject')">
                            Reject
                        </button>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = '<p style="text-align: center;">No pending requests</p>';
        }
        
    } catch (error) {
        console.error('Failed to load friend requests:', error);
    }
}

async function handleFriendRequest(requestId, action) {
    try {
        const response = await fetch(`/api/friend_requests/${requestId}/${action}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            showNotification(`Friend request ${action}ed`, 'success');
            loadFriendRequestsInModal();
            
            if (action === 'accept') {
                // Refresh friends list
                await chatEngine.loadFriends();
                chatEngine.ui.renderFriendsList(
                    chatEngine.friends.getAllFriends(), 
                    chatEngine.getUnreadCounts()
                );
            }
        } else {
            showNotification(data.message || `Failed to ${action} request`, 'error');
        }
        
    } catch (error) {
        console.error(`Error ${action}ing friend request:`, error);
        showNotification(`Error ${action}ing friend request`, 'error');
    }
}

// Utility functions
function showNotification(message, type = 'info', duration = 5000) {
    if (chatEngine && chatEngine.ui) {
        chatEngine.ui.showNotification(message, type, duration);
    } else {
        // Fallback notification
        alert(message);
    }
}

function showErrorMessage(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.innerHTML = `
        <h3>Chat System Error</h3>
        <p>${escapeHtml(message)}</p>
        <button onclick="window.location.reload()">Reload Page</button>
    `;
    errorDiv.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: #f44336;
        color: white;
        padding: 20px;
        border-radius: 5px;
        z-index: 10000;
        text-align: center;
    `;
    
    document.body.appendChild(errorDiv);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function refreshData() {
    if (!chatEngine) return;
    
    try {
        await Promise.all([
            chatEngine.loadFriends(),
            chatEngine.loadSessions(),
            chatEngine.loadFriendRequests()
        ]);
        
        chatEngine.ui.renderFriendsList(
            chatEngine.friends.getAllFriends(), 
            chatEngine.getUnreadCounts()
        );
        
        showNotification('Data refreshed', 'success', 2000);
        
    } catch (error) {
        console.error('Refresh failed:', error);
        showNotification('Failed to refresh data', 'error');
    }
}

// Admin panel check
async function checkAndShowAdminButton() {
    try {
        const response = await fetch('/api/check_admin');
        if (response.ok) {
            const data = await response.json();
            
            if (data.is_admin === true && chatEngine) {
                chatEngine.ui.updateAdminButton(true);
                console.log('Admin panel button shown for:', data.username);
            }
        }
    } catch (error) {
        console.error('Error checking admin privileges:', error);
    }
}

// Test function for forward secrecy
async function testForwardSecrecy() {
    if (!chatEngine) {
        console.error('ChatEngine not initialized');
        return false;
    }
    
    try {
        const sessionKey = await chatEngine.crypto.generateSessionKey();
        const testMessage = "Test Forward Secrecy Message";
        
        const encrypted = await chatEngine.crypto.encryptMessage(sessionKey, testMessage, 'test', true);
        const decrypted = await chatEngine.crypto.decryptMessage(sessionKey, encrypted, 'test');
        
        const success = decrypted === testMessage;
        console.log(success ? 'Forward Secrecy test successful!' : 'Forward Secrecy test failed!');
        return success;
        
    } catch (error) {
        console.error('Forward Secrecy test failed:', error);
        return false;
    }
}

// Logout handler for templates
function handleLogoutClick() {
    eventBus.emit(Events.AUTH_LOGOUT);
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (chatEngine) {
        chatEngine.cleanup();
    }
});

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the chat page
    if (window.location.pathname.includes('/chat')) {
        initializeChat();
        
        // Check admin status after initialization
        setTimeout(checkAndShowAdminButton, 1500);
    }
});

// Export for global access
window.initializeChat = initializeChat;
window.testForwardSecrecy = testForwardSecrecy;
window.checkAndShowAdminButton = checkAndShowAdminButton;
window.handleLogoutClick = handleLogoutClick;

console.log('Modular chat system loaded - Signal-inspired architecture');