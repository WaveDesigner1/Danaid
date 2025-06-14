/**
 * UIManager.js - User Interface Management
 * Signal-inspired: handles all UI updates and interactions
 * Complete with real-time friend system updates
 */

class UIManager {
    constructor() {
        this.currentTheme = 'dark';
        this.notificationTimeout = null;
        this.typingTimeouts = new Map();
        this.activeModal = null;
        
        // Cache DOM elements
        this.elements = {};
        this.cacheElements();
        
        // Initialize UI state
        this.initializeUI();
    }

    // ================================================
    // INITIALIZATION
    // ================================================

    // Cache frequently used DOM elements
    cacheElements() {
        this.elements = {
            // Main containers
            friendList: document.getElementById('friend-list'),
            messagesContainer: document.getElementById('messages'),
            messageInput: document.getElementById('message-input'),
            sendButton: document.getElementById('send-button'),
            
            // Header elements
            chatHeader: document.getElementById('chat-header'),
            connectionStatus: document.getElementById('connection-status'),
            username: document.getElementById('username'),
            
            // Friend system elements
            addFriendBtn: document.getElementById('add-friend-btn'),
            friendRequestCount: document.getElementById('friend-request-count'),
            friendRequestsSection: document.querySelector('.friend-requests'),
            
            // Buttons
            logoutBtn: document.getElementById('logout-btn'),
            adminPanelBtn: document.getElementById('admin-panel-btn'),
            
            // Typing indicator
            typingIndicator: document.getElementById('typing-indicator'),
            
            // Notifications container
            notificationsContainer: document.getElementById('notifications-container')
        };
    }

    // Initialize UI components
    initializeUI() {
        // Create notifications container if it doesn't exist
        if (!this.elements.notificationsContainer) {
            this.createNotificationsContainer();
        }
        
        // Set initial states
        this.updateConnectionStatus(false);
        this.hideTypingIndicator();
        
        console.log('✅ UIManager initialized');
    }

    // Create notifications container
    createNotificationsContainer() {
        const container = document.createElement('div');
        container.id = 'notifications-container';
        container.className = 'notifications-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            pointer-events: none;
        `;
        
        document.body.appendChild(container);
        this.elements.notificationsContainer = container;
    }

    // ================================================
    // FRIEND SYSTEM UI - EXPANDED
    // ================================================

    // Update friend request count badge
    updateFriendRequestCount(count) {
        const badge = this.elements.friendRequestCount;
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'inline-block' : 'none';
            
            // Add animation for new requests
            if (count > 0) {
                badge.classList.add('pulse-animation');
                setTimeout(() => {
                    badge.classList.remove('pulse-animation');
                }, 1000);
            }
        }
        
        console.log(`👥 Friend request count updated: ${count}`);
    }

    // Render friends list with unread counts and online status
    renderFriendsList(friends, unreadCounts = {}) {
        const friendList = this.elements.friendList;
        if (!friendList) return;
        
        if (friends.length === 0) {
            friendList.innerHTML = `
                <li class="no-friends">
                    <div class="no-friends-message">
                        <i class="fas fa-user-friends"></i>
                        <p>Brak znajomych</p>
                        <small>Dodaj pierwszego znajomego!</small>
                    </div>
                </li>
            `;
            return;
        }
        
        friendList.innerHTML = friends.map(friend => {
            const unreadCount = unreadCounts[friend.user_id] || 0;
            const onlineClass = friend.is_online ? 'online' : 'offline';
            const unreadBadge = unreadCount > 0 ? 
                `<span class="unread-count">${unreadCount > 99 ? '99+' : unreadCount}</span>` : '';
            
            return `
                <li class="friend-item ${onlineClass}" 
                    data-user-id="${friend.user_id}" 
                    data-friend-id="${friend.id}">
                    <div class="friend-avatar">
                        <div class="avatar-circle">
                            ${friend.username.charAt(0).toUpperCase()}
                        </div>
                        <div class="status-indicator ${onlineClass}"></div>
                    </div>
                    <div class="friend-info">
                        <div class="friend-name">${this.escapeHtml(friend.username)}</div>
                        <div class="friend-status">
                            ${friend.is_online ? 'Online' : 'Offline'}
                        </div>
                    </div>
                    <div class="friend-actions">
                        ${unreadBadge}
                        <button class="friend-chat-btn" title="Rozpocznij rozmowę">
                            <i class="fas fa-comment"></i>
                        </button>
                        <button class="friend-remove-btn" title="Usuń znajomego">
                            <i class="fas fa-user-minus"></i>
                        </button>
                    </div>
                </li>
            `;
        }).join('');
        
        // Add event listeners
        this.attachFriendListeners();
        
        console.log(`👥 Rendered ${friends.length} friends`);
    }

    // Attach event listeners to friend list items
    attachFriendListeners() {
        const friendList = this.elements.friendList;
        if (!friendList) return;
        
        // Friend item click (start chat)
        friendList.querySelectorAll('.friend-item').forEach(item => {
            item.addEventListener('click', (e) => {
                // Don't trigger if clicking on action buttons
                if (e.target.closest('.friend-actions')) return;
                
                const userId = item.dataset.userId;
                eventBus.emit(Events.SESSION_INIT_REQUESTED, { friendId: userId });
            });
        });
        
        // Chat buttons
        friendList.querySelectorAll('.friend-chat-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const userId = btn.closest('.friend-item').dataset.userId;
                eventBus.emit(Events.SESSION_INIT_REQUESTED, { friendId: userId });
            });
        });
        
        // Remove buttons
        friendList.querySelectorAll('.friend-remove-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const friendId = btn.closest('.friend-item').dataset.friendId;
                const friendName = btn.closest('.friend-item').querySelector('.friend-name').textContent;
                
                if (confirm(`Czy na pewno chcesz usunąć ${friendName} z znajomych?`)) {
                    eventBus.emit(Events.FRIEND_REMOVE_REQUESTED, { friendId: parseInt(friendId) });
                }
            });
        });
    }

    // Update specific friend status (online/offline)
    updateFriendStatus(userId, isOnline) {
        const friendItem = document.querySelector(`[data-user-id="${userId}"]`);
        if (friendItem) {
            const statusIndicator = friendItem.querySelector('.status-indicator');
            const statusText = friendItem.querySelector('.friend-status');
            
            if (statusIndicator) {
                statusIndicator.className = `status-indicator ${isOnline ? 'online' : 'offline'}`;
            }
            
            if (statusText) {
                statusText.textContent = isOnline ? 'Online' : 'Offline';
            }
            
            friendItem.className = `friend-item ${isOnline ? 'online' : 'offline'}`;
        }
    }

    // Update unread count for specific friend
    updateUnreadCount(userId, count) {
        const friendItem = document.querySelector(`[data-user-id="${userId}"]`);
        if (friendItem) {
            let badge = friendItem.querySelector('.unread-count');
            
            if (count > 0) {
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'unread-count';
                    friendItem.querySelector('.friend-actions').prepend(badge);
                }
                badge.textContent = count > 99 ? '99+' : count;
                badge.style.display = 'inline-block';
            } else if (badge) {
                badge.remove();
            }
        }
    }

    // Highlight active session in friends list
    highlightActiveSession(userId) {
        // Remove previous active states
        document.querySelectorAll('.friend-item.active').forEach(item => {
            item.classList.remove('active');
        });
        
        // Add active state to current friend
        const friendItem = document.querySelector(`[data-user-id="${userId}"]`);
        if (friendItem) {
            friendItem.classList.add('active');
        }
    }

    // Show add friend modal
    showAddFriendModal() {
        this.hideActiveModal();
        
        const modal = document.createElement('div');
        modal.className = 'modal add-friend-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fas fa-user-plus"></i> Dodaj znajomego</h3>
                    <button class="modal-close" data-action="close">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="friend-username">Nazwa użytkownika lub ID:</label>
                        <input type="text" id="friend-username" class="form-input" 
                               placeholder="Wpisz nazwę użytkownika..." autocomplete="off">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" data-action="close">
                            Anuluj
                        </button>
                        <button type="button" class="btn btn-primary" data-action="add">
                            <i class="fas fa-user-plus"></i> Wyślij zaproszenie
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        this.activeModal = modal;
        
        // Event listeners
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.dataset.action === 'close') {
                this.hideActiveModal();
            } else if (e.target.dataset.action === 'add') {
                this.handleAddFriend();
            }
        });
        
        // Focus input and handle Enter key
        const input = modal.querySelector('#friend-username');
        input.focus();
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.handleAddFriend();
            }
        });
        
        // Show modal
        setTimeout(() => modal.classList.add('show'), 10);
    }

    // Handle add friend from modal
    handleAddFriend() {
        const input = document.getElementById('friend-username');
        if (!input) return;
        
        const username = input.value.trim();
        if (!username) {
            this.showNotification('Wprowadź nazwę użytkownika', 'warning');
            input.focus();
            return;
        }
        
        // Emit event
        eventBus.emit(Events.FRIEND_ADD_REQUESTED, { username });
        
        // Close modal
        this.hideActiveModal();
    }

    // ================================================
    // CHAT UI MANAGEMENT
    // ================================================

    // Update chat header with current conversation partner
    updateChatHeader(otherUser) {
        const chatHeader = this.elements.chatHeader;
        if (!chatHeader) return;
        
        if (otherUser) {
            const onlineStatus = otherUser.is_online ? 'online' : 'offline';
            chatHeader.innerHTML = `
                <div class="chat-partner-info">
                    <div class="partner-avatar">
                        <div class="avatar-circle">
                            ${otherUser.username.charAt(0).toUpperCase()}
                        </div>
                        <div class="status-indicator ${onlineStatus}"></div>
                    </div>
                    <div class="partner-details">
                        <h2>${this.escapeHtml(otherUser.username)}</h2>
                        <span class="chat-status ${onlineStatus}">
                            ${otherUser.is_online ? 'Online' : 'Offline'}
                        </span>
                    </div>
                </div>
                <div class="chat-actions">
                    <button class="chat-action-btn" data-action="clear" title="Wyczyść rozmowę">
                        <i class="fas fa-broom"></i>
                    </button>
                    <button class="chat-action-btn" data-action="delete" title="Usuń sesję">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `;
            
            // Add action listeners
            chatHeader.querySelectorAll('.chat-action-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const action = btn.dataset.action;
                    if (action === 'clear') {
                        if (confirm('Czy na pewno chcesz wyczyścić tę rozmowę?')) {
                            eventBus.emit(Events.SESSION_CLEAR_REQUESTED);
                        }
                    } else if (action === 'delete') {
                        if (confirm('Czy na pewno chcesz trwale usunąć tę sesję?')) {
                            eventBus.emit(Events.SESSION_DELETE_REQUESTED);
                        }
                    }
                });
            });
            
        } else {
            chatHeader.innerHTML = `
                <div class="chat-partner-info">
                    <h2>Wybierz rozmowę</h2>
                    <span class="chat-status">Wybierz znajomego, aby rozpocząć rozmowę</span>
                </div>
            `;
        }
    }

    // Render messages in chat area
    renderMessages(messages) {
        const container = this.elements.messagesContainer;
        if (!container) return;
        
        if (messages.length === 0) {
            container.innerHTML = `
                <div class="no-messages">
                    <i class="fas fa-comments"></i>
                    <p>Brak wiadomości</p>
                    <small>Rozpocznij rozmowę!</small>
                </div>
            `;
            return;
        }
        
        container.innerHTML = messages.map(msg => this.renderMessage(msg)).join('');
        this.scrollToBottom();
    }

    // Add single message to chat
    addMessage(message) {
        const container = this.elements.messagesContainer;
        if (!container) return;
        
        // Remove no-messages placeholder if exists
        const noMessages = container.querySelector('.no-messages');
        if (noMessages) {
            noMessages.remove();
        }
        
        // Add message
        const messageHtml = this.renderMessage(message);
        container.insertAdjacentHTML('beforeend', messageHtml);
        
        // Scroll to bottom
        this.scrollToBottom();
    }

    // Render single message
    renderMessage(message) {
        const timestamp = this.formatTimestamp(message.timestamp);
        const messageClass = message.is_mine ? 'message-mine' : 'message-other';
        
        return `
            <div class="message ${messageClass}" data-message-id="${message.id}">
                <div class="message-content">
                    <div class="message-text">${this.escapeHtml(message.content)}</div>
                    <div class="message-time">${timestamp}</div>
                </div>
            </div>
        `;
    }

    // Clear all messages
    clearMessages() {
        const container = this.elements.messagesContainer;
        if (container) {
            container.innerHTML = `
                <div class="no-messages">
                    <i class="fas fa-comments"></i>
                    <p>Rozmowa wyczyszczona</p>
                </div>
            `;
        }
    }

    // Scroll messages to bottom
    scrollToBottom() {
        const container = this.elements.messagesContainer;
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    }

    // ================================================
    // TYPING INDICATORS
    // ================================================

    // Show typing indicator
    showTypingIndicator(username) {
        const indicator = this.elements.typingIndicator;
        if (indicator) {
            indicator.innerHTML = `
                <div class="typing-content">
                    <span class="typing-text">${this.escapeHtml(username)} pisze...</span>
                    <div class="typing-dots">
                        <span></span><span></span><span></span>
                    </div>
                </div>
            `;
            indicator.style.display = 'block';
        }
    }

    // Hide typing indicator
    hideTypingIndicator() {
        const indicator = this.elements.typingIndicator;
        if (indicator) {
            indicator.style.display = 'none';
        }
    }

    // ================================================
    // CONNECTION STATUS
    // ================================================

    // Update connection status indicator
    updateConnectionStatus(isConnected) {
        const status = this.elements.connectionStatus;
        if (status) {
            if (isConnected) {
                status.className = 'connection-status connected';
                status.innerHTML = '<i class="fas fa-wifi"></i> Połączony';
            } else {
                status.className = 'connection-status disconnected';
                status.innerHTML = '<i class="fas fa-wifi"></i> Łączenie...';
            }
        }
    }

    // ================================================
    // USER INFO
    // ================================================

    // Update user information display
    updateUserInfo(user) {
        const usernameElement = this.elements.username;
        if (usernameElement && user) {
            usernameElement.textContent = user.username;
        }
    }

    // Update admin panel button visibility
    updateAdminButton(isAdmin) {
        const adminBtn = this.elements.adminPanelBtn;
        if (adminBtn) {
            adminBtn.style.display = isAdmin ? 'inline-block' : 'none';
        }
    }

    // ================================================
    // NOTIFICATIONS
    // ================================================

    // Show notification toast
    showNotification(message, type = 'info', duration = 5000) {
        const container = this.elements.notificationsContainer;
        if (!container) return;
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            background: var(--bg-color, #333);
            color: var(--text-color, #fff);
            padding: 12px 16px;
            margin-bottom: 10px;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            pointer-events: auto;
            cursor: pointer;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            max-width: 300px;
            word-wrap: break-word;
        `;
        
        // Set background color based on type
        const colors = {
            success: '#4CAF50',
            error: '#f44336',
            warning: '#ff9800',
            info: '#2196F3'
        };
        notification.style.background = colors[type] || colors.info;
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${this.escapeHtml(message)}</span>
                <button style="background: none; border: none; color: inherit; margin-left: auto; cursor: pointer;">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        container.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        }, 10);
        
        // Auto remove
        const removeNotification = () => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        };
        
        // Click to close
        notification.addEventListener('click', removeNotification);
        
        // Auto close
        if (duration > 0) {
            setTimeout(removeNotification, duration);
        }
        
        console.log(`📢 Notification: ${message} (${type})`);
    }

    // Get notification icon based on type
    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || icons.info;
    }

    // ================================================
    // MODAL MANAGEMENT
    // ================================================

    // Hide currently active modal
    hideActiveModal() {
        if (this.activeModal) {
            this.activeModal.classList.add('hiding');
            setTimeout(() => {
                if (this.activeModal && this.activeModal.parentNode) {
                    this.activeModal.parentNode.removeChild(this.activeModal);
                }
                this.activeModal = null;
            }, 300);
        }
    }

    // ================================================
    // UTILITY METHODS
    // ================================================

    // Escape HTML to prevent XSS
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Format timestamp for messages
    formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffMins < 1) return 'teraz';
        if (diffMins < 60) return `${diffMins}m temu`;
        if (diffHours < 24) return `${diffHours}h temu`;
        if (diffDays < 7) return `${diffDays}d temu`;
        
        return date.toLocaleDateString('pl-PL', {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    // ================================================
    // CLEANUP
    // ================================================

    // Cleanup UI resources
    cleanup() {
        // Clear timeouts
        if (this.notificationTimeout) {
            clearTimeout(this.notificationTimeout);
        }
        
        // Clear typing timeouts
        this.typingTimeouts.clear();
        
        // Hide active modal
        this.hideActiveModal();
        
        // Clear notifications
        if (this.elements.notificationsContainer) {
            this.elements.notificationsContainer.innerHTML = '';
        }
        
        console.log('🧹 UIManager cleanup completed');
    }
}

// Export for global use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UIManager;
} else {
    window.UIManager = UIManager;
}

console.log('🎨 UIManager loaded with complete friend system support');