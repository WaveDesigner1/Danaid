/**
 * Message.js - Message Data Model
 * Signal-inspired: immutable, validated, secure message handling
 */

class Message {
    constructor(data) {
        this.id = data.id || null;
        this.sessionToken = data.sessionToken || data.session_token;
        this.senderId = data.senderId || data.sender_id;
        this.content = data.content;
        this.iv = data.iv;
        this.timestamp = data.timestamp ? new Date(data.timestamp) : new Date();
        this.isEncrypted = data.isEncrypted !== undefined ? data.isEncrypted : true;
        this.isMine = data.isMine || false;
        this.read = data.read || false;
        
        // Forward secrecy fields
        this.messageNumber = data.messageNumber || data.message_number;
        this.forwardSecrecy = data.forwardSecrecy || data.forward_secrecy || false;
        
        // Metadata
        this.decrypted = data.decrypted || false;
        this.decryptedContent = data.decryptedContent || null;
        this.error = data.error || null;
        
        // Validation
        this.validate();
        
        // Make immutable
        Object.freeze(this);
    }

    // Validation
    validate() {
        if (!this.sessionToken) {
            throw new Error('Message requires session token');
        }
        
        if (!this.senderId) {
            throw new Error('Message requires sender ID');
        }
        
        if (!this.content) {
            throw new Error('Message requires content');
        }
        
        if (this.isEncrypted && !this.iv) {
            throw new Error('Encrypted message requires IV');
        }
    }

    // Create new message with updates (immutable pattern)
    update(changes) {
        return new Message({
            ...this.toJSON(),
            ...changes
        });
    }

    // Mark as decrypted
    markDecrypted(decryptedContent) {
        return this.update({
            decrypted: true,
            decryptedContent: decryptedContent,
            error: null
        });
    }

    // Mark as failed
    markFailed(error) {
        return this.update({
            decrypted: false,
            error: error
        });
    }

    // Mark as read
    markRead() {
        return this.update({
            read: true
        });
    }

    // Get display content
    getDisplayContent() {
        if (this.decryptedContent) {
            return this.decryptedContent;
        }
        
        if (this.error) {
            return `[Decryption failed: ${this.error}]`;
        }
        
        if (!this.decrypted && this.isEncrypted) {
            return '[Encrypted message]';
        }
        
        return this.content;
    }

    // Get display time
    getDisplayTime() {
        return this.timestamp.toLocaleTimeString();
    }

    // Get display date
    getDisplayDate() {
        return this.timestamp.toLocaleDateString();
    }

    // Check if message is from today
    isToday() {
        const today = new Date();
        return this.timestamp.toDateString() === today.toDateString();
    }

    // Get relative time
    getRelativeTime() {
        const now = Date.now();
        const diff = now - this.timestamp.getTime();
        
        if (diff < 60000) return 'now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h`;
        return `${Math.floor(diff / 86400000)}d`;
    }

    // Export for API
    toAPI() {
        return {
            session_token: this.sessionToken,
            content: this.content,
            iv: this.iv,
            message_number: this.messageNumber,
            forward_secrecy: this.forwardSecrecy
        };
    }

    // Export for storage
    toJSON() {
        return {
            id: this.id,
            sessionToken: this.sessionToken,
            senderId: this.senderId,
            content: this.content,
            iv: this.iv,
            timestamp: this.timestamp.toISOString(),
            isEncrypted: this.isEncrypted,
            isMine: this.isMine,
            read: this.read,
            messageNumber: this.messageNumber,
            forwardSecrecy: this.forwardSecrecy,
            decrypted: this.decrypted,
            decryptedContent: this.decryptedContent,
            error: this.error
        };
    }

    // Static factory methods
    static fromAPI(apiData) {
        return new Message({
            id: apiData.id,
            sessionToken: apiData.session_token,
            senderId: apiData.sender_id,
            content: apiData.content,
            iv: apiData.iv,
            timestamp: apiData.timestamp,
            isEncrypted: apiData.is_encrypted,
            isMine: apiData.is_mine,
            read: apiData.read,
            messageNumber: apiData.message_number,
            forwardSecrecy: apiData.forward_secrecy
        });
    }

    static fromSocket(socketData) {
        return new Message({
            id: socketData.id,
            sessionToken: socketData.session_token,
            senderId: socketData.sender_id,
            content: socketData.content,
            iv: socketData.iv,
            timestamp: socketData.timestamp,
            isEncrypted: true,
            isMine: false,
            messageNumber: socketData.message_number,
            forwardSecrecy: socketData.forward_secrecy
        });
    }

    // Create outgoing message
    static createOutgoing(sessionToken, content, senderId) {
        return new Message({
            sessionToken: sessionToken,
            senderId: senderId,
            content: content,
            isEncrypted: true,
            isMine: true,
            timestamp: new Date()
        });
    }
}

// Message collection for managing groups of messages
class MessageCollection {
    constructor() {
        this.messages = new Map();
        this.sessionMessages = new Map();
        this.maxMessages = 1000;
    }

    // Add message
    add(message) {
        if (!(message instanceof Message)) {
            throw new Error('Can only add Message instances');
        }

        this.messages.set(message.id, message);
        
        // Group by session
        if (!this.sessionMessages.has(message.sessionToken)) {
            this.sessionMessages.set(message.sessionToken, []);
        }
        
        const sessionMsgs = this.sessionMessages.get(message.sessionToken);
        
        // Remove existing if updating
        const existingIndex = sessionMsgs.findIndex(m => m.id === message.id);
        if (existingIndex >= 0) {
            sessionMsgs[existingIndex] = message;
        } else {
            sessionMsgs.push(message);
        }
        
        // Sort by timestamp
        sessionMsgs.sort((a, b) => a.timestamp - b.timestamp);
        
        // Limit collection size
        if (sessionMsgs.length > this.maxMessages) {
            const removed = sessionMsgs.splice(0, sessionMsgs.length - this.maxMessages);
            removed.forEach(msg => this.messages.delete(msg.id));
        }
        
        return message;
    }

    // Get message by ID
    get(id) {
        return this.messages.get(id);
    }

    // Get messages for session
    getForSession(sessionToken) {
        return this.sessionMessages.get(sessionToken) || [];
    }

    // Update message
    update(id, changes) {
        const message = this.messages.get(id);
        if (!message) return null;
        
        const updated = message.update(changes);
        return this.add(updated);
    }

    // Remove message
    remove(id) {
        const message = this.messages.get(id);
        if (!message) return false;
        
        this.messages.delete(id);
        
        const sessionMsgs = this.sessionMessages.get(message.sessionToken);
        if (sessionMsgs) {
            const index = sessionMsgs.findIndex(m => m.id === id);
            if (index >= 0) {
                sessionMsgs.splice(index, 1);
            }
        }
        
        return true;
    }

    // Clear session messages
    clearSession(sessionToken) {
        const sessionMsgs = this.sessionMessages.get(sessionToken) || [];
        sessionMsgs.forEach(msg => this.messages.delete(msg.id));
        this.sessionMessages.delete(sessionToken);
    }

    // Get unread count for session
    getUnreadCount(sessionToken) {
        const sessionMsgs = this.sessionMessages.get(sessionToken) || [];
        return sessionMsgs.filter(msg => !msg.read && !msg.isMine).length;
    }

    // Mark session as read
    markSessionRead(sessionToken) {
        const sessionMsgs = this.sessionMessages.get(sessionToken) || [];
        sessionMsgs.forEach(msg => {
            if (!msg.read && !msg.isMine) {
                this.update(msg.id, { read: true });
            }
        });
    }

    // Get stats
    getStats() {
        return {
            totalMessages: this.messages.size,
            sessions: this.sessionMessages.size,
            unreadTotal: Array.from(this.sessionMessages.values())
                .flat()
                .filter(msg => !msg.read && !msg.isMine).length
        };
    }

    // Clear all
    clear() {
        this.messages.clear();
        this.sessionMessages.clear();
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Message, MessageCollection };
} else {
    window.Message = Message;
    window.MessageCollection = MessageCollection;
}