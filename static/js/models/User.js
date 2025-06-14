/**
 * User.js & Session.js - Core Data Models
 * Signal-inspired: validated, immutable user and session management
 */

// USER MODEL
class User {
    constructor(data) {
        this.id = data.id;
        this.userId = data.userId || data.user_id;
        this.username = data.username;
        this.isOnline = data.isOnline || data.is_online || false;
        this.isAdmin = data.isAdmin || data.is_admin || false;
        this.lastActive = data.lastActive ? new Date(data.lastActive) : null;
        this.publicKey = data.publicKey || data.public_key;
        
        this.validate();
        Object.freeze(this);
    }

    validate() {
        if (!this.id || !this.userId || !this.username) {
            throw new Error('User requires id, userId, and username');
        }
    }

    update(changes) {
        return new User({
            ...this.toJSON(),
            ...changes
        });
    }

    getDisplayName() {
        return this.username;
    }

    getInitial() {
        return this.username.charAt(0).toUpperCase();
    }

    getStatusText() {
        return this.isOnline ? 'Online' : 'Offline';
    }

    getStatusClass() {
        return this.isOnline ? 'online' : 'offline';
    }

    toJSON() {
        return {
            id: this.id,
            userId: this.userId,
            username: this.username,
            isOnline: this.isOnline,
            isAdmin: this.isAdmin,
            lastActive: this.lastActive ? this.lastActive.toISOString() : null,
            publicKey: this.publicKey
        };
    }

    static fromAPI(apiData) {
        return new User({
            id: apiData.id,
            userId: apiData.user_id,
            username: apiData.username,
            isOnline: apiData.is_online,
            isAdmin: apiData.is_admin,
            lastActive: apiData.last_active,
            publicKey: apiData.public_key
        });
    }
}

// SESSION MODEL
class Session {
    constructor(data) {
        this.id = data.id;
        this.token = data.token || data.session_token;
        this.initiatorId = data.initiatorId || data.initiator_id;
        this.recipientId = data.recipientId || data.recipient_id;
        this.createdAt = data.createdAt ? new Date(data.createdAt) : new Date();
        this.lastActivity = data.lastActivity ? new Date(data.lastActivity) : new Date();
        this.expiresAt = data.expiresAt ? new Date(data.expiresAt) : null;
        this.isActive = data.isActive !== undefined ? data.isActive : true;
        this.hasKey = data.hasKey || false;
        this.otherUser = data.otherUser ? new User(data.otherUser) : null;
        
        // Key management
        this.keyGenerated = data.keyGenerated || false;
        this.keyExchanged = data.keyExchanged || false;
        this.dualEncryption = data.dualEncryption || false;
        
        this.validate();
        Object.freeze(this);
    }

    validate() {
        if (!this.token || !this.initiatorId || !this.recipientId) {
            throw new Error('Session requires token, initiatorId, and recipientId');
        }
    }

    update(changes) {
        return new Session({
            ...this.toJSON(),
            ...changes
        });
    }

    isExpired() {
        if (!this.expiresAt) return false;
        return new Date() > this.expiresAt;
    }

    getOtherUserId(currentUserId) {
        return this.initiatorId === currentUserId ? this.recipientId : this.initiatorId;
    }

    getDisplayName() {
        return this.otherUser ? this.otherUser.getDisplayName() : 'Unknown User';
    }

    getLastActivityText() {
        if (!this.lastActivity) return 'Never';
        
        const now = new Date();
        const diff = now - this.lastActivity;
        
        if (diff < 60000) return 'Now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        return this.lastActivity.toLocaleDateString();
    }

    isReadyForMessaging() {
        return this.isActive && !this.isExpired() && this.hasKey;
    }

    toJSON() {
        return {
            id: this.id,
            token: this.token,
            initiatorId: this.initiatorId,
            recipientId: this.recipientId,
            createdAt: this.createdAt.toISOString(),
            lastActivity: this.lastActivity.toISOString(),
            expiresAt: this.expiresAt ? this.expiresAt.toISOString() : null,
            isActive: this.isActive,
            hasKey: this.hasKey,
            otherUser: this.otherUser ? this.otherUser.toJSON() : null,
            keyGenerated: this.keyGenerated,
            keyExchanged: this.keyExchanged,
            dualEncryption: this.dualEncryption
        };
    }

    static fromAPI(apiData) {
        return new Session({
            id: apiData.id,
            token: apiData.token || apiData.session_token,
            initiatorId: apiData.initiator_id,
            recipientId: apiData.recipient_id,
            createdAt: apiData.created_at,
            lastActivity: apiData.last_activity,
            expiresAt: apiData.expires_at,
            isActive: apiData.is_active,
            hasKey: apiData.has_key,
            otherUser: apiData.other_user,
            keyGenerated: apiData.key_generated,
            keyExchanged: apiData.key_exchanged,
            dualEncryption: apiData.dual_encryption
        });
    }
}

// FRIEND MODEL
class Friend {
    constructor(data) {
        this.id = data.id;
        this.userId = data.userId || data.user_id;
        this.username = data.username;
        this.isOnline = data.isOnline || data.is_online || false;
        this.createdAt = data.createdAt ? new Date(data.createdAt) : new Date();
        
        this.validate();
        Object.freeze(this);
    }

    validate() {
        if (!this.id || !this.userId || !this.username) {
            throw new Error('Friend requires id, userId, and username');
        }
    }

    update(changes) {
        return new Friend({
            ...this.toJSON(),
            ...changes
        });
    }

    getDisplayName() {
        return this.username;
    }

    getInitial() {
        return this.username.charAt(0).toUpperCase();
    }

    getStatusText() {
        return this.isOnline ? 'Online' : 'Offline';
    }

    getStatusClass() {
        return this.isOnline ? 'online' : 'offline';
    }

    toJSON() {
        return {
            id: this.id,
            userId: this.userId,
            username: this.username,
            isOnline: this.isOnline,
            createdAt: this.createdAt.toISOString()
        };
    }

    static fromAPI(apiData) {
        return new Friend({
            id: apiData.id,
            userId: apiData.user_id,
            username: apiData.username,
            isOnline: apiData.is_online,
            createdAt: apiData.created_at
        });
    }
}

// FRIEND REQUEST MODEL
class FriendRequest {
    constructor(data) {
        this.id = data.id;
        this.senderId = data.senderId || data.sender_id;
        this.username = data.username;
        this.status = data.status || 'pending';
        this.createdAt = data.createdAt ? new Date(data.createdAt) : new Date();
        
        this.validate();
        Object.freeze(this);
    }

    validate() {
        if (!this.id || !this.senderId || !this.username) {
            throw new Error('FriendRequest requires id, senderId, and username');
        }
    }

    update(changes) {
        return new FriendRequest({
            ...this.toJSON(),
            ...changes
        });
    }

    isPending() {
        return this.status === 'pending';
    }

    isAccepted() {
        return this.status === 'accepted';
    }

    isRejected() {
        return this.status === 'rejected';
    }

    getDisplayTime() {
        return this.createdAt.toLocaleDateString();
    }

    toJSON() {
        return {
            id: this.id,
            senderId: this.senderId,
            username: this.username,
            status: this.status,
            createdAt: this.createdAt.toISOString()
        };
    }

    static fromAPI(apiData) {
        return new FriendRequest({
            id: apiData.id,
            senderId: apiData.sender_id,
            username: apiData.username,
            status: apiData.status,
            createdAt: apiData.created_at
        });
    }
}

// COLLECTIONS FOR MANAGING DATA
class UserCollection {
    constructor() {
        this.users = new Map();
        this.currentUser = null;
    }

    setCurrentUser(user) {
        this.currentUser = user instanceof User ? user : new User(user);
        this.users.set(this.currentUser.id, this.currentUser);
    }

    getCurrentUser() {
        return this.currentUser;
    }

    add(user) {
        const userObj = user instanceof User ? user : new User(user);
        this.users.set(userObj.id, userObj);
        return userObj;
    }

    get(id) {
        return this.users.get(id);
    }

    update(id, changes) {
        const user = this.users.get(id);
        if (!user) return null;
        
        const updated = user.update(changes);
        this.users.set(id, updated);
        
        if (this.currentUser && this.currentUser.id === id) {
            this.currentUser = updated;
        }
        
        return updated;
    }

    getAll() {
        return Array.from(this.users.values());
    }

    clear() {
        this.users.clear();
        this.currentUser = null;
    }
}

class SessionCollection {
    constructor() {
        this.sessions = new Map();
        this.currentSession = null;
    }

    setCurrentSession(session) {
        this.currentSession = session instanceof Session ? session : new Session(session);
        this.sessions.set(this.currentSession.token, this.currentSession);
    }

    getCurrentSession() {
        return this.currentSession;
    }

    add(session) {
        const sessionObj = session instanceof Session ? session : new Session(session);
        this.sessions.set(sessionObj.token, sessionObj);
        return sessionObj;
    }

    get(token) {
        return this.sessions.get(token);
    }

    update(token, changes) {
        const session = this.sessions.get(token);
        if (!session) return null;
        
        const updated = session.update(changes);
        this.sessions.set(token, updated);
        
        if (this.currentSession && this.currentSession.token === token) {
            this.currentSession = updated;
        }
        
        return updated;
    }

    getActive() {
        return Array.from(this.sessions.values()).filter(s => s.isActive && !s.isExpired());
    }

    getForUser(userId, currentUserId) {
        return Array.from(this.sessions.values()).find(s => 
            s.getOtherUserId(currentUserId) === userId && s.isActive
        );
    }

    remove(token) {
        const session = this.sessions.get(token);
        if (!session) return false;
        
        this.sessions.delete(token);
        
        if (this.currentSession && this.currentSession.token === token) {
            this.currentSession = null;
        }
        
        return true;
    }

    clear() {
        this.sessions.clear();
        this.currentSession = null;
    }
}

class FriendCollection {
    constructor() {
        this.friends = new Map();
        this.requests = new Map();
    }

    addFriend(friend) {
        const friendObj = friend instanceof Friend ? friend : new Friend(friend);
        this.friends.set(friendObj.id, friendObj);
        return friendObj;
    }

    getFriend(id) {
        return this.friends.get(id);
    }

    getFriendByUserId(userId) {
        return Array.from(this.friends.values()).find(f => f.userId === userId);
    }

    getAllFriends() {
        return Array.from(this.friends.values());
    }

    updateFriend(id, changes) {
        const friend = this.friends.get(id);
        if (!friend) return null;
        
        const updated = friend.update(changes);
        this.friends.set(id, updated);
        return updated;
    }

    removeFriend(id) {
        return this.friends.delete(id);
    }

    addRequest(request) {
        const requestObj = request instanceof FriendRequest ? request : new FriendRequest(request);
        this.requests.set(requestObj.id, requestObj);
        return requestObj;
    }

    getRequest(id) {
        return this.requests.get(id);
    }

    getPendingRequests() {
        return Array.from(this.requests.values()).filter(r => r.isPending());
    }

    updateRequest(id, changes) {
        const request = this.requests.get(id);
        if (!request) return null;
        
        const updated = request.update(changes);
        this.requests.set(id, updated);
        return updated;
    }

    removeRequest(id) {
        return this.requests.delete(id);
    }

    getOnlineFriends() {
        return Array.from(this.friends.values()).filter(f => f.isOnline);
    }

    getFriendsCount() {
        return this.friends.size;
    }

    getRequestsCount() {
        return this.getPendingRequests().length;
    }

    clear() {
        this.friends.clear();
        this.requests.clear();
    }
}

// Export all models and collections
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        User,
        Session,
        Friend,
        FriendRequest,
        UserCollection,
        SessionCollection,
        FriendCollection
    };
} else {
    window.User = User;
    window.Session = Session;
    window.Friend = Friend;
    window.FriendRequest = FriendRequest;
    window.UserCollection = UserCollection;
    window.SessionCollection = SessionCollection;
    window.FriendCollection = FriendCollection;
}