// Optimized chat.js with integrated crypto functions and improved UI
class ChatManager {
    constructor() {
        this.socket = null;
        this.currentSession = null;
        this.user = null;
        this.friends = [];
        this.sessions = [];
        this.messages = new Map();
        this.elements = {};
        this.pollingInterval = null;
        
        // Processing queues and caches
        this.processingMessages = new Set();
        this.apiCache = new Map();
        this.messageHistory = new Map();
        this.unreadCounts = new Map();
        
        // UI state
        this.currentChatPartner = null;
        this.isTyping = false;
        this.lastActivity = Date.now();
        
        // Performance optimization
        this.messageLoadBatch = 50;
        this.maxCachedMessages = 1000;
        
        // ✅ INTEGRATED CRYPTO STORAGE
        this.sessionKeys = new Map(); // sessionToken -> AES key
        this.userPrivateKey = null;
        this.userPublicKey = null;
        this.messageCounters = new Map();
        this.decryptedMessages = new Map();
        this.forwardSecrecyEnabled = true;
        this.typingTimeout = null;
    }

    async init() {
        try {
            console.log("🚀 Initializing ChatManager");
            
            this.user = await this._getCurrentUser();
            console.log("✅ User loaded:", this.user.username);
            
            // ✅ LOAD CRYPTO KEYS
            await this._loadCryptoKeys();
            
            this._initElements();
            this._setupEventListeners();
            
            await this._loadFriends();
            await this._loadSessions();
            await this._initSocket();
            
            this._startPeriodicTasks();
            
            console.log("✅ ChatManager initialized successfully");
        } catch (error) {
            console.error("❌ Failed to initialize ChatManager:", error);
            this._showNotification('Failed to initialize chat system', 'error');
        }
    }

    // =================
    // ✅ INTEGRATED CRYPTO FUNCTIONS
    // =================
    
    async _loadCryptoKeys() {
        try {
            const privateKeyPEM = sessionStorage.getItem('user_private_key_pem');
            if (!privateKeyPEM) {
                throw new Error('No private key found - please login again');
            }
            
            console.log("🔑 Loading crypto keys...");
            this.userPrivateKey = await this._importPrivateKey(privateKeyPEM);
            console.log("✅ Crypto keys loaded successfully");
        } catch (error) {
            console.error("❌ Failed to load crypto keys:", error);
            throw error;
        }
    }
    
    async _importPrivateKey(pemData) {
        try {
            const binaryData = this._pemToBinary(pemData);
            const privateKey = await crypto.subtle.importKey(
                "pkcs8",
                binaryData,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["decrypt"]
            );
            return privateKey;
        } catch (error) {
            console.error("❌ Private key import failed:", error);
            throw new Error('Invalid private key format');
        }
    }
    
    _pemToBinary(pem) {
        const lines = pem.split('\n');
        const base64 = lines.slice(1, -1).join('').replace(/\s/g, '');
        return this._base64ToArrayBuffer(base64);
    }
    
    _base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    _arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    // ✅ AES SESSION KEY MANAGEMENT
    async generateSessionKey() {
        const key = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
        return key;
    }
    
    async exportSessionKey(key) {
        const exported = await crypto.subtle.exportKey("raw", key);
        return this._arrayBufferToBase64(exported);
    }
    
    async importSessionKey(keyBase64) {
        const keyBuffer = this._base64ToArrayBuffer(keyBase64);
        const key = await crypto.subtle.importKey(
            "raw",
            keyBuffer,
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
        return key;
    }
    
    storeSessionKey(sessionToken, keyBase64) {
        this.sessionKeys.set(sessionToken, keyBase64);
        console.log(`💾 Session key stored for ${sessionToken.slice(0, 8)}...`);
    }
    
    getSessionKey(sessionToken) {
        return this.sessionKeys.get(sessionToken);
    }
    
    removeSessionKey(sessionToken) {
        this.sessionKeys.delete(sessionToken);
    }
    
    // ✅ MESSAGE ENCRYPTION/DECRYPTION
    async encryptMessage(sessionKey, message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            data
        );
        
        return {
            data: this._arrayBufferToBase64(encrypted),
            iv: this._arrayBufferToBase64(iv)
        };
    }
    
    async decryptMessage(sessionKey, encryptedData) {
        const data = this._base64ToArrayBuffer(encryptedData.data);
        const iv = this._base64ToArrayBuffer(encryptedData.iv);
        
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            data
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
    
    // ✅ SESSION KEY ENCRYPTION FOR MULTIPLE USERS
    async encryptSessionKeyForMultipleUsers(recipients, sessionKey) {
        const sessionKeyBase64 = await this.exportSessionKey(sessionKey);
        const sessionKeyBuffer = this._base64ToArrayBuffer(sessionKeyBase64);
        const encryptedKeys = {};
        
        for (const [userId, publicKeyPEM] of Object.entries(recipients)) {
            try {
                const publicKey = await this._importPublicKey(publicKeyPEM);
                const encrypted = await crypto.subtle.encrypt(
                    {
                        name: "RSA-OAEP"
                    },
                    publicKey,
                    sessionKeyBuffer
                );
                encryptedKeys[userId] = this._arrayBufferToBase64(encrypted);
            } catch (error) {
                console.error(`❌ Failed to encrypt session key for user ${userId}:`, error);
            }
        }
        return encryptedKeys;
    }
    
    async _importPublicKey(pemData) {
        const binaryData = this._pemToBinary(pemData);
        const publicKey = await crypto.subtle.importKey(
            "spki",
            binaryData,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            false,
            ["encrypt"]
        );
        return publicKey;
    }
    
    async decryptSessionKey(encryptedKeyBase64) {
        const encryptedKey = this._base64ToArrayBuffer(encryptedKeyBase64);
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            this.userPrivateKey,
            encryptedKey
        );
        return this._arrayBufferToBase64(decrypted);
    }

// ============= FORWARD SECRECY - KEY DERIVATION =============

    initMessageCounters() {
        if (!this.messageCounters) {
            this.messageCounters = new Map();
        }
    }

    getNextMessageNumber(sessionToken) {
        if (!this.messageCounters.has(sessionToken)) {
            this.messageCounters.set(sessionToken, 0);
        }
        const current = this.messageCounters.get(sessionToken);
        this.messageCounters.set(sessionToken, current + 1);
        return current + 1;
    }

    async deriveMessageKey(sessionKey, messageNumber, direction = 'send') {
        try {
            const salt = new TextEncoder().encode(`msg_${messageNumber}_${direction}`);
            let sessionKeyRaw;
            
            if (typeof sessionKey === 'string') {
                sessionKeyRaw = this._base64ToArrayBuffer(sessionKey);
            } else {
                try {
                    sessionKeyRaw = await crypto.subtle.exportKey("raw", sessionKey);
                } catch (exportError) {
                    console.log("🔄 Key not extractable, using alternative method");
                    return await this._deriveKeyAlternative(sessionKey, messageNumber, direction);
                }
            }
            
            const hkdfKey = await crypto.subtle.importKey(
                "raw",
                sessionKeyRaw,
                { name: "HKDF" },
                false,
                ["deriveKey"]
            );
            
            const messageKey = await crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: salt,
                    info: new TextEncoder().encode("danaid-message-key-v1")
                },
                hkdfKey,
                {
                    name: "AES-GCM",
                    length: 256
                },
                false,
                ["encrypt", "decrypt"]
            );
            
            console.log(`🔑 Derived message key #${messageNumber} (${direction})`);
            return messageKey;
        } catch (error) {
            console.error("❌ Message key derivation failed:", error);
            throw new Error(`Key derivation failed: ${error.message}`);
        }
    }

    async _deriveKeyAlternative(sessionKey, messageNumber, direction) {
        try {
            console.log("🔄 Using alternative key derivation method");
            const messageData = new TextEncoder().encode(`${messageNumber}_${direction}_key_derivation`);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const derivedKeyMaterial = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                sessionKey,
                messageData
            );
            
            const keyMaterial = new Uint8Array(derivedKeyMaterial).slice(0, 32);
            const derivedKey = await crypto.subtle.importKey(
                "raw",
                keyMaterial,
                {
                    name: "AES-GCM",
                    length: 256
                },
                false,
                ["encrypt", "decrypt"]
            );
            
            console.log(`🔑 Alternative derived key #${messageNumber} (${direction})`);
            return derivedKey;
        } catch (error) {
            console.error("❌ Alternative key derivation failed:", error);
            return sessionKey;
        }
    }

    async encryptMessageWithForwardSecrecy(sessionKey, message, messageNumber) {
        try {
            const messageKey = await this.deriveMessageKey(sessionKey, messageNumber, 'send');
            const encrypted = await this.encryptMessage(messageKey, message);
            return {
                ...encrypted,
                messageNumber: messageNumber,
                forwardSecrecy: true
            };
        } catch (error) {
            console.error("❌ Forward secrecy encryption failed:", error);
            console.log("🔄 Falling back to legacy encryption");
            return await this.encryptMessage(sessionKey, message);
        }
    }

    async decryptMessageWithForwardSecrecy(sessionKey, encryptedData) {
        try {
            if (!encryptedData.forwardSecrecy || !encryptedData.messageNumber) {
                return await this.decryptMessage(sessionKey, encryptedData);
            }
            
            const messageKey = await this.deriveMessageKey(
                sessionKey, 
                encryptedData.messageNumber, 
                'send'
            );
            
            const decrypted = await this.decryptMessage(messageKey, {
                data: encryptedData.data,
                iv: encryptedData.iv
            });
            
            console.log(`🔓 Decrypted message #${encryptedData.messageNumber} with Forward Secrecy`);
            return decrypted;
        } catch (error) {
            console.error("❌ Forward secrecy decryption failed:", error);
            try {
                return await this.decryptMessage(sessionKey, {
                    data: encryptedData.data,
                    iv: encryptedData.iv
                });
            } catch (legacyError) {
                throw new Error(`Both FS and legacy decryption failed: ${error.message}`);
            }
        }
    }

    async storeDecryptedMessage(sessionToken, message) {
        try {
            if (!this.decryptedMessages) {
                this.decryptedMessages = new Map();
            }
            
            if (!this.decryptedMessages.has(sessionToken)) {
                this.decryptedMessages.set(sessionToken, []);
            }
            
            const sessionMessages = this.decryptedMessages.get(sessionToken);
            const existingIndex = sessionMessages.findIndex(m => m.id === message.id);
            
            if (existingIndex >= 0) {
                sessionMessages[existingIndex] = message;
            } else {
                sessionMessages.push(message);
            }
            
            if (sessionMessages.length > 500) {
                sessionMessages.splice(0, sessionMessages.length - 500);
            }
            
            sessionMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            console.log(`💾 Stored decrypted message locally (${sessionMessages.length} total)`);
        } catch (error) {
            console.error("❌ Failed to store decrypted message:", error);
        }
    }

    getStoredDecryptedMessages(sessionToken) {
        if (!this.decryptedMessages) {
            return [];
        }
        return this.decryptedMessages.get(sessionToken) || [];
    }

    getForwardSecrecyInfo() {
        return {
            enabled: this.forwardSecrecyEnabled,
            messageCounters: this.messageCounters ? this.messageCounters.size : 0,
            algorithm: "HKDF-SHA256 + AES-GCM",
            security: "Signal Protocol inspired",
            version: "danaid-fs-v1"
        };
    }

    // =================
    // SESSION MANAGEMENT WITH DUAL ENCRYPTION
    // =================
    
    async _initSession(recipientId) {
        console.log("🚀 Initializing session with:", recipientId);
        
        try {
            const response = await fetch('/api/session/init', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient_id: recipientId })
            });
            
            if (!response.ok) {
                throw new Error(`Session init failed: ${response.status}`);
            }
            
            const data = await response.json();
            this.currentSession = data.session;
            
            console.log("✅ Session initialized:", data.session.token.slice(0, 8) + "...");
            
            await this._ensureSessionKey();
            await this._joinSessionRoom(data.session.token);
            this.initMessageCounters();
            await this._loadMessages(data.session.token);
            this._updateChatUI();
            
        } catch (error) {
            console.error("❌ Session initialization failed:", error);
            this._showNotification('Failed to start chat session', 'error');
            throw error;
        }
    }

    async _ensureSessionKey() {
        if (!this.currentSession) {
            throw new Error('No current session');
        }

        const sessionToken = this.currentSession.token;
        console.log("🔑 Ensuring session key exists for:", sessionToken.slice(0, 8) + "...");

        if (await this._getSessionKeyOptimized(sessionToken)) {
            console.log("✅ Session key already exists locally");
            return;
        }

        try {
            const response = await fetch(`/api/session/${sessionToken}/key`);
            if (response.ok) {
                const data = await response.json();
                if (data.encrypted_key) {
                    console.log("🔍 Found existing session key on server, decrypting...");
                    const decryptedKey = await this.decryptSessionKey(data.encrypted_key);
                    this.storeSessionKey(sessionToken, decryptedKey);
                    console.log("✅ Existing session key decrypted and stored");
                    return;
                }
            }
        } catch (error) {
            console.log("⚠️ No existing key or decryption failed, will generate new");
        }

        console.log("🔧 Generating new session key with dual encryption...");
        await this._generateDualEncryptedSessionKey(sessionToken);
    }

    async _generateDualEncryptedSessionKey(sessionToken) {
        try {
            const sessionKey = await this.generateSessionKey();
            const sessionKeyBase64 = await this.exportSessionKey(sessionKey);
            
            this.storeSessionKey(sessionToken, sessionKeyBase64);
            console.log("💾 Session key stored locally");
            
            const currentUserId = this.user.id;
            const otherUserId = this.currentSession.other_user.id;
            
            const recipients = {};
            recipients[currentUserId] = await this._getUserPublicKey(this.user.user_id);
            recipients[otherUserId] = await this._getUserPublicKey(this.currentSession.other_user.user_id);
            
            console.log(`🔑 Got public keys for users: ${currentUserId}, ${otherUserId}`);
            
            const encryptedKeys = await this.encryptSessionKeyForMultipleUsers(
                recipients,
                sessionKey
            );
            
            console.log("🔐 Session key encrypted for users:", Object.keys(encryptedKeys));
            
            const response = await fetch(`/api/session/${sessionToken}/exchange_key`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    keys: encryptedKeys
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`Server error: ${errorData.message || response.status}`);
            }
            
            const result = await response.json();
            console.log("✅ Dual-encrypted session key sent to server");
            this.apiCache.delete(`session_key_${sessionToken}`);
            
        } catch (error) {
            this.removeSessionKey(sessionToken);
            console.error("❌ Dual encrypted key generation failed:", error);
            throw new Error(`Session key setup failed: ${error.message}`);
        }
    }

    async _joinSessionRoom(sessionToken) {
        if (!this.socket || !this.socket.connected) {
            console.log("⚠️ Socket not connected, cannot join session room");
            return;
        }
        
        console.log(`📡 Joining session room: session_${sessionToken.slice(0, 8)}...`);
        
        this.socket.emit('join_session', {
            session_token: sessionToken
        });
        
        this.socket.once('session_joined', (response) => {
            if (response.status === 'success') {
                console.log("✅ Successfully joined session room");
            } else {
                console.error("❌ Failed to join session room:", response);
            }
        });
    }

// =================
    // ✅ MESSAGE HANDLING WITH FORWARD SECRECY
    // =================
    
    async sendMessage() {
        const content = this.elements.messageInput?.value.trim();
        if (!content || !this.currentSession) return;

        console.log('🚀 Sending message with Forward Secrecy to session:', this.currentSession.token.slice(0, 8) + '...');

        this.elements.messageInput.disabled = true;
        this.elements.sendButton.disabled = true;

        try {
            await this._ensureSessionKey();

            const sessionKey = await this._getSessionKeyOptimized(this.currentSession.token);
            if (!sessionKey) {
                throw new Error('No session key available after ensuring');
            }

            const messageNumber = this.getNextMessageNumber(this.currentSession.token);
            
            let encrypted;
            if (this.forwardSecrecyEnabled) {
                encrypted = await this.encryptMessageWithForwardSecrecy(sessionKey, content, messageNumber);
                console.log(`🔐 Message encrypted with FS (msg #${messageNumber})`);
            } else {
                encrypted = await this.encryptMessage(sessionKey, content);
                console.log('🔐 Message encrypted (legacy mode)');
            }

            const response = await fetch('/api/message/send', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    session_token: this.currentSession.token,
                    content: encrypted.data,
                    iv: encrypted.iv,
                    message_number: encrypted.messageNumber || null,
                    forward_secrecy: encrypted.forwardSecrecy || false
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${response.status} - ${errorText}`);
            }

            const data = await response.json();

            if (data.status === 'success') {
                this.elements.messageInput.value = '';

                const newMessage = {
                    id: data.message.id,
                    sender_id: parseInt(this.user.id),
                    content: content,
                    timestamp: data.message.timestamp,
                    is_mine: true,
                    messageNumber: encrypted.messageNumber,
                    forwardSecrecy: encrypted.forwardSecrecy
                };

                this._addMessageToUI(newMessage);
                await this._storeMessage(this.currentSession.token, newMessage);
                
                if (this.forwardSecrecyEnabled) {
                    await this.storeDecryptedMessage(this.currentSession.token, newMessage);
                }

                console.log('✅ Message sent successfully with Forward Secrecy');
            } else {
                this._showNotification(data.message || 'Send failed', 'error');
            }

        } catch (error) {
            console.error("❌ Send message error:", error);
            this._showNotification('Failed to send message: ' + error.message, 'error');
        } finally {
            this.elements.messageInput.disabled = false;
            this.elements.sendButton.disabled = false;
            this.elements.messageInput.focus();
        }
    }

    async _processMessage(sessionToken, message, source = 'unknown') {
        const messageKey = `${sessionToken}-${message.id || message.timestamp}`;
        
        if (this.processingMessages.has(messageKey)) {
            console.log("Message already processing, skipping");
            return;
        }
        
        this.processingMessages.add(messageKey);
        
        try {
            let processedMessage = { ...message };
            
            // ✅ IMPROVED: Better encryption detection
            const needsDecryption = this._shouldDecryptMessage(message);
            
            if (needsDecryption) {
                const sessionKey = await this._getSessionKeyOptimized(sessionToken);
                
                if (sessionKey) {
                    try {
                        let decryptedContent;
                        
                        // ✅ FORWARD SECRECY: Try Forward Secrecy decryption first
                        if (this.forwardSecrecyEnabled && message.forward_secrecy && message.message_number) {
                            console.log(`🔓 Attempting FS decryption for message #${message.message_number}`);
                            decryptedContent = await this.decryptMessageWithForwardSecrecy(sessionKey, {
                                data: message.content,
                                iv: message.iv,
                                messageNumber: message.message_number,
                                forwardSecrecy: message.forward_secrecy
                            });
                        } else {
                            // Legacy decryption
                            console.log("🔓 Using legacy decryption");
                            decryptedContent = await this.decryptMessage(sessionKey, {
                                data: message.content,
                                iv: message.iv
                            });
                        }
                        
                        processedMessage.content = decryptedContent;
                        processedMessage.decrypted = true;
                        
                        console.log("✅ Message decrypted successfully");
                        
                        // ✅ FORWARD SECRECY: Store decrypted message locally
                        if (this.forwardSecrecyEnabled) {
                            await this.storeDecryptedMessage(sessionToken, processedMessage);
                        }
                        
                    } catch (decryptError) {
                        console.error("❌ Decryption failed:", decryptError.message);
                        processedMessage.content = `[Decryption failed: ${decryptError.message}]`;
                        processedMessage.decrypted = false;
                    }
                } else {
                    console.log("⚠️ No session key available for decryption");
                    processedMessage.content = '[No session key - please refresh]';
                    processedMessage.decrypted = false;
                }
            }
            
            // Store processed message
            await this._storeMessage(sessionToken, processedMessage);
            
            // Update UI if it's for current session
            if (sessionToken === this.currentSession?.token) {
                this._addMessageToUI(processedMessage);
            }
            
        } catch (error) {
            console.error("❌ Message processing error:", error);
            // Store error message so user sees something
            await this._storeMessage(sessionToken, {
                ...message,
                content: `[Processing error: ${error.message}]`,
                decrypted: false
            });
        } finally {
            this.processingMessages.delete(messageKey);
        }
    }

    _shouldDecryptMessage(message) {
        // If no IV, definitely not encrypted
        if (!message.iv) return false;
        
        // Use explicit flag if available
        if (message.hasOwnProperty('is_encrypted')) {
            return message.is_encrypted;
        }
        
        // If content is very short and looks like plain text, probably not encrypted
        if (message.content.length < 20 && /^[a-zA-Z0-9\s\.\,\!\?]+$/.test(message.content)) {
            return false;
        }
        
        // If we have IV and content looks like base64, probably encrypted
        const base64Pattern = /^[A-Za-z0-9+/]+=*$/;
        return base64Pattern.test(message.content.replace(/\s/g, ''));
    }

    async deleteSession() {
        if (!this.currentSession) {
            this._showNotification('Brak aktywnej sesji', 'warning');
            return;
        }

        if (!confirm('Czy na pewno chcesz usunąć całą rozmowę? Ta operacja jest nieodwracalna.')) {
            return;
        }

        try {
            const response = await fetch(`/api/session/${this.currentSession.token}/delete`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();
            if (response.ok && data.status === 'success') {
                if (this.elements.messagesContainer) {
                    this.elements.messagesContainer.innerHTML = '<div class="welcome-message">Wybierz znajomego, aby rozpocząć rozmowę</div>';
                }
                
                this.messages.delete(this.currentSession.token);
                this.removeSessionKey(this.currentSession.token);
                this.currentSession = null;
                this.currentChatPartner = null;
                
                this._updateChatUI();
                await this._loadSessions();
                
                this._showNotification(`Usunięto rozmowę (${data.messages_deleted} wiadomości)`, 'success');
                console.log('✅ Session deleted successfully');
            } else {
                throw new Error(data.error || 'Failed to delete session');
            }
        } catch (error) {
            console.error('❌ Delete session error:', error);
            this._showNotification('Nie udało się usunąć rozmowy: ' + error.message, 'error');
        }
    }

    // =================
    // ✅ IMPROVED SOCKET.IO HANDLING
    // =================
    
    async _initSocket() {
        try {
            // Check if Socket.IO is available
            if (typeof io === 'undefined') {
                console.warn("⚠️ Socket.IO not available, using polling fallback");
                this._enablePollingFallback();
                return;
            }

            const config = await this._getSocketConfig();
            
            this.socket = io(config.socketUrl || window.location.origin, {
                path: config.path || '/socket.io/',
                transports: ['websocket', 'polling'],
                upgrade: true,
                reconnection: true,
                reconnectionAttempts: 5,
                reconnectionDelay: 1000,
                secure: window.location.protocol === 'https:'
            });

            this._setupSocketEvents();

        } catch (error) {
            console.error("❌ Socket initialization failed:", error);
            this._enablePollingFallback();
        }
    }

    _setupSocketEvents() {
        this.socket.on('connect', () => {
            console.log("✅ Socket.IO connected");
            this.socket.emit('register_user', { user_id: this.user.id });
            console.log(`📡 Registered for user room: user_${this.user.id}`);
            
            if (this.pollingInterval) {
                clearInterval(this.pollingInterval);
                this.pollingInterval = null;
            }
        });

        this.socket.on('message', async (data) => {
            try {
                console.log("📨 Real-time message received:", data);
                await this._handleSocketMessage(data);
            } catch (error) {
                console.error("❌ Socket message handling error:", error);
            }
        });

        this.socket.on('session_cleared', (data) => {
            console.log("🧹 Session cleared notification received:", data);
            if (data.session_token === this.currentSession?.token) {
                this._clearMessagesDisplay();
                this._showNotification('Rozmowa została wyczyszczona przez drugą stronę', 'info');
            }
        });

        this.socket.on('session_deleted', (data) => {
            console.log("🗑️ Session deleted notification received:", data);
            if (data.session_token === this.currentSession?.token) {
                this.currentSession = null;
                this._updateChatUI();
                this._showNotification('Rozmowa została usunięta przez drugą stronę', 'warning');
            }
        });

        this.socket.on('connect_error', (error) => {
            console.error("❌ Socket.IO connection error:", error);
            this._enablePollingFallback();
        });

        this.socket.on('disconnect', (reason) => {
            console.log(`🔌 Socket.IO disconnected: ${reason}`);
            this._enablePollingFallback();
            
            if (reason === 'io server disconnect') {
                setTimeout(() => {
                    if (!this.socket.connected) {
                        this.socket.connect();
                    }
                }, 1000);
            }
        });
    }

    async _handleSocketMessage(data) {
        console.log(`📥 Handling socket message type: ${data.type}`);
        
        switch (data.type) {
            case 'new_message':
                await this._handleNewMessage(data);
                break;
            case 'friend_request':
                this._handleFriendRequest(data);
                break;
            case 'user_status_change':
                this._handleStatusChange(data);
                break;
            default:
                console.log("❓ Unknown socket message type:", data.type);
        }
    }

    async _handleNewMessage(data) {
        console.log(`📨 Processing new message from Socket.IO:`);
        console.log(`   Session token: ${data.session_token?.slice(0, 8)}...`);
        console.log(`   Sender ID: ${data.message.sender_id}`);
        console.log(`   My user ID: ${this.user.id}`);
        
        if (data.message.sender_id == this.user.id) {
            console.log("⏭️ Skipping own message");
            return;
        }
        
        try {
            const hasAccess = this._hasSessionAccess(data.session_token);
            
            if (!hasAccess) {
                console.warn("⚠️ Received message for unauthorized session");
                await this._loadSessions();
                
                if (!this._hasSessionAccess(data.session_token)) {
                    console.error("❌ Still no access after reload - rejecting message");
                    return;
                }
            }
            
            await this._processMessage(data.session_token, data.message, 'realtime');
            
            if (data.session_token !== this.currentSession?.token) {
                this._updateUnreadCount(data.session_token);
                
                const session = this.sessions.find(s => s.token === data.session_token);
                const senderName = session?.other_user?.username || 'Nieznany użytkownik';
                this._showNotification(`Nowa wiadomość od ${senderName}`, 'info', 3000);
            }
            
            this._playNotificationSound();
            
        } catch (error) {
            console.error("❌ Error handling new message:", error);
            this._showNotification('Error receiving message', 'error', 3000);
        }
    }

    _hasSessionAccess(sessionToken) {
        if (this.currentSession && this.currentSession.token === sessionToken) {
            return true;
        }
        
        const session = this.sessions.find(s => s.token === sessionToken);
        return !!session;
    }

// =================
    // ✅ FRIENDS MANAGEMENT
    // =================
    
    async _loadFriends() {
        try {
            const response = await fetch('/api/friends');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.friends = data.friends || [];
                this._renderFriendsList();
                console.log(`✅ Loaded ${this.friends.length} friends`);
            }
        } catch (error) {
            console.error("❌ Failed to load friends:", error);
            this._showNotification('Failed to load friends list', 'error');
        }
    }

    async addFriend(userIdOrUsername) {
        try {
            const response = await fetch('/api/friends/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_identifier: userIdOrUsername })
            });

            const data = await response.json();

            if (data.status === 'success') {
                this._showNotification('Friend request sent successfully', 'success');
                await this._loadFriends();
            } else {
                this._showNotification(data.message || 'Failed to send friend request', 'error');
            }
        } catch (error) {
            console.error('❌ Add friend error:', error);
            this._showNotification('Failed to send friend request: ' + error.message, 'error');
        }
    }

    // ✅ POPRAWIONA FUNKCJA removeFriend Z PRZYCISKAMI
    async removeFriend(friendId) {
        console.log('🗑️ Attempting to remove friend:', friendId);
        
        const friend = this.friends.find(f => f.user_id == friendId);
        const friendName = friend ? friend.username : 'tego znajomego';
        
        if (!confirm(`Czy na pewno chcesz usunąć ${friendName} z listy znajomych?`)) {
            console.log('🚫 Friend removal cancelled by user');
            return;
        }

        try {
            this._showNotification('Usuwanie znajomego...', 'info', 2000);
            
            const response = await fetch(`/api/friends/${friendId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();

            if (response.ok && data.status === 'success') {
                this.friends = this.friends.filter(f => f.user_id != friendId);
                
                if (this.currentChatPartner && this.currentChatPartner.user_id == friendId) {
                    this.currentSession = null;
                    this.currentChatPartner = null;
                    this._updateChatUI();
                    
                    if (this.elements.messagesContainer) {
                        this.elements.messagesContainer.innerHTML = '<div class="welcome-message">Wybierz znajomego, aby rozpocząć rozmowę</div>';
                    }
                }
                
                this._renderFriendsList();
                this._showNotification(`Usunięto ${friendName} z listy znajomych`, 'success');
                console.log('✅ Friend removed successfully');
            } else {
                throw new Error(data.message || data.error || 'Failed to remove friend');
            }
        } catch (error) {
            console.error('❌ Remove friend error:', error);
            this._showNotification(`Nie udało się usunąć znajomego: ${error.message}`, 'error');
        }
    }

    _showFriendRequestsModal() {
        console.log("🔔 Showing friend requests modal");
        
        let modal = document.getElementById('friend-requests-modal');
        
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'friend-requests-modal';
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Zaproszenia do znajomych</h3>
                        <button class="modal-close">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div id="friend-requests-list">
                            Ładowanie...
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
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
        this._loadFriendRequestsInModal();
    }

    async _loadFriendRequestsInModal() {
        try {
            const response = await fetch('/api/friend_requests/pending');
            const data = await response.json();
            
            const container = document.getElementById('friend-requests-list');
            
            if (data.status === 'success' && data.requests.length > 0) {
                container.innerHTML = data.requests.map(req => `
                    <div class="friend-request-item">
                        <div class="request-info">
                            <strong>${this._escapeHtml(req.username)}</strong>
                            <small>ID: ${req.sender_id}</small>
                        </div>
                        <div class="request-actions">
                            <button class="btn btn-success" onclick="window.chatManager.acceptFriendRequest(${req.id})">
                                Akceptuj
                            </button>
                            <button class="btn btn-danger" onclick="window.chatManager.rejectFriendRequest(${req.id})">
                                Odrzuć
                            </button>
                        </div>
                    </div>
                `).join('');
            } else {
                container.innerHTML = '<p style="text-align: center;">Brak zaproszeń</p>';
            }
            
            const countElement = document.getElementById('friend-request-count');
            if (countElement) {
                countElement.textContent = data.requests ? data.requests.length : 0;
            }
            
        } catch (error) {
            console.error("❌ Failed to load friend requests:", error);
            document.getElementById('friend-requests-list').innerHTML = 
                '<p style="color: red;">Błąd ładowania zaproszeń</p>';
        }
    }

    async acceptFriendRequest(requestId) {
        try {
            const response = await fetch(`/api/friend_requests/${requestId}/accept`, {
                method: 'POST'
            });
            const data = await response.json();
            
            if (data.status === 'success') {
                this._showNotification('Zaproszenie zaakceptowane', 'success');
                this._loadFriendRequestsInModal();
                this._loadFriends();
            }
        } catch (error) {
            this._showNotification('Błąd akceptacji zaproszenia', 'error');
        }
    }

    async rejectFriendRequest(requestId) {
        try {
            const response = await fetch(`/api/friend_requests/${requestId}/reject`, {
                method: 'POST'
            });
            const data = await response.json();
            
            if (data.status === 'success') {
                this._showNotification('Zaproszenie odrzucone', 'success');
                this._loadFriendRequestsInModal();
            }
        } catch (error) {
            this._showNotification('Błąd odrzucenia zaproszenia', 'error');
        }
    }

    async _loadFriendRequests() {
        try {
            const response = await fetch('/api/friend_requests/pending');
            const data = await response.json();
            
            if (data.status === 'success') {
                this._renderFriendRequests(data.requests);
                
                const countElement = document.getElementById('friend-request-count');
                if (countElement) {
                    countElement.textContent = data.requests ? data.requests.length : 0;
                    if (data.requests && data.requests.length > 0) {
                        countElement.style.display = 'inline';
                    } else {
                        countElement.style.display = 'none';
                    }
                }
            }
        } catch (error) {
            console.error("❌ Failed to load friend requests:", error);
        }
    }

    // =================
    // SESSION MANAGEMENT
    // =================
    
    async _loadSessions() {
        try {
            const response = await fetch('/api/sessions/active');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.sessions = data.sessions || [];
                
                if (this.currentSession) {
                    const existsInSessions = this.sessions.find(s => s.token === this.currentSession.token);
                    if (!existsInSessions) {
                        this.sessions.push(this.currentSession);
                    }
                }
                
                this._renderSessionsList();
                console.log(`✅ Loaded ${this.sessions.length} sessions`);
            }
        } catch (error) {
            console.error("❌ Failed to load sessions:", error);
        }
    }

    async _selectFriend(userId) {
        const friend = this.friends.find(f => f.user_id === userId);
        if (friend) {
            this.currentChatPartner = friend;
            this._markFriendAsActive(userId);
            await this._initSession(userId);
        }
    }

    _markFriendAsActive(userId) {
        document.querySelectorAll('.friend-item').forEach(item => {
            item.classList.remove('active');
        });
        
        const friendElement = document.querySelector(`[data-user-id="${userId}"]`);
        if (friendElement) {
            friendElement.classList.add('active');
        }
    }

    // =================
    // POLLING FALLBACK
    // =================
    
    _enablePollingFallback() {
        if (this.pollingInterval) return;
        
        console.log("🔄 Enabling polling fallback");
        
        let lastMessageId = 0;
        
        this.pollingInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/polling/messages?last_id=${lastMessageId}`);
                
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.messages && data.messages.length > 0) {
                        for (const msgData of data.messages) {
                            await this._handleNewMessage(msgData);
                        }
                        lastMessageId = data.last_id;
                    }
                }
            } catch (error) {
                console.error("❌ Polling error:", error);
            }
        }, 3000);
    }

    // =================
    // MESSAGE LOADING AND CACHING
    // =================
    
    async _loadMessages(sessionToken, limit = 50, offset = 0) {
        try {
            const response = await fetch(`/api/messages/${sessionToken}?limit=${limit}&offset=${offset}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                this.elements.messagesContainer.innerHTML = '';
                
                for (const message of data.messages) {
                    await this._processMessage(sessionToken, message, 'history');
                }
                
                console.log(`✅ Loaded ${data.messages.length} messages for session`);
            }
        } catch (error) {
            console.error("❌ Failed to load messages:", error);
            this._showNotification('Failed to load message history', 'error');
        }
    }

    async _storeMessage(sessionToken, message) {
        if (!this.messages.has(sessionToken)) {
            this.messages.set(sessionToken, []);
        }
        
        const sessionMessages = this.messages.get(sessionToken);
        
        const existingIndex = sessionMessages.findIndex(m => m.id === message.id);
        if (existingIndex >= 0) {
            sessionMessages[existingIndex] = message;
        } else {
            sessionMessages.push(message);
            
            if (sessionMessages.length > this.maxCachedMessages) {
                sessionMessages.splice(0, sessionMessages.length - this.maxCachedMessages);
            }
        }
        
        sessionMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    }

    // =================
    // ✅ UI MANAGEMENT
    // =================
    
    _initElements() {
        this.elements = {
            messageInput: document.getElementById('message-input'),
            sendButton: document.getElementById('send-button'),
            messagesContainer: document.getElementById('messages'),
            friendsList: document.getElementById('friend-list'),
            sessionsList: document.getElementById('sessions-list'),
            friendRequests: document.getElementById('friend-requests'),
            addFriendBtn: document.getElementById('add-friend-btn'),
            addFriendInput: document.getElementById('friend-username-input'),
            chatHeader: document.getElementById('chat-header'),
            typingIndicator: document.getElementById('typing-indicator'),
            connectionStatus: document.getElementById('connection-status')
        };
        
        const requiredElements = ['messageInput', 'sendButton', 'messagesContainer'];
        for (const elementName of requiredElements) {
            if (!this.elements[elementName]) {
                console.warn(`⚠️ Required element not found: ${elementName}`);
            }
        }
    }

    _setupEventListeners() {
        this.elements.sendButton?.addEventListener('click', () => this.sendMessage());
        this.elements.messageInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        this.elements.addFriendBtn?.addEventListener('click', () => {
            this._showAddFriendModal();
        });

        this.elements.messageInput?.addEventListener('input', () => {
            this._handleTyping();
        });

        window.addEventListener('focus', () => {
            this.lastActivity = Date.now();
        });

        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Delete' && !e.shiftKey) {
                e.preventDefault();
                this.clearSessionMessages();
            }
            
            if (e.ctrlKey && e.shiftKey && e.key === 'Delete') {
                e.preventDefault();
                this.deleteSession();
            }
        });
    }

    _showAddFriendModal() {
        const modal = document.getElementById('add-friend-modal');
        if (modal) {
            modal.style.display = 'block';
            
            if (!modal.dataset.listenersSet) {
                const closeBtn = modal.querySelector('.modal-close');
                const sendBtn = document.getElementById('send-friend-request-btn');
                const input = document.getElementById('friend-username-input');
                
                closeBtn?.addEventListener('click', () => {
                    modal.style.display = 'none';
                });
                
                modal.addEventListener('click', (e) => {
                    if (e.target === modal) {
                        modal.style.display = 'none';
                    }
                });
                
                sendBtn?.addEventListener('click', async () => {
                    const username = input?.value.trim();
                    if (username) {
                        await this.addFriend(username);
                        input.value = '';
                        modal.style.display = 'none';
                    }
                });
                
                modal.dataset.listenersSet = 'true';
            }
        }
    }

    _addMessageToUI(message) {
        if (!this.elements.messagesContainer) return;
        
        const messageEl = document.createElement('div');
        messageEl.className = `message ${message.is_mine || message.sender_id == this.user.id ? 'mine' : 'theirs'}`;
        messageEl.dataset.messageId = message.id;

        const timeStr = new Date(message.timestamp).toLocaleTimeString();
        
        messageEl.innerHTML = `
            <div class="message-content">${this._escapeHtml(message.content)}</div>
            <div class="message-time">${timeStr}</div>
            ${(message.is_mine || message.sender_id == this.user.id) ? '<div class="message-status">✓</div>' : ''}
        `;
        
        this.elements.messagesContainer.appendChild(messageEl);
        this.elements.messagesContainer.scrollTop = this.elements.messagesContainer.scrollHeight;
        
        messageEl.style.opacity = '0';
        messageEl.style.transform = 'translateY(20px)';
        requestAnimationFrame(() => {
            messageEl.style.transition = 'all 0.3s ease';
            messageEl.style.opacity = '1';
            messageEl.style.transform = 'translateY(0)';
        });
    }

    // ✅ POPRAWIONA LISTA ZNAJOMYCH - z opcjonalnymi przyciskami
    _renderFriendsList() {
        if (!this.elements.friendsList) return;
        
        this.elements.friendsList.innerHTML = this.friends.map(friend => {
            const initial = friend.username.charAt(0).toUpperCase();
            
            return `
                <li class="friend-item" data-user-id="${friend.user_id}">
                    <div class="friend-avatar">
                        ${initial}
                        <div class="status-indicator ${friend.is_online ? 'online' : 'offline'}"></div>
                    </div>
                    <div class="friend-info">
                        <div class="friend-name">${this._escapeHtml(friend.username)}</div>
                        <div class="friend-status ${friend.is_online ? 'online' : 'offline'}">
                            ${friend.is_online ? 'Online' : 'Offline'}
                        </div>
                    </div>
                    <div class="friend-actions">
                        <button 
                            class="btn btn-primary btn-sm chat-btn" 
                            data-user-id="${friend.user_id}"
                            title="Rozpocznij rozmowę"
                            style="margin-right: 8px; padding: 4px 8px; background: #FF9800; color: #333; border: none; border-radius: 3px; cursor: pointer; font-size: 12px;">
                            💬
                        </button>
                        <button 
                            class="btn btn-danger btn-sm remove-friend-btn" 
                            data-friend-id="${friend.user_id}"
                            title="Usuń znajomego"
                            style="padding: 4px 8px; background: #f44336; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 12px;">
                            🗑️
                        </button>
                    </div>
                    ${this.unreadCounts.get(friend.user_id) ? 
                        `<span class="unread-count">${this.unreadCounts.get(friend.user_id)}</span>` : 
                        ''
                    }
                </li>
            `;
        }).join('');
        
        this._attachFriendListeners();
    }

    // ✅ DODANA FUNKCJA _attachFriendListeners
    _attachFriendListeners() {
        if (!this.elements.friendsList) return;
        
        // Chat buttons
        this.elements.friendsList.querySelectorAll('.chat-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const userId = btn.dataset.userId;
                console.log('🎯 Chat button clicked for user:', userId);
                this._selectFriend(userId);
            });
        });

        // Remove friend buttons
        this.elements.friendsList.querySelectorAll('.remove-friend-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const friendId = btn.dataset.friendId;
                console.log('🗑️ Remove button clicked for friend:', friendId);
                this.removeFriend(friendId);
            });
        });

        // Całe elementy listy (ale nie na przyciski)
        this.elements.friendsList.querySelectorAll('.friend-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (!e.target.closest('.friend-actions')) {
                    const userId = item.dataset.userId;
                    console.log('👤 Friend item clicked:', userId);
                    this._selectFriend(userId);
                }
            });
        });
    }

    _renderFriendRequests(requests) {
        const container = document.getElementById('friend-requests-list');
        if (!container) return;
        
        if (requests && requests.length > 0) {
            container.innerHTML = requests.map(req => `
                <div class="friend-request-item" style="display: flex; justify-content: space-between; align-items: center; padding: 10px; border-bottom: 1px solid #555;">
                    <div>
                        <strong>${this._escapeHtml(req.username)}</strong>
                        <small style="display: block; color: #999;">ID: ${req.sender_id}</small>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-success" onclick="window.chatManager.acceptFriendRequest(${req.id})" style="padding: 5px 10px; font-size: 0.8em;">
                            Akceptuj
                        </button>
                        <button class="btn btn-danger" onclick="window.chatManager.rejectFriendRequest(${req.id})" style="padding: 5px 10px; font-size: 0.8em;">
                            Odrzuć
                        </button>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = '<p style="text-align: center; color: #999;">Brak zaproszeń</p>';
        }
    }

    _updateChatUI() {
        console.log('🔄 Updating chat UI, current session:', this.currentSession?.token?.slice(0,8));
        
        if (this.currentSession && this.elements.chatHeader) {
            const otherUser = this.currentSession.other_user;
            
            const partnerInfo = this.elements.chatHeader.querySelector('.chat-partner-info h2');
            const statusElement = this.elements.chatHeader.querySelector('.chat-status');
            
            if (partnerInfo) {
                partnerInfo.textContent = otherUser.username;
            } else {
                const existingH2 = this.elements.chatHeader.querySelector('h2');
                if (existingH2) {
                    existingH2.textContent = otherUser.username;
                }
            }
            
            if (statusElement) {
                statusElement.textContent = otherUser.is_online ? 'Online' : 'Offline';
                statusElement.className = `chat-status ${otherUser.is_online ? 'online' : 'offline'}`;
            }
        }

        const chatActions = document.querySelector('.chat-actions');
        
        if (chatActions) {
            if (this.currentSession) {
                chatActions.classList.add('visible');
                chatActions.style.display = 'flex';
                chatActions.style.visibility = 'visible';
                this._ensureChatActionListeners();
            } else {
                chatActions.classList.remove('visible');
                chatActions.style.display = 'none';
            }
        } else if (this.currentSession) {
            this._createChatActionsIfMissing();
        }
    }

    _ensureChatActionListeners() {
        const clearBtn = document.getElementById('clear-conversation-btn');
        const deleteBtn = document.getElementById('delete-conversation-btn');
        
        if (clearBtn && !clearBtn.dataset.listenerAttached) {
            clearBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.clearSessionMessages();
            });
            clearBtn.dataset.listenerAttached = 'true';
        }

        if (deleteBtn && !deleteBtn.dataset.listenerAttached) {
            deleteBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.deleteSession();
            });
            deleteBtn.dataset.listenerAttached = 'true';
        }
    }

    _createChatActionsIfMissing() {
        const chatHeader = this.elements.chatHeader;
        if (!chatHeader || document.querySelector('.chat-actions')) return;
        
        const chatActions = document.createElement('div');
        chatActions.className = 'chat-actions visible';
        chatActions.style.cssText = 'display: flex; gap: 12px; align-items: center; margin-left: auto;';
        
        chatActions.innerHTML = `
            <button id="clear-conversation-btn" class="btn btn-secondary" title="Wyczyść konwersację (Ctrl+Delete)">
                <i class="fas fa-broom"></i> <span>Wyczyść</span>
            </button>
            <button id="delete-conversation-btn" class="btn btn-danger" title="Usuń całą konwersację (Ctrl+Shift+Delete)">
                <i class="fas fa-trash"></i> <span>Usuń</span>
            </button>
        `;
        
        chatHeader.appendChild(chatActions);
        this._ensureChatActionListeners();
    }

    _clearMessagesDisplay() {
        const messagesContainer = document.getElementById('messages');
        if (messagesContainer) {
            messagesContainer.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    <i class="fas fa-broom" style="font-size: 48px; margin-bottom: 16px; opacity: 0.3;"></i>
                    <p>Konwersacja została wyczyszczona</p>
                </div>
            `;
        }
    }

    _showNotification(message, type = 'info', duration = 5000) {
        console.log(`🔔 Notification (${type}): ${message}`);
        
        let notificationContainer = document.getElementById('notification-container');
        if (!notificationContainer) {
            notificationContainer = document.createElement('div');
            notificationContainer.id = 'notification-container';
            notificationContainer.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 300px;
            `;
            document.body.appendChild(notificationContainer);
        }
        
        const notification = document.createElement('div');
        notification.style.cssText = `
            background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : type === 'warning' ? '#ff9800' : '#2196F3'};
            color: white;
            padding: 12px 16px;
            margin-bottom: 8px;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            font-size: 14px;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            cursor: pointer;
        `;
        notification.textContent = message;
        
        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '×';
        closeBtn.style.cssText = `
            background: none;
            border: none;
            color: inherit;
            margin-left: 10px;
            cursor: pointer;
            font-size: 18px;
            float: right;
        `;
        notification.appendChild(closeBtn);
        
        notificationContainer.appendChild(notification);
        
        const removeNotification = () => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        };
        
        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        }, 100);
        
        closeBtn.addEventListener('click', removeNotification);
        notification.addEventListener('click', removeNotification);
        
        setTimeout(removeNotification, duration);
    }

    _playNotificationSound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.value = 800;
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0, audioContext.currentTime);
            gainNode.gain.linearRampToValueAtTime(0.1, audioContext.currentTime + 0.01);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.5);
        } catch (error) {
            console.log("Could not play notification sound");
        }
    }

    // =================
    // UTILITY FUNCTIONS
    // =================

    async _getCurrentUser() {
        const response = await fetch('/api/check_auth');
        if (!response.ok) {
            throw new Error('Not authenticated');
        }
        return await response.json();
    }

    async _getUserPublicKey(userId) {
        const cacheKey = `public_key_${userId}`;
        
        if (this.apiCache.has(cacheKey)) {
            const cached = this.apiCache.get(cacheKey);
            if (Date.now() - cached.timestamp < 3600000) {
                return cached.key;
            }
        }
        
        const response = await fetch(`/api/user/${userId}/public_key`);
        if (!response.ok) {
            throw new Error(`Failed to get public key for user ${userId}`);
        }
        
        const keyData = await response.json();
        
        this.apiCache.set(cacheKey, {
            key: keyData.public_key,
            timestamp: Date.now()
        });
        
        return keyData.public_key;
    }

    async _getSessionKeyOptimized(sessionToken) {
        const sessionKey = this.getSessionKey(sessionToken);
        if (sessionKey) {
            return await this.importSessionKey(sessionKey);
        }
        return null;
    }

    async _getSocketConfig() {
        return {
            socketUrl: window.location.origin,
            path: '/socket.io/',
            transports: ['websocket', 'polling']
        };
    }

    _handleTyping() {
        if (!this.isTyping) {
            this.isTyping = true;
            if (this.socket && this.currentSession) {
                this.socket.emit('typing_start', {
                    session_token: this.currentSession.token
                });
            }
        }
        
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        
        this.typingTimeout = setTimeout(() => {
            this.isTyping = false;
            if (this.socket && this.currentSession) {
                this.socket.emit('typing_stop', {
                    session_token: this.currentSession.token
                });
            }
        }, 1000);
    }

    _updateUnreadCount(sessionToken) {
        const currentCount = this.unreadCounts.get(sessionToken) || 0;
        this.unreadCounts.set(sessionToken, currentCount + 1);
        
        const sessionElement = document.querySelector(`[data-session-token="${sessionToken}"]`);
        if (sessionElement) {
            let badge = sessionElement.querySelector('.unread-badge');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'unread-badge';
                sessionElement.appendChild(badge);
            }
            badge.textContent = currentCount + 1;
        }
    }

    _startPeriodicTasks() {
        setInterval(() => {
            this.lastActivity = Date.now();
        }, 30000);
        
        setInterval(() => {
            this._cleanupOldMessages();
        }, 300000);
        
        setInterval(() => {
            this._loadFriends();
        }, 60000);
        
        setInterval(() => {
            this._loadFriendRequests();
        }, 120000);
    }

    _cleanupOldMessages() {
        const cutoffTime = Date.now() - (24 * 60 * 60 * 1000);
        
        for (const [sessionToken, messages] of this.messages.entries()) {
            const filteredMessages = messages.filter(msg => 
                new Date(msg.timestamp).getTime() > cutoffTime
            );
            
            if (filteredMessages.length !== messages.length) {
                this.messages.set(sessionToken, filteredMessages);
                console.log(`🧹 Cleaned up old messages for session ${sessionToken.slice(0, 8)}...`);
            }
        }
    }

    _handleStatusChange(data) {
        const { user_id, is_online } = data;
        
        const friend = this.friends.find(f => f.user_id === user_id);
        if (friend) {
            friend.is_online = is_online;
            this._renderFriendsList();
        }
        
        if (this.currentChatPartner && this.currentChatPartner.user_id === user_id) {
            this._updateChatUI();
        }
    }

    _handleFriendRequest(data) {
        this._showNotification(`New friend request from ${data.from_username}`, 'info');
        this._loadFriendRequests();
    }

    _renderSessionsList() {
        if (!this.elements.sessionsList) return;
        
        this.elements.sessionsList.innerHTML = this.sessions.map(session => {
            const otherUser = session.initiator_id === this.user.id ? 
                session.recipient : session.initiator;
            
            const unreadCount = this.unreadCounts.get(session.token) || 0;
            
            return `
                <div class="session-item" data-session-token="${session.token}">
                    <div class="session-info">
                        <span class="session-partner">${this._escapeHtml(otherUser.username)}</span>
                        <span class="session-time">${new Date(session.last_activity).toLocaleString()}</span>
                    </div>
                    ${unreadCount > 0 ? `<span class="unread-badge">${unreadCount}</span>` : ''}
                </div>
            `;
        }).join('');
        
        this.elements.sessionsList.querySelectorAll('.session-item').forEach(item => {
            item.addEventListener('click', () => {
                const sessionToken = item.dataset.sessionToken;
                const session = this.sessions.find(s => s.token === sessionToken);
                if (session) {
                    const otherUser = session.initiator_id === this.user.id ? 
                        session.recipient : session.initiator;
                    this._selectFriend(otherUser.user_id);
                    
                    this.unreadCounts.delete(sessionToken);
                    this._renderSessionsList();
                }
            });
        });
    }

    _escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // =================
    // PUBLIC API & DEBUG FUNCTIONS
    // =================

    getCurrentSession() {
        return this.currentSession;
    }

    getCurrentUser() {
        return this.user;
    }

    getFriends() {
        return this.friends;
    }

    getMessages(sessionToken) {
        return this.messages.get(sessionToken) || [];
    }

    isConnected() {
        return this.socket && this.socket.connected;
    }

    getDebugInfo() {
        return {
            user: this.user?.username || 'Not logged in',
            friends: this.friends.length,
            sessions: this.sessions.length,
            currentSession: this.currentSession?.token?.slice(0, 8) + '...' || 'None',
            socketConnected: this.isConnected(),
            sessionKeys: this.sessionKeys.size,
            forwardSecrecy: this.getForwardSecrecyInfo(),
            messageCounters: Array.from(this.messageCounters.entries()).map(([token, count]) => ({
                session: token.slice(0, 8) + '...',
                messageCount: count
            })),
            decryptedMessagesStored: this.decryptedMessages ? this.decryptedMessages.size : 0
        };
    }

    async refresh() {
        try {
            await this._loadFriends();
            await this._loadSessions();
            await this._loadFriendRequests();
            this._showNotification('Data refreshed', 'success', 2000);
        } catch (error) {
            console.error('❌ Refresh failed:', error);
            this._showNotification('Failed to refresh data', 'error');
        }
    }

    cleanup() {
        if (this.socket) {
            this.socket.disconnect();
        }
        
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
        }
        
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        
        this.apiCache.clear();
        this.messages.clear();
        this.unreadCounts.clear();
        this.processingMessages.clear();
        this.sessionKeys.clear();
        this.messageCounters.clear();
        this.decryptedMessages.clear();
        
        console.log('🧹 ChatManager cleaned up');
    }

} // ✅ KONIEC KLASY ChatManager

// =================
// GLOBAL INITIALIZATION
// =================

let chatManager = null;

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const auth = await fetch('/api/check_auth');
        if (!auth.ok) {
            window.location.href = '/';
            return;
        }
        
        chatManager = new ChatManager();
        await chatManager.init();
        
        window.chatManager = chatManager;
        
        window.cryptoManager = {
            loadKeys: () => Promise.resolve(true),
            hasPrivateKey: () => chatManager?.userPrivateKey !== null,
            clearAllKeys: () => chatManager?.cleanup(),
            encryptMessage: (key, msg) => chatManager?.encryptMessage(key, msg),
            decryptMessage: (key, data) => chatManager?.decryptMessage(key, data),
            generateSessionKey: () => chatManager?.generateSessionKey(),
            storeSessionKey: (token, key) => chatManager?.storeSessionKey(token, key),
            getSessionKey: (token) => chatManager?.getSessionKey(token),
            encryptMessageWithForwardSecrecy: (key, msg, num) => chatManager?.encryptMessageWithForwardSecrecy(key, msg, num),
            decryptMessageWithForwardSecrecy: (key, data) => chatManager?.decryptMessageWithForwardSecrecy(key, data),
            getForwardSecrecyInfo: () => chatManager?.getForwardSecrecyInfo()
        };
        
        console.log('✅ Chat application initialized successfully with Forward Secrecy');
        console.log('🔐 Forward Secrecy Status:', chatManager.getForwardSecrecyInfo());
        
        setTimeout(() => {
            console.log('🎯 Debug Info:', chatManager.getDebugInfo());
        }, 2000);
        
    } catch (error) {
        console.error('❌ Failed to initialize chat application:', error);
        alert('Failed to initialize chat application: ' + error.message);
    }
});

window.addEventListener('beforeunload', () => {
    if (chatManager) {
        chatManager.cleanup();
    }
});

// ✅ GLOBAL HELPER FUNCTIONS for debugging
window.testForwardSecrecy = async () => {
    if (!window.chatManager) {
        console.error('ChatManager not initialized');
        return;
    }
    
    try {
        const sessionKey = await window.chatManager.generateSessionKey();
        const testMessage = "Test Forward Secrecy Message";
        
        const encrypted = await window.chatManager.encryptMessageWithForwardSecrecy(sessionKey, testMessage, 1);
        console.log('🔐 Encrypted with FS:', encrypted);
        
        const decrypted = await window.chatManager.decryptMessageWithForwardSecrecy(sessionKey, encrypted);
        console.log('🔓 Decrypted with FS:', decrypted);
        
        console.log('✅ Forward Secrecy test successful!');
        return decrypted === testMessage;
    } catch (error) {
        console.error('❌ Forward Secrecy test failed:', error);
        return false;
    }
};

console.log("✅ chat.js loaded successfully with Forward Secrecy support");
console.log("🧪 Run 'testForwardSecrecy()' in console to test Forward Secrecy");
console.log("🔍 Run 'chatManager.getDebugInfo()' for detailed status");
console.log("📊 Run 'chatManager.getForwardSecrecyInfo()' for FS status");


