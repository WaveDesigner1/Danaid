class CryptoManager {
    constructor() {
        this.privateKey = null;
        this.publicKey = null;
        this.sessionKeys = new Map(); // In-memory session key cache
        this.keyCache = new Map(); // Public key cache
    }

    // =================
    // KEY GENERATION AND IMPORT
    // =================

    async generateKeyPair() {
        return await crypto.subtle.generateKey({
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        }, true, ["encrypt", "decrypt"]);
    }

    async generateSessionKey() {
        return await crypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256
        }, true, ["encrypt", "decrypt"]);
    }

    async loadKeys() {
        const privateKeyPEM = sessionStorage.getItem('private_key_pem');
        if (privateKeyPEM) {
            try {
                this.privateKey = await this.importPrivateKey(privateKeyPEM);
                console.log("✅ Private key loaded successfully");
                return true;
            } catch (error) {
                console.error("❌ Failed to load private key:", error);
                return false;
            }
        }
        return false;
    }

    async importPrivateKey(pemData) {
        const binaryData = this._pemToBinary(pemData);
        return await crypto.subtle.importKey(
            "pkcs8",
            binaryData,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );
    }

    async importSigningKey(pemData) {
        const binaryData = this._pemToBinary(pemData);
        return await crypto.subtle.importKey(
            "pkcs8",
            binaryData,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["sign"]
        );
    }

    async importPublicKeyFromPEM(pemData) {
        // Cache check
        const cacheKey = this._hashString(pemData);
        if (this.keyCache.has(cacheKey)) {
            return this.keyCache.get(cacheKey);
        }

        const binaryData = this._pemToBinary(pemData);
        const publicKey = await crypto.subtle.importKey(
            "spki",
            binaryData,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
        );

        // Cache for future use
        this.keyCache.set(cacheKey, publicKey);
        return publicKey;
    }

    // =================
    // DUAL ENCRYPTION FOR MULTIPLE USERS - NEW
    // =================

    async encryptSessionKeyForMultipleUsers(recipients, sessionKey) {
        const encryptedKeys = {};
        const sessionKeyRaw = await crypto.subtle.exportKey("raw", sessionKey);
        
        for (const [userId, publicKeyPem] of Object.entries(recipients)) {
            try {
                const publicKey = await this.importPublicKeyFromPEM(publicKeyPem);
                const encrypted = await crypto.subtle.encrypt(
                    { name: "RSA-OAEP" },
                    publicKey,
                    sessionKeyRaw
                );
                encryptedKeys[userId] = this._arrayBufferToBase64(encrypted);
                console.log(`🔐 Session key encrypted for user ${userId}`);
            } catch (error) {
                console.error(`❌ Failed to encrypt key for user ${userId}:`, error);
                throw new Error(`Key encryption failed for user ${userId}: ${error.message}`);
            }
        }
        
        return encryptedKeys;
    }

    async verifyDualEncryption(encryptedKeys, originalSessionKey) {
        if (!this.privateKey) {
            console.warn("⚠️ Cannot verify - no private key loaded");
            return false;
        }
        
        const originalKeyRaw = await crypto.subtle.exportKey("raw", originalSessionKey);
        const originalKeyBase64 = this._arrayBufferToBase64(originalKeyRaw);
        
        // Try to decrypt our own encrypted key  
        const currentUserId = sessionStorage.getItem('user_id');
        const ourEncryptedKey = encryptedKeys[currentUserId];
        
        if (!ourEncryptedKey) {
            console.warn("⚠️ No encrypted key found for current user");
            return false;
        }
        
        try {
            const decryptedKeyBase64 = await this.decryptSessionKey(ourEncryptedKey);
            const matches = decryptedKeyBase64 === originalKeyBase64;
            
            console.log(`🔍 Dual encryption verification: ${matches ? 'PASS' : 'FAIL'}`);
            return matches;
            
        } catch (error) {
            console.error("❌ Dual encryption verification failed:", error);
            return false;
        }
    }

    // =================
    // SESSION KEY MANAGEMENT
    // =================

    async exportSessionKey(sessionKey) {
        const rawKey = await crypto.subtle.exportKey("raw", sessionKey);
        return this._arrayBufferToBase64(rawKey);
    }

    async importSessionKey(sessionKeyBase64) {
        const rawKey = this._base64ToArrayBuffer(sessionKeyBase64);
        return await crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );
    }

    storeSessionKey(sessionToken, sessionKeyBase64) {
        sessionStorage.setItem(`session_key_${sessionToken}`, sessionKeyBase64);
        // Also store in memory cache for performance
        this.sessionKeys.set(sessionToken, sessionKeyBase64);
    }

    getSessionKey(sessionToken) {
        // Check memory cache first
        if (this.sessionKeys.has(sessionToken)) {
            return this.sessionKeys.get(sessionToken);
        }
        
        // Check sessionStorage
        const key = sessionStorage.getItem(`session_key_${sessionToken}`);
        if (key) {
            this.sessionKeys.set(sessionToken, key); // Cache it
        }
        return key;
    }

    removeSessionKey(sessionToken) {
        sessionStorage.removeItem(`session_key_${sessionToken}`);
        this.sessionKeys.delete(sessionToken);
    }

    // =================
    // RSA ENCRYPTION/DECRYPTION
    // =================

    async encryptSessionKey(publicKey, sessionKey) {
        const sessionKeyRaw = await crypto.subtle.exportKey("raw", sessionKey);
        const encrypted = await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            sessionKeyRaw
        );
        return this._arrayBufferToBase64(encrypted);
    }

    async decryptSessionKey(encryptedKeyBase64) {
        if (!this.privateKey) {
            throw new Error('Private key not loaded');
        }
        
        const encryptedData = this._base64ToArrayBuffer(encryptedKeyBase64);
        const decryptedKey = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            this.privateKey,
            encryptedData
        );
        
        return this._arrayBufferToBase64(decryptedKey);
    }

    // =================
    // MESSAGE ENCRYPTION/DECRYPTION
    // =================

    async encryptMessage(sessionKey, message) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(message);
        
        const encrypted = await crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: iv
        }, sessionKey, encoded);

        return {
            iv: this._arrayBufferToBase64(iv),
            data: this._arrayBufferToBase64(encrypted)
        };
    }

    async decryptMessage(sessionKey, encryptedMsg) {
        const iv = this._base64ToArrayBuffer(encryptedMsg.iv);
        const data = this._base64ToArrayBuffer(encryptedMsg.data);
        
        const decrypted = await crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: iv
        }, sessionKey, data);
        
        return new TextDecoder().decode(decrypted);
    }

    // =================
    // DIGITAL SIGNATURES
    // =================

    async signData(privateKey, data) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        
        return await crypto.subtle.sign(
            "RSASSA-PKCS1-v1_5",
            privateKey,
            encodedData
        );
    }

    async verifySignature(publicKey, signature, data) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        
        return await crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            publicKey,
            signature,
            encodedData
        );
    }

    // =================
    // KEY EXPORT FOR DOWNLOAD
    // =================

    async exportPublicKey(keyPair) {
        const exported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        return this._arrayBufferToPEM(exported, 'PUBLIC KEY');
    }

    async exportPrivateKey(keyPair) {
        const exported = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        return this._arrayBufferToPEM(exported, 'PRIVATE KEY');
    }

    // =================
    // SECURITY AND CLEANUP - ENHANCED
    // =================

    clearAllKeys() {
        try {
            console.log("🧹 CryptoManager: Clearing all encryption data");
            
            // Clear session keys from sessionStorage
            const sessionKeys = [];
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                if (key && key.startsWith('session_key_')) {
                    sessionKeys.push(key);
                }
            }
            
            sessionKeys.forEach(key => {
                sessionStorage.removeItem(key);
                console.log(`   Cleared: ${key}`);
            });
            
            // Clear private key and user data
            sessionStorage.removeItem('private_key_pem');
            sessionStorage.removeItem('user_id');
            sessionStorage.removeItem('username');
            sessionStorage.removeItem('is_admin');
            
            // Clear in-memory references
            this.privateKey = null;
            this.publicKey = null;
            this.sessionKeys.clear();
            this.keyCache.clear();
            
            console.log(`✅ CryptoManager: Cleared ${sessionKeys.length} session keys + private key + cache`);
            
        } catch (error) {
            console.error("❌ Error clearing crypto data:", error);
            
            // Force clear sessionStorage as fallback
            try {
                sessionStorage.clear();
                console.log("🧹 Fallback: Cleared entire sessionStorage");
            } catch (e) {
                console.error("❌ Even fallback clear failed:", e);
            }
        }
    }

    getPostLogoutSecurityStatus() {
        const hasPrivateKey = !!sessionStorage.getItem('private_key_pem');
        const sessionKeyCount = Object.keys(sessionStorage).filter(k => 
            k.startsWith('session_key_')
        ).length;
        
        return {
            secure: !hasPrivateKey && sessionKeyCount === 0,
            private_key_cleared: !hasPrivateKey,
            session_keys_cleared: sessionKeyCount === 0,
            remaining_session_keys: sessionKeyCount,
            memory_cache_cleared: this.sessionKeys.size === 0,
            key_cache_cleared: this.keyCache.size === 0
        };
    }

    // =================
    // UTILITY AND VALIDATION
    // =================

    hasPrivateKey() {
        return !!this.privateKey;
    }

    getSecurityInfo() {
        return {
            hasPrivateKey: this.hasPrivateKey(),
            sessionKeyCount: this.sessionKeys.size,
            keyCache: this.keyCache.size,
            algorithms: {
                asymmetric: 'RSA-OAEP-2048',
                symmetric: 'AES-GCM-256',
                hash: 'SHA-256',
                signature: 'RSASSA-PKCS1-v1_5'
            },
            securityLevel: 'High'
        };
    }

    validateKeyPair(keyPair) {
        return !!(keyPair && keyPair.publicKey && keyPair.privateKey);
    }

    // =================
    // PRIVATE UTILITY FUNCTIONS
    // =================

    _arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    _base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    _pemToBinary(pem) {
        const lines = pem.split('\n');
        const base64 = lines.slice(1, -1).join('').replace(/\s/g, '');
        return this._base64ToArrayBuffer(base64);
    }

    _arrayBufferToPEM(buffer, label) {
        const base64 = this._arrayBufferToBase64(buffer);
        const chunks = base64.match(/.{1,64}/g) || [];
        return `-----BEGIN ${label}-----\n${chunks.join('\n')}\n-----END ${label}-----`;
    }

    _hashString(str) {
        // Simple hash for caching keys (not cryptographic)
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString();
    }

    // =================
    // PERFORMANCE OPTIMIZATION
    // =================

    optimizePerformance() {
        // Clean up old cached keys periodically
        if (this.keyCache.size > 100) {
            this.keyCache.clear();
            console.log("🧹 Cleaned up key cache for performance");
        }
        
        // Limit session key cache size
        if (this.sessionKeys.size > 50) {
            const entries = Array.from(this.sessionKeys.entries());
            const toKeep = entries.slice(-25); // Keep most recent 25
            this.sessionKeys.clear();
            toKeep.forEach(([key, value]) => {
                this.sessionKeys.set(key, value);
            });
            console.log("🧹 Optimized session key cache");
        }
    }

    // =================
    // DEBUGGING HELPERS (development only)
    // =================

    debugInfo() {
        if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
            return 'Debug info only available in development';
        }

        return {
            crypto: {
                hasPrivateKey: this.hasPrivateKey(),
                sessionKeys: Array.from(this.sessionKeys.keys()),
                keyCache: this.keyCache.size,
                webCryptoAvailable: !!(window.crypto && window.crypto.subtle)
            },
            storage: {
                sessionStorageKeys: Object.keys(sessionStorage).filter(k => 
                    k.startsWith('session_key_') || k === 'private_key_pem'
                ),
                totalSessionStorageSize: JSON.stringify(sessionStorage).length
            },
            performance: {
                memoryCacheHits: 'Not tracked in current implementation',
                averageEncryptionTime: 'Not tracked in current implementation'
            }
        };
    }
}// Global initialization when script loads
if (typeof window !== 'undefined') {
    // Auto-initialize crypto manager
    window.addEventListener('DOMContentLoaded', () => {
        if (!window.cryptoManager) {
            window.cryptoManager = new CryptoManager();
            console.log('✅ CryptoManager auto-initialized');
        }
    });
    
    // Performance optimization - run cleanup periodically
    setInterval(() => {
        if (window.cryptoManager) {
            window.cryptoManager.optimizePerformance();
        }
    }, 300000); // Every 5 minutes
    
    // Security cleanup on page visibility change
    document.addEventListener('visibilitychange', () => {
        if (document.hidden && window.cryptoManager) {
            // Page is hidden - good time to optimize
            window.cryptoManager.optimizePerformance();
        }
    });
}
