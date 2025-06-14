/**
 * CryptoManager.js - Unified Crypto Interface - FIXED VERSION
 * Signal-inspired: wraps existing crypto.js, provides clean API
 * POPRAWKI: Web Crypto validation, better error handling, thread-safe counters
 */

class CryptoManager {
    constructor() {
        this.sessionKeys = new Map();
        this.messageCounters = new Map();
        this.forwardSecrecyEnabled = true;
        this.cryptoSystem = null;
        this.userPrivateKey = null;
        this.isInitialized = false;
        
        // POPRAWKA: Sprawdź dostępność Web Crypto API od razu
        if (!this.isWebCryptoAvailable()) {
            console.error('Web Crypto API not available in this browser');
            // Nie rzucaj błędu tutaj - pozwól na graceful degradation
        }
    }

    // POPRAWKA: Sprawdzenie Web Crypto API
    isWebCryptoAvailable() {
        return typeof window !== 'undefined' && 
               window.crypto && 
               window.crypto.subtle &&
               typeof window.crypto.subtle.encrypt === 'function' &&
               typeof window.crypto.subtle.decrypt === 'function' &&
               typeof window.crypto.subtle.generateKey === 'function';
    }

    // POPRAWKA: Ulepszona inicjalizacja crypto systemu
    async initializeCrypto() {
        try {
            // Sprawdź dostępność Web Crypto
            if (!this.isWebCryptoAvailable()) {
                console.warn('Web Crypto API not supported - crypto features will be limited');
                // Nie przerywaj - pozwól na działanie bez crypto
                this.isInitialized = false;
                return false;
            }

            // POPRAWKA: Lepsze wykrywanie zewnętrznych systemów crypto
            if (typeof window !== 'undefined') {
                if (window.cryptoSystem && typeof window.cryptoSystem.initialize === 'function') {
                    console.log('Found existing cryptoSystem');
                    this.cryptoSystem = window.cryptoSystem;
                    try {
                        await this.cryptoSystem.initialize();
                    } catch (error) {
                        console.warn('External crypto system initialization failed:', error);
                        this.cryptoSystem = null;
                    }
                } else if (typeof window.HybridCrypto === 'function') {
                    console.log('Found HybridCrypto constructor');
                    try {
                        this.cryptoSystem = new window.HybridCrypto();
                        if (typeof this.cryptoSystem.initialize === 'function') {
                            await this.cryptoSystem.initialize();
                        }
                    } catch (error) {
                        console.warn('HybridCrypto initialization failed:', error);
                        this.cryptoSystem = null;
                    }
                } else {
                    console.log('No external crypto system found, using Web Crypto API only');
                }
            }

            // POPRAWKA: Test podstawowej funkcjonalności
            await this.testBasicCrypto();
            
            this.isInitialized = true;
            console.log('CryptoManager initialized successfully');
            
            // Event bus notification (jeśli dostępny)
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_SYSTEM_READY);
            }
            
            return true;
            
        } catch (error) {
            console.error('Crypto initialization failed:', error);
            this.isInitialized = false;
            
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            
            // Nie rzucaj błędu - pozwól aplikacji działać bez crypto
            return false;
        }
    }

    // POPRAWKA: Test podstawowej funkcjonalności crypto
    async testBasicCrypto() {
        try {
            const key = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );
            
            const testData = new TextEncoder().encode("test");
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                key,
                testData
            );
            
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                encrypted
            );
            
            const result = new TextDecoder().decode(decrypted);
            if (result !== "test") {
                throw new Error('Crypto test failed - decryption mismatch');
            }
            
            return true;
            
        } catch (error) {
            throw new Error(`Basic crypto test failed: ${error.message}`);
        }
    }

    // Generate RSA key pair
    async generateKeyPair() {
        try {
            if (!this.isInitialized) {
                const initResult = await this.initializeCrypto();
                if (!initResult) {
                    throw new Error('Crypto system not available');
                }
            }

            // POPRAWKA: Lepsze wykorzystanie zewnętrznego systemu
            if (this.cryptoSystem) {
                // Sprawdź różne możliwe metody
                if (typeof this.cryptoSystem.generateKeyPair === 'function') {
                    const result = await this.cryptoSystem.generateKeyPair();
                    if (result && result.publicKey && result.privateKey) {
                        return result;
                    }
                } else if (typeof this.cryptoSystem.getPublicKeyPEM === 'function' && 
                          typeof this.cryptoSystem.getPrivateKeyPEM === 'function') {
                    const publicKey = await this.cryptoSystem.getPublicKeyPEM();
                    const privateKey = await this.cryptoSystem.getPrivateKeyPEM();
                    if (publicKey && privateKey) {
                        return { publicKey, privateKey };
                    }
                }
            }

            // Fallback do Web Crypto API
            console.log('Generating RSA key pair using Web Crypto API...');
            
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );

            const publicKey = await this.exportPublicKeyToPEM(keyPair.publicKey);
            const privateKey = await this.exportPrivateKeyToPEM(keyPair.privateKey);

            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_KEY_GENERATED, { publicKey });
            }

            return { publicKey, privateKey };
            
        } catch (error) {
            console.error('Key generation failed:', error);
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // POPRAWKA: Dodane helper methods dla eksportu kluczy
    async exportPublicKeyToPEM(key) {
        const exported = await crypto.subtle.exportKey("spki", key);
        const base64 = this.arrayBufferToBase64(exported);
        return `-----BEGIN PUBLIC KEY-----\n${this.formatPEM(base64)}\n-----END PUBLIC KEY-----`;
    }

    async exportPrivateKeyToPEM(key) {
        const exported = await crypto.subtle.exportKey("pkcs8", key);
        const base64 = this.arrayBufferToBase64(exported);
        return `-----BEGIN PRIVATE KEY-----\n${this.formatPEM(base64)}\n-----END PRIVATE KEY-----`;
    }

    formatPEM(base64) {
        return base64.match(/.{1,64}/g).join('\n');
    }

    // Load private key
    async loadPrivateKey(privateKeyPEM) {
        try {
            this.userPrivateKey = privateKeyPEM;
            
            // Store in session for compatibility
            if (typeof sessionStorage !== 'undefined') {
                sessionStorage.setItem('user_private_key_pem', privateKeyPEM);
            }
            
            return true;
            
        } catch (error) {
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // Generate session key
    async generateSessionKey() {
        try {
            if (!this.isInitialized) {
                const initResult = await this.initializeCrypto();
                if (!initResult) {
                    throw new Error('Crypto system not available');
                }
            }

            // POPRAWKA: Sprawdź czy external crypto ma metodę generateSessionKey
            if (this.cryptoSystem && typeof this.cryptoSystem.aes === 'object' && 
                typeof this.cryptoSystem.aes.generateSessionKey === 'function') {
                const sessionKey = await this.cryptoSystem.aes.generateSessionKey();
                if (sessionKey) {
                    if (typeof eventBus !== 'undefined' && eventBus.emit) {
                        eventBus.emit(Events.CRYPTO_KEY_GENERATED, { type: 'session' });
                    }
                    return sessionKey;
                }
            }
            
            // Fallback do Web Crypto API
            const sessionKey = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
            
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_KEY_GENERATED, { type: 'session' });
            }
            
            return sessionKey;
            
        } catch (error) {
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // Export session key
    async exportSessionKey(sessionKey) {
        try {
            const keyBuffer = await crypto.subtle.exportKey("raw", sessionKey);
            return this.arrayBufferToBase64(keyBuffer);
        } catch (error) {
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw new Error(`Session key export failed: ${error.message}`);
        }
    }

    // Import session key
    async importSessionKey(keyBase64) {
        try {
            const keyBuffer = this.base64ToArrayBuffer(keyBase64);
            return await crypto.subtle.importKey(
                "raw", 
                keyBuffer,
                { name: "AES-GCM", length: 256 },
                false, 
                ["encrypt", "decrypt"]
            );
        } catch (error) {
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw new Error(`Session key import failed: ${error.message}`);
        }
    }

    // Store session key
    storeSessionKey(sessionToken, keyBase64) {
        this.sessionKeys.set(sessionToken, keyBase64);
        if (typeof eventBus !== 'undefined' && eventBus.emit) {
            eventBus.emit(Events.CRYPTO_KEY_STORED, { sessionToken });
        }
    }

    // Get session key
    async getSessionKey(sessionToken) {
        const keyBase64 = this.sessionKeys.get(sessionToken);
        if (!keyBase64) return null;
        
        try {
            return await this.importSessionKey(keyBase64);
        } catch (error) {
            console.error('Failed to import stored session key:', error);
            this.sessionKeys.delete(sessionToken);
            throw error;
        }
    }

    // Remove session key
    removeSessionKey(sessionToken) {
        return this.sessionKeys.delete(sessionToken);
    }

    // Encrypt session key for multiple users
    async encryptSessionKeyForUsers(recipients, sessionKey) {
        try {
            const sessionKeyBase64 = await this.exportSessionKey(sessionKey);
            const sessionKeyBuffer = this.base64ToArrayBuffer(sessionKeyBase64);
            const encryptedKeys = {};
            
            for (const [userId, publicKeyPEM] of Object.entries(recipients)) {
                try {
                    const publicKey = await this.importPublicKey(publicKeyPEM);
                    const encrypted = await crypto.subtle.encrypt(
                        { name: "RSA-OAEP" },
                        publicKey,
                        sessionKeyBuffer
                    );
                    encryptedKeys[userId] = this.arrayBufferToBase64(encrypted);
                } catch (error) {
                    console.error(`Failed to encrypt key for user ${userId}:`, error);
                }
            }
            
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_KEY_EXCHANGED, { recipients: Object.keys(encryptedKeys) });
            }
            
            return encryptedKeys;
            
        } catch (error) {
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // Decrypt session key
    async decryptSessionKey(encryptedKeyBase64) {
        try {
            if (!this.userPrivateKey) {
                throw new Error('No private key loaded');
            }
            
            const privateKey = await this.importPrivateKey(this.userPrivateKey);
            const encryptedKey = this.base64ToArrayBuffer(encryptedKeyBase64);
            
            const decrypted = await crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privateKey,
                encryptedKey
            );
            
            return this.arrayBufferToBase64(decrypted);
            
        } catch (error) {
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // POPRAWKA: Thread-safe message counter
    getNextMessageNumber(sessionToken) {
        if (!this.messageCounters.has(sessionToken)) {
            this.messageCounters.set(sessionToken, 0);
        }
        
        // Atomowa operacja
        const current = this.messageCounters.get(sessionToken);
        const next = current + 1;
        this.messageCounters.set(sessionToken, next);
        
        return next;
    }

    // Forward secrecy: derive message key
    async deriveMessageKey(sessionKey, messageNumber, direction = 'send') {
        try {
            // POPRAWKA: Więcej entropii w salt
            const salt = new TextEncoder().encode(
                `danaid_msg_${messageNumber}_${direction}_v2`
            );
            
            let cryptoSessionKey = sessionKey;
            if (typeof sessionKey === 'string') {
                cryptoSessionKey = await this.importSessionKey(sessionKey);
            }
            
            const rawSessionKey = await crypto.subtle.exportKey("raw", cryptoSessionKey);
            
            const hkdfKey = await crypto.subtle.importKey(
                "raw", 
                rawSessionKey,
                { name: "HKDF" },
                false, 
                ["deriveKey"]
            );
            
            return await crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: salt,
                    info: new TextEncoder().encode("danaid-message-key-v2")
                },
                hkdfKey,
                { name: "AES-GCM", length: 256 },
                false, 
                ["encrypt", "decrypt"]
            );
            
        } catch (error) {
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // POPRAWKA: Ulepszone szyfrowanie z walidacją
    async encryptMessage(sessionKey, message, sessionToken = null, useForwardSecrecy = true) {
        try {
            if (!this.isInitialized) {
                const initResult = await this.initializeCrypto();
                if (!initResult) {
                    throw new Error('Crypto system not available');
                }
            }

            // POPRAWKA: Walidacja parametrów
            if (!sessionKey) {
                throw new Error('Session key is required');
            }
            
            if (!message || typeof message !== 'string') {
                throw new Error('Valid message content is required');
            }

            let messageKey = sessionKey;
            let messageNumber = null;
            
            // Use forward secrecy if enabled and session token provided
            if (this.forwardSecrecyEnabled && useForwardSecrecy && sessionToken) {
                messageNumber = this.getNextMessageNumber(sessionToken);
                messageKey = await this.deriveMessageKey(sessionKey, messageNumber, 'send');
            }
            
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                messageKey,
                data
            );
            
            const result = {
                data: this.arrayBufferToBase64(encrypted),
                iv: this.arrayBufferToBase64(iv.buffer),
                timestamp: Date.now()
            };
            
            if (messageNumber) {
                result.messageNumber = messageNumber;
                result.forwardSecrecy = true;
            }
            
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ENCRYPT_SUCCESS);
            }
            
            return result;
            
        } catch (error) {
            console.error('Encryption failed:', error);
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // POPRAWKA: Lepsze deszyfrowanie z obsługą błędów
    async decryptMessage(sessionKey, encryptedData, sessionToken = null) {
        try {
            if (!this.isInitialized) {
                const initResult = await this.initializeCrypto();
                if (!initResult) {
                    throw new Error('Crypto system not available');
                }
            }

            // POPRAWKA: Walidacja
            if (!sessionKey || !encryptedData) {
                throw new Error('Session key and encrypted data required');
            }

            if (!encryptedData.data || !encryptedData.iv) {
                throw new Error('Invalid encrypted data format');
            }

            let messageKey = sessionKey;
            
            // Use forward secrecy if message has the metadata
            if (this.forwardSecrecyEnabled && 
                encryptedData.forwardSecrecy && 
                encryptedData.messageNumber) {
                messageKey = await this.deriveMessageKey(
                    sessionKey, 
                    encryptedData.messageNumber, 
                    'send'
                );
            }
            
            const data = this.base64ToArrayBuffer(encryptedData.data);
            const iv = this.base64ToArrayBuffer(encryptedData.iv);
            
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                messageKey,
                data
            );
            
            const result = new TextDecoder().decode(decrypted);
            
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_DECRYPT_SUCCESS);
            }
            
            return result;
            
        } catch (error) {
            console.error('Decryption failed:', error);
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    // Sign password
    async signPassword(password, privateKeyPEM) {
        try {
            if (!this.isInitialized) {
                await this.initializeCrypto();
            }

            // POPRAWKA: Sprawdź czy zewnętrzny system ma tę funkcję
            if (this.cryptoSystem && typeof this.cryptoSystem.signPassword === 'function') {
                return await this.cryptoSystem.signPassword(password, privateKeyPEM);
            }
            
            // Fallback implementation using Web Crypto API
            const privateKey = await this.importPrivateKeyForSigning(privateKeyPEM);
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            
            const signature = await crypto.subtle.sign(
                "RSASSA-PKCS1-v1_5",
                privateKey,
                data
            );
            
            return this.arrayBufferToBase64(signature);
            
        } catch (error) {
            console.error('Password signing failed:', error);
            if (typeof eventBus !== 'undefined' && eventBus.emit) {
                eventBus.emit(Events.CRYPTO_ERROR, error.message);
            }
            throw error;
        }
    }

    // Import public key
    async importPublicKey(pemData) {
        try {
            const binaryData = this.pemToBinary(pemData);
            return await crypto.subtle.importKey(
                "spki", 
                binaryData,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false, 
                ["encrypt"]
            );
        } catch (error) {
            throw new Error(`Failed to import public key: ${error.message}`);
        }
    }

    // Import private key
    async importPrivateKey(pemData) {
        try {
            const binaryData = this.pemToBinary(pemData);
            return await crypto.subtle.importKey(
                "pkcs8", 
                binaryData,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false, 
                ["decrypt"]
            );
        } catch (error) {
            throw new Error(`Failed to import private key: ${error.message}`);
        }
    }

    // POPRAWKA: Dodana metoda dla klucza do podpisywania
    async importPrivateKeyForSigning(pemData) {
        try {
            const binaryData = this.pemToBinary(pemData);
            return await crypto.subtle.importKey(
                "pkcs8", 
                binaryData,
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                false, 
                ["sign"]
            );
        } catch (error) {
            throw new Error(`Failed to import private key for signing: ${error.message}`);
        }
    }

    // Utility functions
    pemToBinary(pem) {
        const lines = pem.split('\n');
        const base64 = lines.slice(1, -1).join('').replace(/\s/g, '');
        return this.base64ToArrayBuffer(base64);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // POPRAWKA: Ulepszone statystyki
    getStats() {
        return {
            initialized: this.isInitialized,
            webCryptoSupported: this.isWebCryptoAvailable(),
            sessionKeys: this.sessionKeys.size,
            messageCounters: this.messageCounters.size,
            forwardSecrecyEnabled: this.forwardSecrecyEnabled,
            hasPrivateKey: !!this.userPrivateKey,
            cryptoSystemReady: !!this.cryptoSystem,
            externalCryptoType: this.cryptoSystem ? 
                (this.cryptoSystem.constructor.name || 'external') : 'none'
        };
    }

    // Clear all crypto data
    clear() {
        this.sessionKeys.clear();
        this.messageCounters.clear();
        this.userPrivateKey = null;
        this.isInitialized = false;
        
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.removeItem('user_private_key_pem');
        }
        
        if (typeof eventBus !== 'undefined' && eventBus.emit) {
            eventBus.emit(Events.CRYPTO_CLEARED);
        }
    }

    // Enable/disable forward secrecy
    setForwardSecrecy(enabled) {
        this.forwardSecrecyEnabled = enabled;
        console.log(`Forward secrecy ${enabled ? 'enabled' : 'disabled'}`);
    }

    // POPRAWKA: Dodana metoda diagnostyczna
    async runDiagnostics() {
        const results = {
            webCrypto: this.isWebCryptoAvailable(),
            initialized: this.isInitialized,
            externalCrypto: !!this.cryptoSystem,
            canGenerateKeys: false,
            canEncryptDecrypt: false,
            hasPrivateKey: !!this.userPrivateKey
        };

        try {
            // Test key generation
            await this.generateSessionKey();
            results.canGenerateKeys = true;

            // Test encryption/decryption
            const key = await this.generateSessionKey();
            const encrypted = await this.encryptMessage(key, "test", "test_session", false);
            const decrypted = await this.decryptMessage(key, encrypted, "test_session");
            results.canEncryptDecrypt = (decrypted === "test");

        } catch (error) {
            console.warn('Diagnostics test failed:', error);
        }

        return results;
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoManager;
} else {
    window.CryptoManager = CryptoManager;
}

// Extend Events with crypto events (jeśli Events istnieje)
if (typeof Events !== 'undefined') {
    Object.assign(Events, {
        CRYPTO_SYSTEM_READY: 'crypto.systemReady',
        CRYPTO_KEY_STORED: 'crypto.keyStored',
        CRYPTO_CLEARED: 'crypto.cleared',
        CRYPTO_KEY_GENERATED: 'crypto.keyGenerated',
        CRYPTO_KEY_EXCHANGED: 'crypto.keyExchanged',
        CRYPTO_ENCRYPT_SUCCESS: 'crypto.encryptSuccess',
        CRYPTO_DECRYPT_SUCCESS: 'crypto.decryptSuccess',
        CRYPTO_ERROR: 'crypto.error'
    });
}

// POPRAWKA: Dodana globalna funkcja diagnostyczna
if (typeof window !== 'undefined') {
    window.testCrypto = async function() {
        console.log('🔧 Testing CryptoManager...');
        try {
            const crypto = new CryptoManager();
            const results = await crypto.runDiagnostics();
            console.table(results);
            
            const allPassed = Object.values(results).every(r => r === true);
            console.log(allPassed ? '✅ All crypto tests passed!' : '❌ Some crypto tests failed!');
            return results;
        } catch (error) {
            console.error('❌ Crypto test failed:', error);
            return { error: error.message };
        }
    };
    
    console.log('🧪 CryptoManager loaded. Run testCrypto() to diagnose.');
}