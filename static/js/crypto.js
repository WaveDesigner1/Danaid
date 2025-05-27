/**
 * crypto.js - Zoptymalizowany moduł kryptograficzny
 * Redukcja z 600 → 300 linii (usunięcie redundancji)
 * Tylko sessionStorage - maksymalne bezpieczeństwo
 */
class CryptoManager {
  constructor() {
    this.crypto = window.crypto.subtle;
    this.keys = new Map();
    this.sessionKeys = new Map();
    this.privateKey = null;
    this.publicKey = null;
    
    // Auto-load keys
    this.loadKeys();
    console.log("🔒 CryptoManager initialized (session-only mode)");
  }

  // === KEY MANAGEMENT ===
  async loadKeys() {
    const userId = sessionStorage.getItem('user_id');
    if (!userId) return false;

    try {
      // Load private key from sessionStorage
      const privateKeyPEM = sessionStorage.getItem('private_key_pem');
      if (privateKeyPEM) {
        this.privateKey = await this._importPrivateKey(privateKeyPEM);
        console.log("✅ Private key loaded");
      }

      // Load public key (cache first, then server)
      let publicKeyPEM = sessionStorage.getItem('user_public_key_pem');
      if (!publicKeyPEM) {
        const response = await fetch(`/api/user/${userId}/public_key`);
        if (response.ok) {
          const data = await response.json();
          publicKeyPEM = data.public_key;
          sessionStorage.setItem('user_public_key_pem', publicKeyPEM);
        }
      }
      
      if (publicKeyPEM) {
        this.publicKey = await this._importPublicKey(publicKeyPEM);
        console.log("✅ Public key loaded");
      }

      return !!(this.privateKey && this.publicKey);
    } catch (error) {
      console.error("❌ Key loading error:", error);
      return false;
    }
  }

  async _importPrivateKey(pem) {
    const pemContents = pem
      .replace(/-----BEGIN PRIVATE KEY-----/, "")
      .replace(/-----END PRIVATE KEY-----/, "")
      .replace(/\s+/g, "");
    
    const binaryDer = this._base64ToArrayBuffer(pemContents);
    
    return await this.crypto.importKey(
      "pkcs8", binaryDer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true, ["decrypt"]
    );
  }

  async _importPublicKey(pem) {
    const pemContents = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s+/g, "");
    
    const binaryDer = this._base64ToArrayBuffer(pemContents);
    
    return await this.crypto.importKey(
      "spki", binaryDer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true, ["encrypt"]
    );
  }

  async importPublicKeyFromPEM(pem) {
    return await this._importPublicKey(pem);
  }

  // === SESSION KEYS (AES-GCM) ===
  async generateSessionKey() {
    return await this.crypto.generateKey(
      { name: "AES-GCM", length: 256 },
      true, ["encrypt", "decrypt"]
    );
  }

  async exportSessionKey(sessionKey) {
    const rawKey = await this.crypto.exportKey("raw", sessionKey);
    return this._arrayBufferToBase64(rawKey);
  }

  async importSessionKey(base64Key) {
    const rawKey = this._base64ToArrayBuffer(base64Key);
    return await this.crypto.importKey(
      "raw", rawKey,
      { name: "AES-GCM", length: 256 },
      true, ["encrypt", "decrypt"]
    );
  }

  // === ENCRYPTION/DECRYPTION ===
  async encryptSessionKey(publicKey, sessionKey) {
    const rawKey = await this.crypto.exportKey("raw", sessionKey);
    const encrypted = await this.crypto.encrypt(
      { name: "RSA-OAEP" }, publicKey, rawKey
    );
    return this._arrayBufferToBase64(encrypted);
  }

  async decryptSessionKey(encryptedKey) {
    if (!this.privateKey) throw new Error("No private key available");
    
    const data = this._base64ToArrayBuffer(encryptedKey);
    const decrypted = await this.crypto.decrypt(
      { name: "RSA-OAEP" }, this.privateKey, data
    );
    return this._arrayBufferToBase64(decrypted);
  }

  async encryptMessage(sessionKey, message) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(message);
    
    const encrypted = await this.crypto.encrypt(
      { name: "AES-GCM", iv: iv }, sessionKey, encoded
    );

    return {
      iv: this._arrayBufferToBase64(iv),
      data: this._arrayBufferToBase64(encrypted)
    };
  }

  async decryptMessage(sessionKey, encryptedMsg) {
    const iv = this._base64ToArrayBuffer(encryptedMsg.iv);
    const data = this._base64ToArrayBuffer(encryptedMsg.data);
    
    const decrypted = await this.crypto.decrypt(
      { name: "AES-GCM", iv: iv }, sessionKey, data
    );

    return new TextDecoder().decode(decrypted);
  }

  // === SESSION KEY STORAGE ===
  storeSessionKey(sessionToken, sessionKeyBase64) {
    const key = `session_key_${sessionToken}`;
    sessionStorage.setItem(key, sessionKeyBase64);
    this.sessionKeys.set(sessionToken, sessionKeyBase64);
    console.log(`🔑 Session key stored: ${sessionToken.slice(0, 8)}...`);
    return true;
  }

  getSessionKey(sessionToken) {
    // Check memory cache first
    if (this.sessionKeys.has(sessionToken)) {
      return this.sessionKeys.get(sessionToken);
    }
    
    // Check sessionStorage
    const key = `session_key_${sessionToken}`;
    const sessionKey = sessionStorage.getItem(key);
    if (sessionKey) {
      this.sessionKeys.set(sessionToken, sessionKey);
      return sessionKey;
    }
    
    return null;
  }

  removeSessionKey(sessionToken) {
    const key = `session_key_${sessionToken}`;
    sessionStorage.removeItem(key);
    this.sessionKeys.delete(sessionToken);
    console.log(`🗑️ Session key removed: ${sessionToken.slice(0, 8)}...`);
    return true;
  }

  // === UTILITY METHODS ===
  hasPrivateKey() {
    return !!this.privateKey;
  }

  hasSessionKey(sessionToken) {
    return !!this.getSessionKey(sessionToken);
  }

  clearAllKeys() {
    // Clear sessionStorage
    sessionStorage.removeItem('private_key_pem');
    sessionStorage.removeItem('user_public_key_pem');
    
    // Clear session keys
    Object.keys(sessionStorage).forEach(key => {
      if (key.startsWith('session_key_')) {
        sessionStorage.removeItem(key);
      }
    });
    
    // Clear memory
    this.sessionKeys.clear();
    this.keys.clear();
    this.privateKey = null;
    this.publicKey = null;
    
    console.log("🧹 All keys cleared (session-only mode)");
    return true;
  }

  getSecurityInfo() {
    const sessionKeyCount = Object.keys(sessionStorage)
      .filter(k => k.startsWith('session_key_')).length;
    
    return {
      mode: 'session-only',
      description: 'Maximum security - keys cleared on browser close',
      sessionKeys: sessionKeyCount,
      hasPrivateKey: this.hasPrivateKey(),
      memoryKeys: this.sessionKeys.size
    };
  }

  // === HELPER METHODS ===
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
}

// Global instance with backward compatibility
window.cryptoManager = new CryptoManager();
window.unifiedCrypto = window.cryptoManager; // Backward compatibility
window.chatCrypto = window.cryptoManager;     // Backward compatibility

console.log("🔒 Crypto module loaded:", window.cryptoManager.getSecurityInfo());
