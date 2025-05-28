/**
 * crypto.js - NAPRAWIONY moduł kryptograficzny
 * 🚀 GŁÓWNE POPRAWKI: API zgodne z ChatManager, eksport globalny
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

  // === 🚀 NAPRAWIONE: SESSION KEY ENCRYPTION/DECRYPTION ===
  async encryptSessionKey(sessionKey, recipientPublicKeyPEM) {
    try {
      // Import recipient's public key
      const publicKey = await this.importPublicKeyFromPEM(recipientPublicKeyPEM);
      
      // Export session key to raw format
      const rawKey = await this.crypto.exportKey("raw", sessionKey);
      
      // Encrypt with recipient's public key
      const encrypted = await this.crypto.encrypt(
        { name: "RSA-OAEP" }, publicKey, rawKey
      );
      
      return this._arrayBufferToBase64(encrypted);
    } catch (error) {
      console.error("❌ Session key encryption failed:", error);
      throw error;
    }
  }

  async decryptSessionKey(encryptedKeyBase64) {
    try {
      if (!this.privateKey) throw new Error("No private key available");
      
      const data = this._base64ToArrayBuffer(encryptedKeyBase64);
      const decrypted = await this.crypto.decrypt(
        { name: "RSA-OAEP" }, this.privateKey, data
      );
      
      // Import decrypted key as session key
      const sessionKey = await this.crypto.importKey(
        "raw", decrypted,
        { name: "AES-GCM", length: 256 },
        true, ["encrypt", "decrypt"]
      );
      
      return sessionKey;
    } catch (error) {
      console.error("❌ Session key decryption failed:", error);
      throw error;
    }
  }

  // === 🚀 NAPRAWIONE: MESSAGE ENCRYPTION/DECRYPTION - API ZGODNE Z CHATMANAGER ===
  async encryptMessage(message, sessionToken) {
    try {
      console.log("🔐 Encrypting message for session:", sessionToken?.substring(0, 8));
      
      // Get session key
      const sessionKey = await this.getSessionKey(sessionToken);
      if (!sessionKey) {
        throw new Error("No session key available for token: " + sessionToken);
      }
      
      // 🚀 VALIDATE: Ensure sessionKey is a CryptoKey object
      if (!(sessionKey instanceof CryptoKey)) {
        console.error("❌ Session key is not a CryptoKey object:", typeof sessionKey);
        throw new Error("Session key is not a valid CryptoKey object");
      }
      
      console.log("✅ Valid CryptoKey obtained for encryption");
      
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(message);
      
      const encrypted = await this.crypto.encrypt(
        { name: "AES-GCM", iv: iv }, sessionKey, encoded
      );

      return {
        content: this._arrayBufferToBase64(encrypted),
        iv: this._arrayBufferToBase64(iv)
      };
    } catch (error) {
      console.error("❌ Message encryption failed:", error);
      console.error("❌ Error details:", {
        message: error.message,
        stack: error.stack,
        sessionToken: sessionToken?.substring(0, 8)
      });
      throw error;
    }
  }

  async decryptMessage(encryptedContent, ivBase64, sessionToken) {
    try {
      console.log("🔓 Decrypting message for session:", sessionToken?.substring(0, 8));
      
      // Get session key
      const sessionKey = await this.getSessionKey(sessionToken);
      if (!sessionKey) {
        throw new Error("No session key available for token: " + sessionToken);
      }
      
      // 🚀 VALIDATE: Ensure sessionKey is a CryptoKey object
      if (!(sessionKey instanceof CryptoKey)) {
        console.error("❌ Session key is not a CryptoKey object:", typeof sessionKey);
        throw new Error("Session key is not a valid CryptoKey object");
      }
      
      console.log("✅ Valid CryptoKey obtained for decryption");
      
      const iv = this._base64ToArrayBuffer(ivBase64);
      const data = this._base64ToArrayBuffer(encryptedContent);
      
      const decrypted = await this.crypto.decrypt(
        { name: "AES-GCM", iv: iv }, sessionKey, data
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error("❌ Message decryption failed:", error);
      console.error("❌ Error details:", {
        message: error.message,
        stack: error.stack,
        sessionToken: sessionToken?.substring(0, 8)
      });
      throw error;
    }
  }

  // === 🚀 NAPRAWIONE: SESSION KEY STORAGE ===
  async storeSessionKey(sessionToken, sessionKey) {
    try {
      console.log("💾 Storing session key for:", sessionToken?.substring(0, 8));
      
      // If sessionKey is a CryptoKey object, export it first
      let keyData;
      if (sessionKey instanceof CryptoKey) {
        const rawKey = await this.crypto.exportKey("raw", sessionKey);
        keyData = this._arrayBufferToBase64(rawKey);
      } else {
        keyData = sessionKey; // Already base64 string
      }
      
      const key = `session_key_${sessionToken}`;
      sessionStorage.setItem(key, keyData);
      
      // Also store the CryptoKey object in memory for faster access
      if (sessionKey instanceof CryptoKey) {
        this.sessionKeys.set(sessionToken, sessionKey);
      } else {
        // Import the key for memory storage
        const importedKey = await this.importSessionKey(keyData);
        this.sessionKeys.set(sessionToken, importedKey);
      }
      
      console.log(`🔑 Session key stored: ${sessionToken.slice(0, 8)}...`);
      return true;
    } catch (error) {
      console.error("❌ Session key storage failed:", error);
      return false;
    }
  }

  async getSessionKey(sessionToken) {
    try {
      // Check memory cache first (returns CryptoKey object)
      if (this.sessionKeys.has(sessionToken)) {
        console.log("🎯 Session key found in memory:", sessionToken?.substring(0, 8));
        return this.sessionKeys.get(sessionToken);
      }
      
      // Check sessionStorage (returns base64 string, need to import)
      const key = `session_key_${sessionToken}`;
      const sessionKeyBase64 = sessionStorage.getItem(key);
      if (sessionKeyBase64) {
        console.log("💾 Session key found in storage, importing:", sessionToken?.substring(0, 8));
        try {
          const sessionKey = await this.importSessionKey(sessionKeyBase64);
          this.sessionKeys.set(sessionToken, sessionKey);
          console.log("✅ Session key imported successfully");
          return sessionKey;
        } catch (importError) {
          console.error("❌ Failed to import session key:", importError);
          // Clear corrupted key
          sessionStorage.removeItem(key);
          this.sessionKeys.delete(sessionToken);
          return null;
        }
      }
      
      console.warn("❌ No session key found for:", sessionToken?.substring(0, 8));
      return null;
    } catch (error) {
      console.error("❌ Session key retrieval failed:", error);
      return null;
    }
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

  async hasSessionKey(sessionToken) {
    const sessionKey = await this.getSessionKey(sessionToken);
    return !!sessionKey;
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

// === 🚀 KRYTYCZNE: EKSPORT GLOBALNY ===
window.CryptoManager = CryptoManager; // Make class available globally
window.cryptoManager = new CryptoManager();
window.unifiedCrypto = window.cryptoManager; // Backward compatibility
window.chatCrypto = window.cryptoManager;     // Backward compatibility

console.log("🔒 Crypto module loaded:", window.cryptoManager.getSecurityInfo());
