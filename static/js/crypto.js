/**
 * crypto.js - Zoptymalizowany moduł kryptograficzny z naprawionym RSA decryption
 * Redukcja z 600 → 300 linii (usunięcie redundancji)
 * Tylko sessionStorage - maksymalne bezpieczeństwo
 * NAPRAWIONO: RSA decryption error handling i debugging
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
    try {
      console.log("🔑 Importing private key...");
      const pemContents = pem
        .replace(/-----BEGIN PRIVATE KEY-----/, "")
        .replace(/-----END PRIVATE KEY-----/, "")
        .replace(/\s+/g, "");
      
      const binaryDer = this._base64ToArrayBuffer(pemContents);
      console.log("🔑 Private key DER length:", binaryDer.byteLength);
      
      const key = await this.crypto.importKey(
        "pkcs8", binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true, ["decrypt"]
      );
      
      console.log("✅ Private key imported successfully");
      return key;
    } catch (error) {
      console.error("❌ Private key import failed:", error);
      throw error;
    }
  }

  async _importPublicKey(pem) {
    try {
      console.log("🔑 Importing public key...");
      const pemContents = pem
        .replace(/-----BEGIN PUBLIC KEY-----/, "")
        .replace(/-----END PUBLIC KEY-----/, "")
        .replace(/\s+/g, "");
      
      const binaryDer = this._base64ToArrayBuffer(pemContents);
      console.log("🔑 Public key DER length:", binaryDer.byteLength);
      
      const key = await this.crypto.importKey(
        "spki", binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true, ["encrypt"]
      );
      
      console.log("✅ Public key imported successfully");
      return key;
    } catch (error) {
      console.error("❌ Public key import failed:", error);
      throw error;
    }
  }

  async importPublicKeyFromPEM(pem) {
    return await this._importPublicKey(pem);
  }

  // === SESSION KEYS (AES-GCM) ===
  async generateSessionKey() {
    console.log("🔑 Generating new AES session key...");
    const key = await this.crypto.generateKey(
      { name: "AES-GCM", length: 256 },
      true, ["encrypt", "decrypt"]
    );
    console.log("✅ AES session key generated");
    return key;
  }

  async exportSessionKey(sessionKey) {
    console.log("📤 Exporting session key to base64...");
    const rawKey = await this.crypto.exportKey("raw", sessionKey);
    const base64Key = this._arrayBufferToBase64(rawKey);
    console.log("✅ Session key exported, length:", base64Key.length);
    return base64Key;
  }

  async importSessionKey(base64Key) {
    console.log("📥 Importing session key from base64, length:", base64Key.length);
    try {
      const rawKey = this._base64ToArrayBuffer(base64Key);
      console.log("🔑 Raw key buffer length:", rawKey.byteLength);
      
      const key = await this.crypto.importKey(
        "raw", rawKey,
        { name: "AES-GCM", length: 256 },
        true, ["encrypt", "decrypt"]
      );
      
      console.log("✅ Session key imported successfully");
      return key;
    } catch (error) {
      console.error("❌ Session key import failed:", error);
      throw error;
    }
  }

  // === ENCRYPTION/DECRYPTION ===
  async encryptSessionKey(publicKey, sessionKey) {
    console.log("🔐 Encrypting session key with recipient's public key...");
    try {
      const rawKey = await this.crypto.exportKey("raw", sessionKey);
      console.log("🔑 Raw session key length:", rawKey.byteLength);
      
      const encrypted = await this.crypto.encrypt(
        { name: "RSA-OAEP" }, publicKey, rawKey
      );
      console.log("🔐 RSA encryption successful, result length:", encrypted.byteLength);
      
      const base64Result = this._arrayBufferToBase64(encrypted);
      console.log("✅ Session key encrypted, final length:", base64Result.length);
      return base64Result;
    } catch (error) {
      console.error("❌ Session key encryption failed:", error);
      throw error;
    }
  }

  // === NAPRAWIONE DESZYFROWANIE RSA ===
  async decryptSessionKey(encryptedKey) {
    console.log("🔓 decryptSessionKey called with key length:", encryptedKey.length);
    
    if (!this.privateKey) {
      throw new Error("No private key available");
    }
    
    try {
      console.log("🔓 Converting base64 to array buffer...");
      const data = this._base64ToArrayBuffer(encryptedKey);
      console.log("✅ Encrypted data buffer length:", data.byteLength);
      
      // Validate buffer size (RSA 2048-bit = 256 bytes encrypted)
      if (data.byteLength < 200 || data.byteLength > 512) {
        console.warn("⚠️ Unusual encrypted data size:", data.byteLength);
      }
      
      console.log("🔓 Attempting RSA decryption...");
      const decrypted = await this.crypto.decrypt(
        { name: "RSA-OAEP" }, 
        this.privateKey, 
        data
      );
      console.log("✅ RSA decryption successful, result length:", decrypted.byteLength);
      
      // Validate decrypted size (AES-256 key = 32 bytes)
      if (decrypted.byteLength !== 32) {
        console.warn("⚠️ Unexpected decrypted key size:", decrypted.byteLength, "expected: 32");
      }
      
      // Convert decrypted ArrayBuffer back to base64 (AES key format)
      const sessionKeyBase64 = this._arrayBufferToBase64(decrypted);
      console.log("✅ Session key converted to base64, length:", sessionKeyBase64.length);
      
      // Validate base64 format
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(sessionKeyBase64)) {
        throw new Error("Invalid base64 format in decrypted key");
      }
      
      return sessionKeyBase64;
      
    } catch (error) {
      console.error("❌ RSA decryption failed:", error);
      console.error("❌ Error details:", {
        name: error.name,
        message: error.message,
        stack: error.stack
      });
      
      // Additional debugging info
      console.error("🔍 Debug info:");
      console.error("- Private key available:", !!this.privateKey);
      console.error("- Encrypted key type:", typeof encryptedKey);
      console.error("- Encrypted key valid base64:", /^[A-Za-z0-9+/]+={0,2}$/.test(encryptedKey));
      console.error("- Encrypted key preview:", encryptedKey.slice(0, 50) + "...");
      
      throw new Error(`RSA decryption failed: ${error.message}`);
    }
  }

  async encryptMessage(sessionKey, message) {
    console.log("🔐 Encrypting message, length:", message.length);
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(message);
      
      const encrypted = await this.crypto.encrypt(
        { name: "AES-GCM", iv: iv }, sessionKey, encoded
      );

      const result = {
        iv: this._arrayBufferToBase64(iv),
        data: this._arrayBufferToBase64(encrypted)
      };
      
      console.log("✅ Message encrypted successfully");
      return result;
    } catch (error) {
      console.error("❌ Message encryption failed:", error);
      throw error;
    }
  }

  async decryptMessage(sessionKey, encryptedMsg) {
    console.log("🔓 Decrypting message...");
    try {
      const iv = this._base64ToArrayBuffer(encryptedMsg.iv);
      const data = this._base64ToArrayBuffer(encryptedMsg.data);
      
      console.log("🔓 IV length:", iv.byteLength, "Data length:", data.byteLength);
      
      const decrypted = await this.crypto.decrypt(
        { name: "AES-GCM", iv: iv }, sessionKey, data
      );

      const result = new TextDecoder().decode(decrypted);
      console.log("✅ Message decrypted successfully, length:", result.length);
      return result;
    } catch (error) {
      console.error("❌ Message decryption failed:", error);
      throw error;
    }
  }

  // === SESSION KEY STORAGE ===
  storeSessionKey(sessionToken, sessionKeyBase64) {
    console.log(`🔑 Storing session key for ${sessionToken.slice(0, 8)}...`);
    try {
      const key = `session_key_${sessionToken}`;
      sessionStorage.setItem(key, sessionKeyBase64);
      this.sessionKeys.set(sessionToken, sessionKeyBase64);
      console.log(`✅ Session key stored successfully: ${sessionToken.slice(0, 8)}...`);
      return true;
    } catch (error) {
      console.error("❌ Session key storage failed:", error);
      return false;
    }
  }

  getSessionKey(sessionToken) {
    // Check memory cache first
    if (this.sessionKeys.has(sessionToken)) {
      console.log(`🔑 Session key found in memory cache: ${sessionToken.slice(0, 8)}...`);
      return this.sessionKeys.get(sessionToken);
    }
    
    // Check sessionStorage
    const key = `session_key_${sessionToken}`;
    const sessionKey = sessionStorage.getItem(key);
    if (sessionKey) {
      console.log(`🔑 Session key found in sessionStorage: ${sessionToken.slice(0, 8)}...`);
      this.sessionKeys.set(sessionToken, sessionKey);
      return sessionKey;
    }
    
    console.log(`❌ Session key not found: ${sessionToken.slice(0, 8)}...`);
    return null;
  }

  removeSessionKey(sessionToken) {
    console.log(`🗑️ Removing session key: ${sessionToken.slice(0, 8)}...`);
    const key = `session_key_${sessionToken}`;
    sessionStorage.removeItem(key);
    this.sessionKeys.delete(sessionToken);
    console.log(`✅ Session key removed: ${sessionToken.slice(0, 8)}...`);
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
    console.log("🧹 Clearing all cryptographic keys...");
    
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
    
    console.log("✅ All keys cleared (session-only mode)");
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
      memoryKeys: this.sessionKeys.size,
      debugging: true
    };
  }

  // === ENHANCED DEBUGGING METHODS ===
  debugSessionKey(sessionToken) {
    console.log("=== SESSION KEY DEBUG ===");
    console.log("Session token:", sessionToken.slice(0, 8) + "...");
    
    const memoryKey = this.sessionKeys.get(sessionToken);
    const storageKey = sessionStorage.getItem(`session_key_${sessionToken}`);
    
    console.log("Memory cache:", !!memoryKey);
    console.log("SessionStorage:", !!storageKey);
    
    if (memoryKey) {
      console.log("Memory key length:", memoryKey.length);
      console.log("Memory key preview:", memoryKey.slice(0, 20) + "...");
    }
    
    if (storageKey) {
      console.log("Storage key length:", storageKey.length);
      console.log("Storage key preview:", storageKey.slice(0, 20) + "...");
    }
    
    return {
      hasMemoryKey: !!memoryKey,
      hasStorageKey: !!storageKey,
      keysMatch: memoryKey === storageKey
    };
  }

  async testRSADecryption(encryptedKey) {
    console.log("=== RSA DECRYPTION TEST ===");
    console.log("Testing encrypted key length:", encryptedKey.length);
    
    try {
      const result = await this.decryptSessionKey(encryptedKey);
      console.log("✅ Test successful, result length:", result.length);
      return result;
    } catch (error) {
      console.error("❌ Test failed:", error.message);
      throw error;
    }
  }

  // === HELPER METHODS ===
  _arrayBufferToBase64(buffer) {
    try {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    } catch (error) {
      console.error("❌ ArrayBuffer to Base64 conversion failed:", error);
      throw error;
    }
  }

  _base64ToArrayBuffer(base64) {
    try {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      console.error("❌ Base64 to ArrayBuffer conversion failed:", error);
      throw error;
    }
  }
}

// Global instance with backward compatibility
window.cryptoManager = new CryptoManager();
window.unifiedCrypto = window.cryptoManager; // Backward compatibility
window.chatCrypto = window.cryptoManager;     // Backward compatibility

// Debug helpers for console
window.debugCrypto = (sessionToken) => window.cryptoManager.debugSessionKey(sessionToken);
window.testRSA = (encryptedKey) => window.cryptoManager.testRSADecryption(encryptedKey);

console.log("🔒 Enhanced Crypto module loaded:", window.cryptoManager.getSecurityInfo());
