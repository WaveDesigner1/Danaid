/**
 * UnifiedCrypto.js - Zunifikowany moduł kryptograficzny
 * Łączy funkcjonalności z chat_crypto.js i E2EEProtocol.js
 */
class UnifiedCrypto {
  constructor() {
    this.crypto = window.crypto.subtle;
    this.keys = {};
    this.sessionKeys = {};
    
    // Automatycznie załaduj klucze z localStorage
    this.loadKeys();
    
    console.log("UnifiedCrypto zainicjalizowany");
  }

  // === ZARZĄDZANIE KLUCZAMI ===

  /**
   * Ładuje klucze z pamięci lokalnej
   */
  async loadKeys() {
    const privateKeyPEM = localStorage.getItem('private_key_pem');
    if (!privateKeyPEM) {
      console.warn("Brak klucza prywatnego w localStorage");
      return false;
    }
    
    try {
      this.privateKey = await this.importPrivateKeyFromPEM(privateKeyPEM);
      console.log("Klucz prywatny załadowany pomyślnie");
      return true;
    } catch (error) {
      console.error('Błąd podczas ładowania klucza prywatnego:', error);
      return false;
    }
  }

  /**
   * Generuje parę kluczy RSA
   */
  async generateKeyPair() {
    try {
      const keyPair = await this.crypto.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
      );
      
      console.log("Wygenerowano nową parę kluczy RSA");
      return keyPair;
    } catch (error) {
      console.error("Błąd generowania pary kluczy:", error);
      throw error;
    }
  }

  /**
   * Importuje klucz prywatny z formatu PEM
   */
  async importPrivateKeyFromPEM(pem) {
    try {
      console.log("Importowanie klucza prywatnego z PEM...");
      const pemContents = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace(/\s+/g, "");

      const binaryDer = this.base64ToArrayBuffer(pemContents);

      return await this.crypto.importKey(
        "pkcs8",
        binaryDer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["decrypt"]
      );
    } catch (error) {
      console.error("Błąd importowania klucza prywatnego:", error);
      throw error;
    }
  }

  /**
   * Importuje klucz publiczny z formatu PEM
   */
  async importPublicKeyFromPEM(pem) {
    try {
      const pemContents = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/\s+/g, "");

      const binaryDer = this.base64ToArrayBuffer(pemContents);

      return await this.crypto.importKey(
        "spki",
        binaryDer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["encrypt"]
      );
    } catch (error) {
      console.error("Błąd importowania klucza publicznego:", error);
      throw error;
    }
  }

  // === KLUCZE SESJI AES-GCM ===

  /**
   * Generuje klucz sesji AES-GCM
   */
  async generateSessionKey() {
    try {
      const key = await this.crypto.generateKey(
        {
          name: "AES-GCM",
          length: 256
        },
        true,
        ["encrypt", "decrypt"]
      );
      
      console.log("Wygenerowano nowy klucz sesji AES-GCM");
      return key;
    } catch (error) {
      console.error("Błąd generowania klucza sesji:", error);
      throw error;
    }
  }

  /**
   * Eksportuje klucz sesji do formatu Base64
   */
  async exportSessionKey(sessionKey) {
    try {
      const rawKey = await this.crypto.exportKey("raw", sessionKey);
      return this.arrayBufferToBase64(rawKey);
    } catch (error) {
      console.error("Błąd eksportu klucza sesji:", error);
      throw error;
    }
  }

  /**
   * Importuje klucz sesji z formatu Base64
   */
  async importSessionKey(base64Key) {
    try {
      console.log("Importowanie klucza sesji...");
      const rawKey = this.base64ToArrayBuffer(base64Key);
      return await this.crypto.importKey(
        "raw",
        rawKey,
        {
          name: "AES-GCM",
          length: 256
        },
        true,
        ["encrypt", "decrypt"]
      );
    } catch (error) {
      console.error("Błąd importowania klucza sesji:", error);
      throw error;
    }
  }

  // === SZYFROWANIE KLUCZY SESJI ===

  /**
   * Szyfruje klucz sesji kluczem publicznym RSA
   */
  async encryptSessionKey(publicKey, sessionKey) {
    try {
      console.log("Szyfrowanie klucza sesji...");
      const rawKey = await this.crypto.exportKey("raw", sessionKey);
      
      const encrypted = await this.crypto.encrypt(
        {
          name: "RSA-OAEP"
        },
        publicKey,
        rawKey
      );
      
      return this.arrayBufferToBase64(encrypted);
    } catch (error) {
      console.error("Błąd szyfrowania klucza sesji:", error);
      throw error;
    }
  }

  /**
   * Deszyfruje klucz sesji kluczem prywatnym RSA
   */
  async decryptSessionKey(encryptedKey) {
    try {
      console.log("Deszyfrowanie klucza sesji...");
      
      if (!this.privateKey) {
        throw new Error("Brak klucza prywatnego - załaduj klucz najpierw");
      }
      
      const data = this.base64ToArrayBuffer(encryptedKey);
      
      const decrypted = await this.crypto.decrypt(
        {
          name: "RSA-OAEP"
        },
        this.privateKey,
        data
      );
      
      return this.arrayBufferToBase64(decrypted);
    } catch (error) {
      console.error("Błąd deszyfrowania klucza sesji:", error);
      throw error;
    }
  }

  // === SZYFROWANIE WIADOMOŚCI ===

  /**
   * Szyfruje wiadomość kluczem sesji AES-GCM
   */
  async encryptMessage(sessionKey, message) {
    try {
      console.log("Szyfrowanie wiadomości...");
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(message);
      
      const encrypted = await this.crypto.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        sessionKey,
        encoded
      );

      return {
        iv: this.arrayBufferToBase64(iv),
        data: this.arrayBufferToBase64(encrypted)
      };
    } catch (error) {
      console.error("Błąd szyfrowania wiadomości:", error);
      throw error;
    }
  }

  /**
   * Deszyfruje wiadomość kluczem sesji AES-GCM
   */
  async decryptMessage(sessionKey, encryptedMsg) {
    try {
      console.log("Deszyfrowanie wiadomości:", encryptedMsg);
      const iv = this.base64ToArrayBuffer(encryptedMsg.iv);
      const data = this.base64ToArrayBuffer(encryptedMsg.data);
      
      const decrypted = await this.crypto.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        sessionKey,
        data
      );

      const decryptedText = new TextDecoder().decode(decrypted);
      console.log("Wiadomość odszyfrowana pomyślnie");
      return decryptedText;
    } catch (error) {
      console.error("Błąd deszyfrowania wiadomości:", error);
      throw error;
    }
  }

  // === ZARZĄDZANIE KLUCZAMI SESJI ===

  /**
   * Zapisuje klucz sesji w pamięci lokalnej
   */
  storeSessionKey(sessionToken, sessionKeyBase64) {
    try {
      localStorage.setItem(`session_key_${sessionToken}`, sessionKeyBase64);
      this.sessionKeys[sessionToken] = sessionKeyBase64;
      console.log(`Klucz sesji ${sessionToken} zapisany`);
      return true;
    } catch (error) {
      console.error("Błąd zapisywania klucza sesji:", error);
      return false;
    }
  }

  /**
   * Pobiera klucz sesji z pamięci lokalnej
   */
  getSessionKey(sessionToken) {
    try {
      // Najpierw sprawdź cache w pamięci
      if (this.sessionKeys[sessionToken]) {
        return this.sessionKeys[sessionToken];
      }
      
      // Potem sprawdź localStorage
      const sessionKey = localStorage.getItem(`session_key_${sessionToken}`);
      if (sessionKey) {
        this.sessionKeys[sessionToken] = sessionKey;
        return sessionKey;
      }
      
      return null;
    } catch (error) {
      console.error("Błąd pobierania klucza sesji:", error);
      return null;
    }
  }

  /**
   * Usuwa klucz sesji
   */
  removeSessionKey(sessionToken) {
    try {
      localStorage.removeItem(`session_key_${sessionToken}`);
      delete this.sessionKeys[sessionToken];
      console.log(`Klucz sesji ${sessionToken} usunięty`);
      return true;
    } catch (error) {
      console.error("Błąd usuwania klucza sesji:", error);
      return false;
    }
  }

  // === FUNKCJE POMOCNICZE ===

  /**
   * Konwertuje ArrayBuffer na Base64
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Konwertuje Base64 na ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Sprawdza czy klucz prywatny jest dostępny
   */
  hasPrivateKey() {
    return !!this.privateKey;
  }

  /**
   * Sprawdza czy klucz sesji istnieje
   */
  hasSessionKey(sessionToken) {
    return !!this.getSessionKey(sessionToken);
  }

  /**
   * Czyści wszystkie klucze z pamięci
   */
  clearAllKeys() {
    try {
      // Wyczyść klucze sesji z localStorage
      for (const key in this.sessionKeys) {
        localStorage.removeItem(`session_key_${key}`);
      }
      
      // Wyczyść cache
      this.sessionKeys = {};
      this.keys = {};
      this.privateKey = null;
      
      console.log("Wszystkie klucze wyczyszczone");
      return true;
    } catch (error) {
      console.error("Błąd czyszczenia kluczy:", error);
      return false;
    }
  }
}

// Eksport globalny - zastępuje zarówno chatCrypto jak i e2eeProtocol
window.unifiedCrypto = new UnifiedCrypto();

// Zachowaj kompatybilność wsteczną
window.chatCrypto = window.unifiedCrypto;
window.e2eeProtocol = window.unifiedCrypto;

console.log("UnifiedCrypto załadowany i skonfigurowany");
