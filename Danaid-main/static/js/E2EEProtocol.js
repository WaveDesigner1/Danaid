/**
 * Protokół E2EE - Poprawiona obsługa szyfrowanej komunikacji end-to-end
 */
class E2EEProtocol {
  constructor() {
    this.crypto = window.crypto.subtle;
    this.keys = {};
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
   * Generuje klucz symetryczny AES-GCM
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
   * Szyfruje wiadomość
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
   * Deszyfruje wiadomość
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

  /**
   * Szyfruje klucz sesji
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
   * Deszyfruje klucz sesji
   */
  async decryptSessionKey(privateKey, encryptedKey) {
    try {
      console.log("Deszyfrowanie klucza sesji...");
      const data = this.base64ToArrayBuffer(encryptedKey);
      
      const decrypted = await this.crypto.decrypt(
        {
          name: "RSA-OAEP"
        },
        privateKey,
        data
      );
      
      return this.arrayBufferToBase64(decrypted);
    } catch (error) {
      console.error("Błąd deszyfrowania klucza sesji:", error);
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
   * Importuje klucz sesji
   */
  async importSessionKey(base64Key) {
    try {
      console.log("Importowanie klucza sesji...");
      const keyData = this.base64ToArrayBuffer(base64Key);
      return await this.crypto.importKey(
        "raw",
        keyData,
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

  // Funkcje pomocnicze
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// Eksport globalny
window.e2eeProtocol = new E2EEProtocol();
