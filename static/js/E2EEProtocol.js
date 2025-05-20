/**
 * Protokół E2EE - Obsługa szyfrowanej komunikacji end-to-end
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
    return await this.crypto.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Generuje klucz symetryczny AES-GCM
   */
  async generateSessionKey() {
    return await this.crypto.generateKey(
      {
        name: "AES-GCM",
        length: 256
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Szyfruje wiadomość
   */
  async encryptMessage(sessionKey, message) {
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
  }

  /**
   * Deszyfruje wiadomość
   */
  async decryptMessage(sessionKey, encryptedMsg) {
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

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Szyfruje klucz sesji
   */
  async encryptSessionKey(publicKey, sessionKey) {
    const rawKey = await this.crypto.exportKey("raw", sessionKey);
    
    const encrypted = await this.crypto.encrypt(
      {
        name: "RSA-OAEP"
      },
      publicKey,
      rawKey
    );

    return this.arrayBufferToBase64(encrypted);
  }

  /**
   * Deszyfruje klucz sesji
   */
  async decryptSessionKey(privateKey, encryptedKey) {
    const data = this.base64ToArrayBuffer(encryptedKey);
    
    const decrypted = await this.crypto.decrypt(
      {
        name: "RSA-OAEP"
      },
      privateKey,
      data
    );

    return await this.crypto.importKey(
      "raw",
      decrypted,
      {
        name: "AES-GCM",
        length: 256
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  // Funkcje pomocnicze
  arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
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
