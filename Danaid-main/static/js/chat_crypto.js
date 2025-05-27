/**
 * Moduł do obsługi szyfrowania w aplikacji czatu
 */
class ChatCrypto {
  constructor() {
    this.loadKeys();
    this.sessionKeys = {};
  }
  
  /**
   * Ładuje klucze z pamięci lokalnej
   */
  async loadKeys() {
    const privateKeyPEM = localStorage.getItem('private_key_pem');
    if (!privateKeyPEM) return false;
    
    try {
      this.privateKey = await this.importPrivateKeyFromPEM(privateKeyPEM);
      return true;
    } catch (error) {
      console.error('Błąd podczas ładowania klucza:', error);
      return false;
    }
  }
  
  /**
   * Importuje klucz prywatny z formatu PEM
   */
  async importPrivateKeyFromPEM(pem) {
    const pemContents = pem
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("-----END PRIVATE KEY-----", "")
      .replace(/\s+/g, "");

    const binaryDer = this.str2ab(atob(pemContents));

    return await window.crypto.subtle.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["decrypt"]
    );
  }
  
  /**
   * Importuje klucz publiczny z formatu PEM
   */
  async importPublicKeyFromPEM(pem) {
    const pemContents = pem
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replace(/\s+/g, "");

    const binaryDer = this.str2ab(atob(pemContents));

    return await window.crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
  }
  
  /**
   * Generuje klucz sesji (AES-GCM)
   */
  async generateSessionKey() {
    return await window.crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256
      },
      true,
      ["encrypt", "decrypt"]
    );
  }
  
  /**
   * Eksportuje klucz sesji do formatu Base64
   */
  async exportSessionKey(sessionKey) {
    const rawKey = await window.crypto.subtle.exportKey("raw", sessionKey);
    return this.arrayBufferToBase64(rawKey);
  }
  
  /**
   * Importuje klucz sesji z formatu Base64
   */
  async importSessionKey(base64Key) {
    const rawKey = this.base64ToArrayBuffer(base64Key);
    return await window.crypto.subtle.importKey(
      "raw",
      rawKey,
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
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  
  base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
  
  str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
}

// Inicjalizacja
window.chatCrypto = new ChatCrypto();
